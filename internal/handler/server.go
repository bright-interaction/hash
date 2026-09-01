// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package handler wires the HTTP API. The Server holds the dependencies
// every handler needs; methods on Server bind chi routes.
package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/requestmeta"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

const (
	SessionCookieName = "hash_session"
	// hashProxyAuthHeader is overwritten by the managed Caddy before it dials
	// Hash. Network position is not identity: unrelated containers share both
	// production networks and can otherwise dial Hash directly.
	hashProxyAuthHeader = "X-Hash-Proxy-Auth"
	// hashProxyClientIPHeader is also overwritten by Caddy, but with Caddy's
	// strict trusted-proxy result rather than a forwarded chain. Hash accepts
	// exactly one literal address from this authenticated channel. Private/VPN
	// addresses stay private instead of exposing an earlier forged XFF entry.
	hashProxyClientIPHeader = "X-Hash-Client-IP"

	// Signer limits are deliberately split by credential and risk class. A
	// single IP can represent an entire customer office, while the magic token
	// already identifies one ceremony. The generous IP-wide ceiling only bounds
	// random-token scanning; the tighter token buckets bound leaked-link abuse.
	signerGlobalIPRequestsPerMinute = 1200
	automationGlobalIPPerMinute     = 6000
	automationOrgRequestsPerMinute  = 600
	signerReadRequestsPerMinute     = 240
	signerMutationRequestsPerMinute = 60
	signerDownloadRequestsPerMinute = 30
	signerClarifyRequestsPerMinute  = 10

	// Resource-heavy endpoints also keep a generous aggregate IP ceiling so an
	// attacker cannot rotate otherwise-valid tokens to amplify egress, telemetry
	// allocation, or LLM spend. These buckets are isolated from legal responses.
	signerDownloadIPRequestsPerMinute  = 240
	signerTelemetryIPRequestsPerMinute = 240
	signerClarifyIPRequestsPerMinute   = 60
)

// Server holds shared deps for HTTP handlers.
type Server struct {
	Pool                   *pgxpool.Pool
	Queries                *generated.Queries
	Storage                *storage.Client
	Audit                  *audit.Logger
	OIDC                   *auth.OIDC
	Cookies                *auth.SignedCookie
	APIKeys                auth.APIKeyVerifier
	MCP                    *mcp.Server
	Sign                   *sign.Engine
	Send                   *send.Engine
	Mailer                 dispatch.Mailer
	Versions               *versions.Engine
	Resolver               *resolver.Resolver
	AIRuntime              *ai.Runtime
	BrandingResolver       *branding.Resolver
	Envelopes              *envelopes.Engine
	EIDAS                  *eidas.Engine
	Evidence               *evidence.Builder
	Clarifier              *aiapps.Clarifier
	Negotiator             *aiapps.Negotiator
	Bilingual              *aiapps.Bilingual
	RiskAnalyzer           *aiapps.RiskAnalyzer
	Compliance             *compliance.Seeder
	ComplianceFlagger      *compliance.Flagger
	ComplianceFeed         compliance.Feed
	Billing                *billing.Engine
	Collab                 *collab.Hub
	BrightCRMWebhookSecret string
	// WebhookSecrets encrypts new per-endpoint outbound HMAC keys before any
	// database write. Production config always wires it; nil test/dev servers
	// reject endpoint creation instead of falling back to plaintext.
	WebhookSecrets *webhooksecret.Keyring
	// The BrightCRM receiver claims replay protection and appends every affected
	// tenant ledger atomically before mutating the process-local resolver cache.
	// This private override keeps that boundary unit-testable; production uses
	// the Server implementation backed by Pool, Queries, and Audit.
	brightCRMProcessorOverride brightCRMWebhookProcessor
	// The standalone automation command has a private test seam for its
	// transaction/send orchestrator. Production always uses the Server-backed
	// implementation and its durable idempotency table.
	automationSignatureRequestProcessorOverride automationSignatureRequestProcessor
	// EvidenceTrustedPublicKeys pins bundle verification to this Hash issuer.
	// Cryptographically valid bundles signed by arbitrary self-supplied keys
	// must never receive an issuer-authentic OK result.
	EvidenceTrustedPublicKeys []string
	// Historical keys remain valid for certificates issued while they were
	// active, but must not authorize newly generated export manifests.
	EvidenceManifestPublicKeys []string
	Frontend                   http.Handler // SPA catch-all; nil = disabled (404 for unmatched paths)
	OrgName                    string
	// Operator disclosure fields are the deployed instance's factual Article
	// 13 identity. Config requires them outside explicit local development.
	OperatorName         string
	PrivacyContact       string
	SupervisoryAuthority string
	PrivacyPolicyURL     string
	PublicURL            string
	// Release and Environment are public deployment identity, not secrets.
	// /health publishes them so an external cutover probe can prove that ingress
	// reached the selected release instead of any older healthy Hash instance.
	Release     string
	Environment string
	// ProxyAuth is never exposed to handlers. The outermost production
	// middleware compares a fixed-size digest in constant time, strips the
	// header, and rejects direct shared-network requests before XFF is trusted.
	ProxyAuth string
	// AISealKey is the 32-byte key used to encrypt per-org BYOAI provider
	// keys at rest (same key the AI shield uses). Empty disables BYOAI: the
	// settings handler refuses to store a key it cannot later decrypt.
	AISealKey []byte
	// AIEUHosts is the operator's extra EU-endpoint allow-list (from
	// HASH_AI_EU_HOSTS_ALLOWLIST) used to validate a per-org BYOAI base_url.
	AIEUHosts []string
	// ActionSecret signs/verifies one-click email action links (approve/deny).
	ActionSecret string
	// CSPScriptSrc holds extra script-src CSP tokens (e.g. the sha256 hashes of the
	// SvelteKit inline bootstrap script). Without these the strict script-src 'self'
	// CSP blocks the SPA's own inline bootstrap and every page renders blank. Set at
	// boot from the embedded frontend; empty in API-only/test setups.
	CSPScriptSrc string
}

// docGetParams is a tiny helper so handlers don't repeat the params struct.
func docGetParams(id, orgID uuid.UUID) generated.GetDocumentParams {
	return generated.GetDocumentParams{ID: id, OrgID: orgID}
}

// signerTokenRateLimit keys a limiter by a one-way digest of the magic token.
// Using the credential rather than only the source IP keeps separate signers
// behind one NAT from consuming each other's ceremony budget. Never retain the
// raw bearer token in a limiter map or expose it in diagnostics.
func signerTokenRateLimit(requestLimit int) func(http.Handler) http.Handler {
	return httprate.Limit(requestLimit, time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
		token := chi.URLParam(r, "token")
		if token == "" {
			return "", errors.New("missing signer token")
		}
		return hex.EncodeToString(auth.HashMagicToken(token)), nil
	}))
}

// automationOrgRateLimit is applied after API-key authentication. A shared
// Google UrlFetch egress address or corporate NAT therefore cannot make one
// partner consume another partner's normal command budget; the separate high
// IP ceiling remains an unauthenticated abuse-control layer.
func automationOrgRateLimit(requestLimit int) func(http.Handler) http.Handler {
	return httprate.Limit(requestLimit, time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
		user, ok := auth.FromContext(r.Context())
		if !ok || user.OrgID == uuid.Nil {
			return "", errors.New("missing authenticated organization")
		}
		return user.OrgID.String(), nil
	}))
}

// Routes builds the chi router with every Hash endpoint mounted.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(s.requireProductionProxyAuth)
	r.Use(middleware.RequestID)
	r.Use(safeAccessLogger)
	// Recovery order is intentional (first registered = outermost): Flare sees
	// and re-panics first, panicMiddleware records the scrubbed local stack and
	// re-panics second, and chi's outer Recoverer finally writes the 500. Putting
	// Recoverer inside either observer swallows the panic before it reaches it.
	r.Use(middleware.Recoverer)
	r.Use(panicMiddleware)
	r.Use(flarereport.FlareRecoverer)
	r.Use(middleware.StripSlashes)
	r.Use(s.securityHeaders)
	r.Use(middleware.Timeout(60 * 1000 * 1000 * 1000)) // 60s

	r.Get("/health", s.handleHealth) // never rate-limited: liveness probes

	// Auth endpoints: tight per-IP cap against credential/callback abuse.
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(20, time.Minute))
		r.Get("/auth/login", s.handleAuthLogin)
		r.Get("/auth/callback", s.handleAuthCallback)
		// Logout mutates an ambient cookie. SameSite=Strict does not stop a
		// sibling subdomain (same-site, different origin) from forcing it, so
		// apply the same exact-origin browser guard as the authenticated API.
		r.With(s.requireSameOriginMutation).Post("/auth/logout", s.handleAuthLogout)
	})

	// Public signature-verification surface (anonymous, CPU-heavy crypto +
	// decompression). Moderate per-IP cap.
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(30, time.Minute))
		r.Get("/.well-known/hash-public-key", s.handleVerifyKey)
		r.Post("/api/verify", s.handleVerify)
		r.Post("/api/verify-bundle", s.handleVerifyBundle)
	})

	// Phase 8.5: public branding logo (no auth, cached). Lets the signer
	// page + Gotenberg renderer fetch a stable URL for the org logo.
	r.Get("/branding/logo/{filename}", s.handleGetBrandingLogo)

	// Phase 9.1: BrightCRM webhook receiver (HMAC-signed, no session).
	// Invalidates the resolver cache when a referenced CRM entity
	// changes so the next render fetches fresh data.
	r.Post("/webhooks/brightcrm", s.handleBrightCRMWebhook)

	// v1.1 billing webhook receiver. Path includes a per-instance
	// secret so Mollie's URL-based authentication works; the provider
	// re-verifies the payment via api.mollie.com.
	if s.Billing != nil {
		r.Post("/webhooks/billing/{secret}", s.handleBillingWebhook)
		// Convenience: webhooks without a secret hit a 404; bare
		// /webhooks/billing returns a 401 so clueless POSTs without
		// the path secret get a clear error.
		r.Post("/webhooks/billing", func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusUnauthorized, "billing webhook requires path secret")
		})
	}

	// Explicit tombstone prevents retired provider callbacks from falling
	// through to the SPA's 200 HTML shell. HTTP 410 cannot be mistaken for an
	// active or temporarily degraded QES integration.
	r.Post("/qes/callback/{provider_session_id}", s.handleQESCallback)

	// Signer-side: magic-link auth (URL token IS the credential).
	if s.Sign != nil {
		s.mountSignerRoutes(r)
		// Compatibility response for already-sent legacy email pixels. It never
		// looks up the token or writes analytics/audit data; new templates emit no
		// pixel. Rate-limit it like the other public credential-shaped routes.
		r.With(httprate.LimitByIP(60, time.Minute)).Get("/e/o/{token}", s.handleRetiredOpenBeacon)
		// One-click email actions (approve/deny a change request). Token-authed;
		// GET shows a confirm page, POST performs the action.
		r.With(httprate.LimitByIP(60, time.Minute)).Get("/a/cr", s.handleChangeActionPage)
		r.With(httprate.LimitByIP(60, time.Minute)).Post("/a/cr", s.handleChangeActionConfirm)
		r.With(httprate.LimitByIP(60, time.Minute)).Get("/a/comment", s.handleCommentReplyPage)
		r.With(httprate.LimitByIP(60, time.Minute)).Post("/a/comment", s.handleCommentReplyConfirm)
		// AES/QES ceremony operations are represented only by 410 tombstones;
		// dormant provider code and legacy rows cannot activate a lifecycle.
	}

	// MCP endpoint mounted outside /api/v1 so JSON-RPC envelopes don't fight
	// CSRF or accept-negotiation middleware. API-key auth gates it.
	if s.MCP != nil && s.APIKeys != nil {
		r.Route("/mcp", func(r chi.Router) {
			// Per-IP cap: every other authed/public surface has one, and the AI
			// tools each fan out to a paid LLM. Generous (agents make many calls)
			// but bounds cost/DoS amplification from a leaked/over-shared token.
			r.Use(httprate.LimitByIP(240, time.Minute))
			r.Use(auth.RequireAPIKey(s.APIKeys))
			// The whole MCP product is plan-gated, not just selected premium
			// tools. Recheck on every request so a downgrade immediately disables
			// previously issued keys; entitlement lookup errors fail closed.
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					u, ok := auth.FromContext(req.Context())
					if !ok {
						writeError(w, http.StatusUnauthorized, "not authenticated")
						return
					}
					if !s.requireFeature(w, req, u.OrgID, "mcp") {
						return
					}
					next.ServeHTTP(w, req)
				})
			})
			r.Mount("/", s.MCP.Handler())
		})
	}

	// Standalone machine API. It deliberately lives outside the session-only
	// /api/v1 tree: an authenticated CRM, Reactor workflow, or Google-hosted
	// producer can create and send a complete request without browser cookies.
	// The handler additionally requires both authoring and workflow scopes and
	// rejects document-scoped agent credentials.
	if s.APIKeys != nil {
		r.Route("/api/automation/v1", func(r chi.Router) {
			r.Use(httprate.LimitByIP(automationGlobalIPPerMinute, time.Minute))
			r.Use(auth.RequireAPIKey(s.APIKeys))
			r.Use(automationOrgRateLimit(automationOrgRequestsPerMinute))
			r.Use(auth.RequireRole(auth.RoleSender))
			r.Use(requireAutomationSignatureRequestScope)
			r.Post("/signature-requests", s.handleAutomationSignatureRequest)
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		// SameSite=Strict stops cross-site CSRF, but sibling subdomains are
		// same-site and can still issue cookie-bearing simple requests. Require
		// browser mutations to originate from this exact app origin before the
		// session cookie is accepted.
		r.Use(s.requireSameOriginMutation)
		// Revalidate the signed cookie's user against PostgreSQL on every
		// request. Cookie integrity authenticates the session; the live row is
		// authoritative for current membership, tenant, and role.
		r.Use(auth.RequireSession(s.Cookies, SessionCookieName, s.Queries))
		r.Get("/me", s.handleMe)
		// Org-wide setting: owner-only, like every other org setting below (a
		// viewer/sender must not flip how change-request approvals behave for
		// the whole org, e.g. to auto_apply signer-proposed text).
		r.With(auth.RequireRole(auth.RoleOwner)).Patch("/settings/change-approval-mode", s.handleSetChangeApprovalMode)
		r.Get("/dashboard", s.handleDashboard)

		// Phase 8.4: AI runtime status (operator read).
		r.Get("/ai/status", s.handleAIStatus)

		// BYOAI: per-org provider override. The key is sealed at rest and
		// never returned; GET surfaces only a last-4 hint.
		r.Get("/ai/provider", s.handleGetOrgAIProvider)
		r.With(auth.RequireRole(auth.RoleOwner)).Put("/ai/provider", s.handleSetOrgAIProvider)
		r.With(auth.RequireRole(auth.RoleOwner)).Delete("/ai/provider", s.handleDeleteOrgAIProvider)

		// Phase 8.8: org-wide activity feed.
		r.Get("/activity", s.handleOrgActivity)
		r.Get("/activity/leaderboard", s.handleOrgActivityLeaderboard)

		// Phase 12: compliance baseline + EDPB flag dashboard.
		if s.Compliance != nil {
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireRole(auth.RoleOwner)) // compliance admin: owner only
				r.Post("/compliance/seed", s.handleSeedCompliance)
				r.Get("/compliance/baseline", s.handleGetComplianceBaseline)
				r.Get("/compliance/flags", s.handleListComplianceFlags)
				r.Patch("/compliance/flags/{id}", s.handleSetComplianceFlagStatus)
				r.Post("/compliance/flag-run", s.handleComplianceFlagRun)
			})
		}

		// Phase 10.1: aggregate org insights.
		r.Get("/insights", s.handleOrgInsights)

		// Audit hash-chain verifier (audit pass #10 + carryover #16).
		// Walks every events row for the org and reports any divergence
		// between the stored row_hash and the recomputed SHA-256.
		r.Get("/audit/verify-chain", s.handleVerifyAuditChain)

		// GDPR Art. 15-22 data-subject-rights surface for senders.
		// Sender raises a DSR (e.g. from a DPO email), lists pending
		// ones, transitions status, runs an Art. 15+20 export.
		r.Route("/dsr", func(r chi.Router) {
			// DSR rows contain subject emails, names, and free-text notes. They are
			// a sender/DPO workflow, not ordinary viewer-readable org metadata.
			r.Use(auth.RequireRole(auth.RoleSender))
			r.Get("/", s.handleListDSR)
			r.Post("/", s.handleCreateSenderDSR)
			r.Patch("/{id}", s.handleTransitionDSR)
		})
		// Subject exports disclose recipient identity and ceremony metadata.
		// Treat them as DSR operations, not ordinary viewer document reads.
		r.With(auth.RequireRole(auth.RoleSender)).Get("/data-subject/export", s.handleDSRExport)

		// Phase 9.2: eIDAS routing rules.
		if s.EIDAS != nil {
			r.Route("/eidas-rules", func(r chi.Router) {
				r.Use(auth.RequireRole(auth.RoleOwner)) // compliance config: owner only
				r.Get("/", s.handleListEIDASRules)
				r.Post("/", s.handleCreateEIDASRule)
				r.Post("/seed-sweden", s.handleSeedSwedishEIDASRules)
				r.Post("/preview", s.handlePreviewEIDASRules)
				r.Patch("/{id}", s.handleUpdateEIDASRule)
				r.Delete("/{id}", s.handleDeleteEIDASRule)
			})
		}

		// Phase 8.5: org-level brand theming. Read = any session; edits = owner.
		r.Get("/branding", s.handleGetOrgBranding)
		r.With(auth.RequireRole(auth.RoleOwner)).Put("/branding", s.handleUpsertOrgBranding)
		r.With(auth.RequireRole(auth.RoleOwner)).Post("/branding/extract", s.handleExtractBrandingPalette)
		r.With(auth.RequireRole(auth.RoleOwner)).Post("/branding/logo", s.handleUploadBrandingLogo)

		// Org members + RBAC. Anyone in the org can see the roster; only an
		// owner can change a member's role.
		r.Route("/members", func(r chi.Router) {
			r.Get("/", s.handleListMembers)
			r.With(auth.RequireRole(auth.RoleOwner)).Patch("/{id}/role", s.handleUpdateMemberRole)
		})

		r.Route("/api-keys", func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleOwner)) // org credentials: owner only
			r.Get("/", s.handleListAPIKeys)
			r.Post("/", s.handleCreateAPIKey)
			r.Delete("/{id}", s.handleDeleteAPIKey)
		})

		r.Route("/webhooks", func(r chi.Router) {
			r.Use(auth.RequireRole(auth.RoleOwner)) // org integrations: owner only
			r.Get("/", s.handleListWebhooks)
			r.Post("/", s.handleCreateWebhook)
			r.Delete("/{id}", s.handleDeleteWebhook)
			r.Get("/{id}/deliveries", s.handleListWebhookDeliveries)
		})

		r.Route("/templates", func(r chi.Router) {
			r.Use(auth.RequireRoleForWrites(auth.RoleSender))
			r.Get("/", s.handleListTemplates)
			r.Post("/", s.handleCreateTemplate)
			r.Post("/starter", s.handleCreateStarterTemplate)
			r.Get("/{id}", s.handleGetTemplate)
			r.Patch("/{id}", s.handleUpdateTemplate)
			r.Delete("/{id}", s.handleArchiveTemplate)
		})

		r.Route("/documents", func(r chi.Router) {
			// RBAC: viewers read; senders+ create/edit/send. Method-aware so
			// every current + future write route in this group is covered.
			r.Use(auth.RequireRoleForWrites(auth.RoleSender))
			r.Get("/", s.handleListDocuments)
			r.Post("/", s.handleCreateDocument)
			// One-step signable-proposal intake: multipart PDF upload OR a
			// designed HTML body rendered to PDF, both landing as a pdf-source
			// document straight into the field designer (no template detour).
			r.Post("/import", s.handleImportDocument)
			r.Get("/{id}", s.handleGetDocument)
			r.Patch("/{id}", s.handleUpdateDocument)
			r.Delete("/{id}", s.handleDeleteDocument)
			r.Get("/{id}/events", s.handleListEvents)
			r.Get("/{id}/recipients", s.handleListRecipients)
			r.Post("/{id}/recipients", s.handleCreateRecipient)
			r.Patch("/{id}/recipients/{rid}", s.handleUpdateRecipient)
			r.Delete("/{id}/recipients/{rid}", s.handleDeleteRecipient)

			// Block tree edits (block-source documents only).
			r.Post("/{id}/blocks", s.handleAppendBlock)
			r.Patch("/{id}/blocks/{bid}", s.handleUpdateBlock)
			r.Delete("/{id}/blocks/{bid}", s.handleDeleteBlock)
			r.Post("/{id}/blocks/reorder", s.handleReorderBlocks)
			r.Post("/{id}/import-html", s.handleImportHTML)
			r.Post("/{id}/import-md", s.handleImportMarkdown)
			r.Get("/{id}/preview", s.handlePreviewHTML)
			r.Get("/{id}/pdf", s.handleGetDocumentPDF) // original PDF for the field designer

			// Send / void / final downloads.
			r.Post("/{id}/send", s.handleSendDocument)
			r.Post("/{id}/void", s.handleVoidDocument)
			r.Post("/{id}/remind", s.handleRemindDocument)
			r.Get("/{id}/comments", s.handleListComments)
			r.Post("/{id}/comments", s.handleCreateComment)
			r.Get("/{id}/change-requests", s.handleListChangeRequests)
			r.Post("/{id}/change-requests/{crid}/approve", s.handleApproveChangeRequest)
			r.Post("/{id}/change-requests/{crid}/deny", s.handleDenyChangeRequest)
			r.Post("/{id}/revise", s.handleReviseDocument)
			r.Get("/{id}/final-pdf", s.handleFinalPDF)
			r.Get("/{id}/audit-cert", s.handleAuditCert)

			// Phase 8.1: version history + diff + restore. Powers the
			// negotiation copilot, court-ready evidence export, and
			// the per-document timeline UI.
			if s.Versions != nil {
				r.Get("/{id}/versions", s.handleListVersions)
				r.Get("/{id}/versions/{n}", s.handleGetVersion)
				r.Get("/{id}/diff", s.handleDiffVersions)
				r.Post("/{id}/versions/{n}/restore", s.handleRestoreVersion)
			}

			// Phase 8.2: variable bindings + live resolve preview.
			r.Get("/{id}/variable-bindings", s.handleListVariableBindings)
			r.Put("/{id}/variable-bindings/{name}", s.handleUpsertVariableBinding)
			r.Delete("/{id}/variable-bindings/{name}", s.handleDeleteVariableBinding)
			r.Get("/{id}/resolve-preview", s.handleResolvePreview)

			// Phase 8.3: signer telemetry rollup + raw timeline.
			r.Get("/{id}/engagement", s.handleEngagement)
			r.Get("/{id}/telemetry-stream", s.handleTelemetryStream)
			r.Get("/{id}/timeline", s.handleAuditTimeline)
			r.Get("/{id}/timeline.csv", s.handleAuditTimelineCSV)

			// Phase 8.6: envelope promotion lives on the document so
			// existing /documents/{id} machinery handles auth + lookup.
			if s.Envelopes != nil {
				r.Post("/{id}/promote-to-envelope", s.handlePromoteToEnvelope)
			}

			// Phase 9.2: per-document routing tier (SES/AES/QES).
			if s.EIDAS != nil {
				r.Patch("/{id}/routing-tier", s.handleSetDocumentRoutingTier)
			}

			// Phase 10.2: court-ready evidence bundle.
			if s.Evidence != nil {
				r.Get("/{id}/evidence-bundle", s.handleEvidenceBundle)
				r.Get("/{id}/evidence-manifest", s.handleEvidenceManifest)
			}

			// v1.1: per-document scoped agent tokens.
			r.Post("/{id}/agent-tokens", s.handleMintDocAgentToken)
			r.Get("/{id}/agent-tokens", s.handleListDocAgentTokens)

			// v1.1 Yjs collaborative editing. WebSocket upgrade under
			// the session-authed group so the cookie + doc-scope token
			// already gated us; the handler enforces doc-scope a 2nd
			// time before joining the hub.
			if s.Collab != nil {
				r.Get("/{id}/collab", s.handleCollabSocket)
			}

			// Phase 11.2: negotiation copilot.
			r.Get("/{id}/proposals", s.handleListProposals)
			r.Post("/{id}/proposals", s.handleCreateProposal)
			r.Patch("/{id}/negotiation-enabled", s.handleSetNegotiationEnabled)
			if s.Negotiator != nil {
				r.Post("/{id}/proposals/suggest", s.handleSuggestCounter)
			}

			// Phase 11.3: bilingual equivalence.
			r.Patch("/{id}/bilingual-target", s.handleSetBilingualTarget)
			if s.Bilingual != nil {
				r.Post("/{id}/bilingual/equivalence", s.handleBilingualEquivalence)
			}

			// v1.2: AI risk analysis pass over the draft block tree.
			if s.RiskAnalyzer != nil {
				r.Post("/{id}/risk-analysis", s.handleRunRiskAnalysis)
			}

			// v1.2 fillable fields ,  sender CRUD for non-signature field
			// overlays (text, date, checkbox, dropdown, initial).
			r.Get("/{id}/fields", s.handleListFields)
			r.Post("/{id}/fields", s.handleAddField)
		})

		// v1.2 field deletion lives outside /documents because the field
		// id is the addressing key on remove. These three routes address by
		// their own id so they sit outside the /documents group, but they are
		// still sender-tier writes: gate them explicitly so a viewer can't
		// mutate via them (parity with the /documents group + the MCP twins,
		// whose Write:true defaults to RoleSender).
		r.With(auth.RequireRole(auth.RoleSender)).Delete("/fields/{id}", s.handleDeleteField)

		// Phase 11.2 proposal status lives outside /documents because
		// the proposal id is the addressing key on accept/reject.
		r.With(auth.RequireRole(auth.RoleSender)).Patch("/proposals/{id}/status", s.handleSetProposalStatus)

		// v1.1: per-doc agent token revoke (token id is the addressing key).
		r.With(auth.RequireRole(auth.RoleSender)).Delete("/agent-tokens/{id}", s.handleRevokeDocAgentToken)

		// Phase 8.6: envelope-specific operations live under /envelopes
		// so the URL surface signals envelope-vs-document intent. The
		// envelope itself is still a document with is_envelope=true.
		if s.Envelopes != nil {
			r.Route("/envelopes", func(r chi.Router) {
				// Envelope topology is document authoring. Keep child/manifest
				// reads available to viewers, but require sender privileges for
				// attach, detach, and reorder mutations.
				r.Use(auth.RequireRoleForWrites(auth.RoleSender))
				r.Post("/{id}/attach", s.handleAttachToEnvelope)
				r.Post("/{id}/detach", s.handleDetachFromEnvelope)
				r.Post("/{id}/reorder", s.handleReorderEnvelope)
				r.Get("/{id}/children", s.handleListEnvelopeChildren)
				r.Get("/{id}/manifest", s.handleEnvelopeManifest)
			})
		}

		// v1.1 Mollie billing surface. List plans + current subscription,
		// start a checkout, cancel-at-period-end, list invoices.
		if s.Billing != nil {
			r.Route("/billing", func(r chi.Router) {
				r.Get("/plans", s.handleListBillingPlans)
				r.Get("/subscription", s.handleGetBillingSubscription)
				r.With(auth.RequireRole(auth.RoleOwner)).Post("/checkout", s.handleStartBillingCheckout)
				r.With(auth.RequireRole(auth.RoleOwner)).Post("/cancel", s.handleCancelBillingSubscription)
				r.Get("/invoices", s.handleListBillingInvoices)
			})
		}
	})

	// SPA catch-all: every path that isn't an API route falls through here
	// so the SvelteKit client-side router (/dashboard, /documents, /sign,
	// /settings/*, /legal/*, /verify) renders correctly.
	if s.Frontend != nil {
		r.NotFound(s.Frontend.ServeHTTP)
	}

	return r
}

// mountSignerRoutes registers the magic-link ceremony surface with independent
// budgets for reads, legal mutations, artifact downloads, and paid AI work.
// The outer IP ceiling prevents unbounded random-token scans without making a
// shared customer NAT the primary identity for ordinary ceremony traffic.
func (s *Server) mountSignerRoutes(r chi.Router) {
	r.Route("/sign/{token}", func(r chi.Router) {
		// Defense in depth for forged-token enumeration. At 20 requests/second
		// this remains well above legitimate shared-office ceremony traffic.
		r.Use(httprate.LimitByIP(signerGlobalIPRequestsPerMinute, time.Minute))

		r.Group(func(r chi.Router) {
			r.Use(signerTokenRateLimit(signerReadRequestsPerMinute))
			r.Get("/", s.handleSignerRoot)
			r.Get("/document", s.handleSignerDocument)
			r.Get("/comments", s.handleSignerListComments)
			r.Get("/fields", s.handleSignerListFields)
			r.Get("/qes/status", s.handleQESStatus)
		})

		// PDF routes can move substantially more bytes than bootstrap reads, so
		// they receive a smaller, independent credential-scoped budget.
		r.Group(func(r chi.Router) {
			r.Use(httprate.LimitByIP(signerDownloadIPRequestsPerMinute, time.Minute))
			r.Use(signerTokenRateLimit(signerDownloadRequestsPerMinute))
			r.Get("/pdf", s.handleSignerPDF)
			r.Get("/final-pdf", s.handleSignerFinalPDF)
		})

		r.Group(func(r chi.Router) {
			r.Use(signerTokenRateLimit(signerMutationRequestsPerMinute))
			r.Post("/view", s.handleSignerView)
			r.Post("/sign", s.handleSignerSign)
			r.Post("/accept", s.handleSignerAccept)
			r.Post("/decline", s.handleSignerDecline)
			r.Post("/request-changes", s.handleSignerRequestChanges)
			r.Post("/comments", s.handleSignerCreateComment)
			// v1.2 fillable fields beyond signature.
			r.Post("/fields", s.handleSignerSubmitFields)
			// GDPR Art. 15-22: signer raises a data-subject-rights
			// request against their own row (access/erasure/etc).
			r.Post("/dsr", s.handleSignerDSR)
			r.Post("/qes/start", s.handleQESStart)
		})

		// Compatibility route for pre-release clients. The handler always returns
		// 410 and writes nothing until consent is persisted and enforced server-side.
		r.With(httprate.LimitByIP(signerTelemetryIPRequestsPerMinute, time.Minute)).Post("/telemetry", s.handleSignerTelemetry)
		if s.Clarifier != nil {
			r.With(
				httprate.LimitByIP(signerClarifyIPRequestsPerMinute, time.Minute),
				signerTokenRateLimit(signerClarifyRequestsPerMinute),
			).Post("/clarify", s.handleSignerClarify)
		}
	})
}

// safeAccessLogger records enough request metadata for operations without ever
// serializing the raw URL. Hash has several credentials in URLs: signer magic
// tokens and billing secrets are path segments, while OIDC codes and one-click
// action tokens are query parameters. chi's stock Logger writes RequestURI and
// therefore leaked all of them into container/central logs.
func safeAccessLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		slog.Info("http request",
			"request_id", middleware.GetReqID(r.Context()),
			"method", r.Method,
			"path", safeAccessPath(r.URL.Path),
			"status", status,
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func safeAccessPath(path string) string {
	segments := strings.Split(path, "/")
	// Leading slash produces segments[0] == "".
	if len(segments) >= 3 && segments[1] == "sign" {
		segments[2] = ":token"
	}
	if len(segments) >= 4 && segments[1] == "e" && segments[2] == "o" {
		segments[3] = ":token"
	}
	if len(segments) >= 4 && segments[1] == "webhooks" && segments[2] == "billing" {
		segments[3] = ":secret"
	}
	if len(segments) >= 4 && segments[1] == "qes" && segments[2] == "callback" {
		segments[3] = ":provider_session_id"
	}
	return strings.Join(segments, "/")
}

// securityHeaders adds the baseline OWASP-recommended headers on every
// response. All fonts are self-hosted under /fonts/* so the CSP can stay
// fully first-party; no third-party CDN is allowed at runtime.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	// script-src is locked to 'self' plus the sha256 hashes of the SvelteKit inline
	// bootstrap (s.CSPScriptSrc). The hashes are required: SvelteKit boots the SPA
	// from one inline <script>, so a bare script-src 'self' blocks it and every page
	// renders blank. No 'unsafe-inline', so the stored-XSS protection still holds.
	scriptSrc := "script-src 'self'" + s.CSPScriptSrc
	csp := "default-src 'self'; " +
		"img-src 'self' data: blob:; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self'; " +
		scriptSrc + "; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Signing URLs carry bearer credentials in the path. Never forward even
		// the origin as referrer metadata when a signer follows an external link;
		// this also keeps the full token out of same-origin analytics requests.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		h.Set("Content-Security-Policy", csp)
		// Magic/action URLs are bearer credentials and their responses contain
		// contract content or signer identity. Do not let browsers, shared
		// proxies, or service workers retain a reusable copy.
		if strings.HasPrefix(r.URL.Path, "/sign/") || strings.HasPrefix(r.URL.Path, "/a/") || strings.HasPrefix(r.URL.Path, "/e/o/") {
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Readiness alone cannot prove a cutover: a stale reverse-proxy target can
	// be perfectly healthy. Bind the public response to the manifest-selected
	// release and runtime mode so deployment automation can fail closed on that
	// routing error. These values contain no credentials.
	w.Header().Set("X-Hash-Release", s.Release)
	w.Header().Set("X-Hash-Environment", s.Environment)
	w.Header().Set("Cache-Control", "no-store")

	// /health used to ping Postgres only. Compose + Caddy treat a 200
	// here as "ready to receive traffic"; when Gotenberg or MinIO is
	// down the API technically responds but sign + render flows die
	// in production. Each dep gets a 1-second budget so a single slow
	// dependency cannot stall the health probe.
	type depCheck struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
		Err  string `json:"err,omitempty"`
	}
	checks := make([]depCheck, 0, 4)
	overall := true
	check := func(name string, fn func(context.Context) error) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		err := fn(ctx)
		dc := depCheck{Name: name, OK: err == nil}
		if err != nil {
			// /health is unauthenticated; a pgx/minio ping error string leaks
			// internal hostnames + ports ("dial tcp postgres:5432").
			// Log it server-side; the anon body carries only {name, ok}.
			slog.Warn("health check failed", "dep", name, "err", err)
			overall = false
		}
		checks = append(checks, dc)
	}
	check("postgres", s.Pool.Ping)
	if s.Storage != nil {
		check("storage", s.Storage.Ping)
	}
	if s.Sign != nil && s.Sign.PDF != nil {
		check("gotenberg", s.Sign.PDF.Ping)
	}
	status := http.StatusOK
	if !overall {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ok": overall, "checks": checks})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	mode := "accept"
	if org, err := s.Queries.GetOrg(r.Context(), u.OrgID); err == nil {
		mode = org.ChangeApprovalMode
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":              u.UserID,
		"org_id":               u.OrgID,
		"email":                u.Email,
		"role":                 u.Role,
		"change_approval_mode": mode,
	})
}

// writeJSON marshals v and writes it as the response body. Errors are logged
// but the response is best-effort.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeInternalError logs the underlying error server-side and returns a generic
// 500 body. Raw pgx/SQL error strings (SQLSTATE, column/constraint names) and
// connection errors ("dial tcp host:port") must never reach the client - any
// API/MCP/curl caller, proxy log, or browser devtools would otherwise see schema
// internals + internal hostnames. Use for UNEXPECTED failures; keep the typed
// 4xx branches (quota/eidas/not-found/permission) exactly as-is.
func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error serving request", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

// writeInternalErrorMsg is writeInternalError with a safe, operator-authored
// public message (e.g. "create document failed"). The raw err is logged
// server-side only; it never reaches the client body.
func writeInternalErrorMsg(w http.ResponseWriter, publicMsg string, err error) {
	slog.Error("internal error serving request", "msg", publicMsg, "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": publicMsg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)) // 1MB body cap for JSON; multipart upload is separate
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// parseUUIDParam pulls a chi URL param and parses it as a UUID, writing the
// 400 response itself on failure. Caller should return immediately if the
// returned bool is false.
func parseUUIDParam(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	v := chi.URLParam(r, name)
	id, err := uuid.Parse(v)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

// requireSessionUser returns the session user or writes 401.
func requireSessionUser(w http.ResponseWriter, ctx context.Context) (auth.SessionUser, bool) {
	u, ok := auth.FromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return auth.SessionUser{}, false
	}
	return u, true
}

// errNotFound lets handlers report missing rows without a SQL leak.
var errNotFound = errors.New("not found")

// clientIP returns the request's source IP after the production proxy-auth
// middleware has selected Caddy's authenticated single-address value.
// net.SplitHostPort is required: a last-colon split corrupts IPv6.
func clientIP(r *http.Request) string {
	return requestmeta.ClientIP(r.RemoteAddr)
}

// requireProductionProxyAuth makes the managed reverse proxy an authenticated
// ingress boundary, not merely another peer in a broad private CIDR. The sole
// header-free production exception is the exact loopback /health request used
// by Docker and the in-container deployment probe. Every other request must
// carry the value Caddy overwrote; even a loopback request to an application
// route is refused.
func (s *Server) requireProductionProxyAuth(next http.Handler) http.Handler {
	wantDigest := sha256.Sum256([]byte(s.ProxyAuth))
	production := s.Environment == "production"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authValues := r.Header.Values(hashProxyAuthHeader)
		clientIPValues := r.Header.Values(hashProxyClientIPHeader)
		presented := ""
		if len(authValues) > 0 {
			presented = authValues[0]
		}
		// Strip before any logger, handler, or downstream integration can see the
		// authentication channel. Only the resulting RemoteAddr is authoritative.
		r.Header.Del(hashProxyAuthHeader)
		r.Header.Del(hashProxyClientIPHeader)
		stripForwardingHeaders(r.Header)

		if !production {
			next.ServeHTTP(w, r)
			return
		}
		peer := net.ParseIP(clientIP(r))
		if r.URL.Path == "/health" && peer != nil && peer.IsLoopback() {
			// A header-free local probe must remain local attribution too. This
			// exception does not authorize a loopback caller to name another IP.
			next.ServeHTTP(w, r)
			return
		}

		presentedDigest := sha256.Sum256([]byte(presented))
		secretOK := subtle.ConstantTimeCompare(presentedDigest[:], wantDigest[:]) == 1
		clientAddr, clientIPOK := parseAuthenticatedClientIP(clientIPValues)
		if len(authValues) != 1 || !secretOK || !clientIPOK {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		_, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			port = "0"
		}
		r.RemoteAddr = net.JoinHostPort(clientAddr, port)
		next.ServeHTTP(w, r)
	})
}

func parseAuthenticatedClientIP(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false
	}
	ip := net.ParseIP(values[0])
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

func stripForwardingHeaders(header http.Header) {
	header.Del("Forwarded")
	header.Del("X-Forwarded-For")
	header.Del("X-Real-IP")
	header.Del("True-Client-IP")
}
