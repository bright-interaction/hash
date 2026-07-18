// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package handler wires the HTTP API. The Server holds the dependencies
// every handler needs; methods on Server bind chi routes.
package handler

import (
	"context"
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

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/aiapps"
	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/billing"
	"github.com/brightinteraction/hash/internal/branding"
	"github.com/brightinteraction/hash/internal/collab"
	"github.com/brightinteraction/hash/internal/compliance"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/eidas"
	"github.com/brightinteraction/hash/internal/envelopes"
	"github.com/brightinteraction/hash/internal/evidence"
	"github.com/brightinteraction/hash/internal/flarereport"
	"github.com/brightinteraction/hash/internal/mcp"
	"github.com/brightinteraction/hash/internal/qes"
	"github.com/brightinteraction/hash/internal/resolver"
	"github.com/brightinteraction/hash/internal/send"
	"github.com/brightinteraction/hash/internal/sign"
	"github.com/brightinteraction/hash/internal/storage"
	"github.com/brightinteraction/hash/internal/versions"
)

const (
	SessionCookieName = "hash_session"
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
	QES                    *qes.Engine
	Billing                *billing.Engine
	Collab                 *collab.Hub
	BrightCRMWebhookSecret string
	Frontend               http.Handler // SPA catch-all; nil = disabled (404 for unmatched paths)
	OrgName                string
	PublicURL              string
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

// Routes builds the chi router with every Hash endpoint mounted.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(trustedClientIP)
	r.Use(middleware.Logger)
	r.Use(panicMiddleware)
	r.Use(middleware.Recoverer)
	// Innermost of the recovery layers: it recovers first, ships the panic
	// to Flare, then re-panics so Recoverer still writes the standard 500
	// and panicMiddleware's stack logging contract is untouched.
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
		r.Post("/auth/logout", s.handleAuthLogout)
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

	// Signer-side: magic-link auth (URL token IS the credential).
	if s.Sign != nil {
		r.Route("/sign/{token}", func(r chi.Router) {
			// Per-IP cap across the whole magic-link surface (a leaked link is
			// otherwise an unbounded request + LLM-spend primitive).
			r.Use(httprate.LimitByIP(60, time.Minute))
			r.Get("/", s.handleSignerRoot)
			r.Get("/document", s.handleSignerDocument)
			r.Get("/pdf", s.handleSignerPDF)
			r.Get("/final-pdf", s.handleSignerFinalPDF)
			r.Post("/view", s.handleSignerView)
			r.Post("/sign", s.handleSignerSign)
			r.Post("/accept", s.handleSignerAccept)
			r.Post("/decline", s.handleSignerDecline)
			r.Post("/request-changes", s.handleSignerRequestChanges)
			r.Get("/comments", s.handleSignerListComments)
			r.Post("/comments", s.handleSignerCreateComment)
			r.Post("/telemetry", s.handleSignerTelemetry)
			// v1.2 fillable fields beyond signature.
			r.Get("/fields", s.handleSignerListFields)
			r.Post("/fields", s.handleSignerSubmitFields)
			// GDPR Art. 15-22: signer raises a data-subject-rights
			// request against their own row (access/erasure/etc).
			r.Post("/dsr", s.handleSignerDSR)
			if s.Clarifier != nil {
				r.Post("/clarify", s.handleSignerClarify)
			}
			if s.QES != nil {
				r.Post("/qes/start", s.handleQESStart)
				r.Get("/qes/status", s.handleQESStatus)
			}
		})
		// Email open-beacon: 1x1 transparent gif keyed by magic token.
		r.Get("/e/o/{token}", s.handleOpenBeacon)
		// One-click email actions (approve/deny a change request). Token-authed;
		// GET shows a confirm page, POST performs the action.
		r.With(httprate.LimitByIP(60, time.Minute)).Get("/a/cr", s.handleChangeActionPage)
		r.With(httprate.LimitByIP(60, time.Minute)).Post("/a/cr", s.handleChangeActionConfirm)
		r.With(httprate.LimitByIP(60, time.Minute)).Get("/a/comment", s.handleCommentReplyPage)
		r.With(httprate.LimitByIP(60, time.Minute)).Post("/a/comment", s.handleCommentReplyConfirm)
		// QTSP callback: public route gated by HMAC inside the handler.
		// Mounted outside /sign/{token} because the QTSP authenticates
		// the session via its own ID, not the magic token.
		if s.QES != nil {
			r.Post("/qes/callback/{provider_session_id}", s.handleQESCallback)
		}
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
			r.Mount("/", s.MCP.Handler())
		})
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.RequireSession(s.Cookies, SessionCookieName))
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
			r.Use(auth.RequireRoleForWrites(auth.RoleSender))
			r.Get("/", s.handleListDSR)
			r.Post("/", s.handleCreateSenderDSR)
			r.Patch("/{id}", s.handleTransitionDSR)
		})
		r.Get("/data-subject/export", s.handleDSRExport)

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
				r.Post("/checkout", s.handleStartBillingCheckout)
				r.Post("/cancel", s.handleCancelBillingSubscription)
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
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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

// clientIP returns the request's source IP. chi.middleware.RealIP has
// already moved any X-Forwarded-For value into r.RemoteAddr. We strip the
// trailing :port and return the host portion.
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// trustedClientIP replaces chi middleware.RealIP, which trusts client-supplied
// True-Client-IP / X-Real-IP / leftmost X-Forwarded-For (all spoofable, so an
// attacker could rotate a header per request to defeat per-IP rate limits and
// forge the signer IP recorded on the eIDAS audit trail). Instead we take the
// RIGHTMOST PUBLIC entry of X-Forwarded-For: our proxy hops (nginx, caddy) sit
// on private IPs and are skipped, and any attacker-injected entries are LEFT of
// the real client (the outermost trusted proxy appended it), so they are never
// chosen. True-Client-IP / X-Real-IP are ignored entirely. With no XFF (local
// dev, direct dial) the direct-peer RemoteAddr is left untouched.
func trustedClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := rightmostPublicXFF(r.Header.Get("X-Forwarded-For")); ip != "" {
			_, port, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				port = "0"
			}
			r.RemoteAddr = net.JoinHostPort(ip, port)
		}
		next.ServeHTTP(w, r)
	})
}

// rightmostPublicXFF returns the rightmost X-Forwarded-For entry that parses as
// a public IP, or "" if there is none.
func rightmostPublicXFF(xff string) string {
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	return ""
}
