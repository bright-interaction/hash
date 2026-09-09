// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/config"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/handler"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

const (
	// productionServerLockKey is an application-specific, database-scoped
	// PostgreSQL advisory lock (ASCII "HASHSRVR"). Production intentionally
	// serves through one HTTP process because signer rate-limit buckets, Yjs
	// rooms, and BrightCRM resolver-cache invalidation are process-local. Holding
	// this lock for the full process lifetime makes that singleton topology fail
	// closed: a second production HTTP process cannot accept traffic and split
	// the aggregate abuse budget or retain a stale integration cache.
	productionServerLockKey      int64 = 0x4841534853525652
	productionLeaseCheckInterval       = 5 * time.Second
	productionLeaseCheckTimeout        = 3 * time.Second
)

type productionServerLease interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Release()
}

type productionServerLeaseAcquire func(context.Context) (productionServerLease, error)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	})))

	// No-op unless FLARE_DSN is set (injected by the deploy step). Release and
	// environment must describe the deployed artifact; reporting every event as
	// release "dev" made production regressions impossible to correlate.
	flarereport.InitFlare("hash", cfg.Release, cfg.Environment)

	ctx := context.Background()

	// Pool for handlers (sqlc). Signer clarification deliberately holds one
	// document SHARE lock while independently committing audit rows; production
	// also reserves one connection for the singleton lease. Refuse pool sizes
	// that can deadlock that accountability path.
	poolConfig, err := serverPoolConfig(cfg.DBURL, cfg.Environment)
	if err != nil {
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("connect pgx pool: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	// Hash's production signer buckets deliberately live in process memory: the
	// magic-token digest is the ceremony identity and generous per-IP ceilings
	// protect the ingress. Enforce the documented single-server production
	// topology at the database boundary so a stray second replica cannot split
	// those aggregate budgets, the in-memory collaboration room map, or the
	// process-local BrightCRM resolver-cache invalidation contract.
	var productionLeaseLost <-chan error
	if cfg.Environment == "production" {
		lease, err := acquireProductionServerLease(ctx, func(ctx context.Context) (productionServerLease, error) {
			return pool.Acquire(ctx)
		})
		if err != nil {
			return err
		}
		defer lease.Release()
		leaseCtx, cancelLeaseMonitor := context.WithCancel(context.Background())
		defer cancelLeaseMonitor()
		productionLeaseLost = monitorProductionServerLease(leaseCtx, lease)
		slog.Info("production singleton HTTP-server lease acquired")
	}

	// Run migrations against a database/sql handle (goose's interface). We
	// open a separate sql.DB on the same DSN; close it after migrations so we
	// don't double-pool.
	if err := runMigrations(ctx, cfg.DBURL); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	queries := generated.New(pool)
	webhookKeys, err := webhooksecret.NewKeyringHex(
		cfg.WebhookEncryptionKey, cfg.WebhookEncryptionKeyPrevious,
	)
	if err != nil {
		return fmt.Errorf("webhook encryption keyring: %w", err)
	}
	webhookSecrets, err := webhooksecret.NewManager(pool, webhookKeys, cfg.WebhookSecret)
	if err != nil {
		return fmt.Errorf("webhook secret manager: %w", err)
	}
	webhookBackfill, err := webhookSecrets.Backfill(ctx)
	if err != nil {
		return fmt.Errorf("webhook secret backfill: %w", err)
	}
	slog.Info("webhook secrets verified at rest",
		"rows", webhookBackfill.Rows,
		"encrypted_legacy", webhookBackfill.EncryptedLegacy,
		"rewrapped_previous_key", webhookBackfill.RewrappedPreviousKey,
		"cleared_plaintext", webhookBackfill.ClearedPlaintext,
	)

	// Storage.
	store, err := storage.New(ctx, storage.Config{
		Endpoint:                         cfg.S3Endpoint,
		Region:                           cfg.S3Region,
		Bucket:                           cfg.S3Bucket,
		AccessKey:                        cfg.S3AccessKey,
		SecretKey:                        cfg.S3SecretKey,
		UseSSL:                           cfg.S3UseSSL,
		SSEMode:                          cfg.S3SSEMode,
		SSECKeyFile:                      cfg.S3SSECKeyFile,
		SSECKeySHA256:                    cfg.S3SSECKeySHA256,
		BucketLookup:                     cfg.S3BucketLookup,
		RequireObjectLock:                !config.IsLocalDevelopment(cfg.PublicURL),
		RequireExistingBucket:            !config.IsLocalDevelopment(cfg.PublicURL),
		SkipTransientLifecycle:           cfg.Environment != "development",
		AllowInsecureDevelopmentEndpoint: cfg.Environment == "development" && config.IsLocalDevelopment(cfg.PublicURL),
	})
	if err != nil {
		return fmt.Errorf("init storage: %w", err)
	}

	// Cookies + OIDC.
	cookies, err := auth.NewSignedCookie(cfg.SessionKey)
	if err != nil {
		return fmt.Errorf("init session cookie: %w", err)
	}
	oidc, err := auth.NewOIDC(ctx, auth.OIDCConfig{
		IssuerURL:    cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		Cookies:      cookies,
	})
	if err != nil {
		// Come up anyway: an IdP that is down must not stop hash from booting.
		//
		// KEEP the returned value. It used to be discarded (`oidc = nil`), which
		// meant a momentary discovery failure during our startup disabled SSO for
		// the whole process lifetime, recoverable only by a restart. Prod hash sat
		// exactly like that from 2026-07-29 02:02 until it was redeployed a day
		// later, with a fully populated /opt/hash/.env the entire time.
		//
		// NewOIDC returns a non-nil, retrying OIDC whenever an issuer is
		// configured, so login self-heals the moment the IdP answers. It returns
		// nil only when no issuer is set at all, and the handlers answer 503.
		slog.Warn("OIDC discovery failed at boot; /auth/login will retry on demand", "err", err)
	}

	auditLog := audit.New(queries, pool)

	// Outbound webhooks: every public audit event fans out to subscribed
	// endpoints. The hook runs synchronously after the audit row inserts but
	// the actual HTTP delivery is async (worker loopWebhookRedrive picks up the
	// pending row on its next tick). Internal-only kinds are filtered by
	// dispatch.IsPublicEventKind. The same helper is wired in the worker so
	// worker-emitted events (expirations, reminders) also fan out.
	dispatch.RegisterWebhookFanout(auditLog, queries)

	apiKeys := &auth.PgVerifier{Queries: queries}
	pdfClient := render.NewGotenberg(cfg.GotenbergURL)

	// Mailer: the server never sends inline. It enqueues into email_deliveries
	// (durable); the worker's email-dispatch loop drains the queue over SMTP
	// with backoff retries, so a transient outage never drops a message.
	var mailer dispatch.Mailer = dispatch.QueueingMailer{Q: queries}

	versionsEngine := versions.New(queries)
	envelopesEngine := envelopes.New(queries)
	eidasEngine := eidas.New(queries)

	// Phase 8.4: AI runtime. Shield key empty => NoopShield (PII passthrough,
	// dev only). Provider creds empty => provider registered but Complete
	// fails with a clean "API key not configured" until the env var lands.
	aiRuntime, err := buildAIRuntime(cfg, queries)
	if err != nil {
		slog.Warn("ai runtime init failed; falling back to no-op", "err", err)
		aiRuntime = ai.New(queries, ai.NoopShield{}, ai.NoopEmbedder{})
	}
	slog.Info("ai runtime ready",
		"providers", aiRuntime.Status().Providers,
		"default", aiRuntime.Status().Default,
		"shield_active", aiRuntime.Status().ShieldActive,
		"prompts", aiRuntime.Status().PromptCount,
	)

	// Phase 8.2: variable resolver. Empty BrightCRM/Scanner creds are fine,
	// the corresponding source plugins return ErrNotConfigured and the UI
	// surfaces a "configure integration" hint per binding. The org-setting
	// source always works (reads local hash.orgs); agent.computed always
	// works (override-only).
	allowPrivateIntegrations := config.IsLocalDevelopment(cfg.PublicURL)
	resolverEngine := resolver.New(queries,
		resolver.NewCRMDealSource(cfg.BrightCRMURL, cfg.BrightCRMToken, allowPrivateIntegrations),
		resolver.NewCRMContactSource(cfg.BrightCRMURL, cfg.BrightCRMToken, allowPrivateIntegrations),
		resolver.NewScannerFindingSource(cfg.ScannerURL, cfg.ScannerToken, allowPrivateIntegrations),
		&resolver.OrgSettingSource{Q: queries},
		resolver.AgentComputedSource{},
	)

	var signer *sign.CertSigner
	if cfg.AuditPrivateKey == "" {
		// config.Load permits an empty audit key only for explicit local
		// development. Keep that convenience, but never continue without a
		// working signer: an unsigned certificate is not legal evidence.
		signer, err = sign.GenerateCertSigner()
		if err != nil || signer == nil {
			return fmt.Errorf("generate local ephemeral audit signer: %w", err)
		}
		slog.Info("ephemeral audit signer generated", "public_key_b64", signer.PublicKeyBase64())
	} else {
		signer, err = sign.NewCertSigner(cfg.AuditPrivateKey)
		if err != nil || signer == nil {
			return fmt.Errorf("init configured audit signer: %w", err)
		}
	}

	brandingResolver := branding.NewResolver(queries)

	signEngine := &sign.Engine{
		Pool:         pool,
		Queries:      queries,
		Storage:      store,
		PDF:          pdfClient,
		Audit:        auditLog,
		Mailer:       mailer,
		Signer:       signer,
		OrgName:      cfg.OperatorName,
		BaseURL:      cfg.PublicURL,
		ActionSecret: cfg.SignerTokenKey,
		BrandingCSS: func(ctx context.Context, doc *generated.Document) (string, error) {
			if doc == nil {
				return branding.DefaultBranding().CSSVariables(), nil
			}
			b, err := brandingResolver.ResolveFrozen(ctx, doc.ID)
			if err != nil {
				return "", err
			}
			return b.CSSVariables(), nil
		},
		EnvelopeManifestHTML: func(ctx context.Context, doc *generated.Document) string {
			if doc == nil || !doc.IsEnvelope {
				return ""
			}
			m, err := envelopesEngine.BuildManifest(ctx, doc)
			if err != nil {
				return ""
			}
			return m.HTMLSection()
		},
		EnvelopeChildren: func(ctx context.Context, doc *generated.Document) ([]*generated.Document, error) {
			if doc == nil || !doc.IsEnvelope {
				return nil, nil
			}
			return envelopesEngine.Children(ctx, doc.ID, doc.OrgID)
		},
	}

	// Phase 10.2 evidence builder. OTS anchoring is opt-in via env so
	// laptop dev doesn't hit the public calendar on every test.
	var otsAnchor evidence.OTSAnchor = evidence.NoopOTSAnchor{}
	if cfg.EvidenceOTSEnabled {
		otsAnchor = evidence.NewHTTPOTSAnchor(cfg.EvidenceOTSEndpoint)
	}
	trustedEvidenceKeys := evidenceTrustedPublicKeys(signer.PublicKeyBase64(), cfg.AuditTrustedPublicKeys)
	evidenceBuilder := &evidence.Builder{
		Q:                            queries,
		Storage:                      store,
		Versions:                     versionsEngine,
		OTSAnchor:                    otsAnchor,
		PublicKeyPEM:                 signerPEM(signer),
		Issuer:                       "Hash / " + cfg.OperatorName,
		Signer:                       signer,
		CertificateTrustedPublicKeys: trustedEvidenceKeys,
	}

	// Phase 11 AI-app helpers. Each wraps the ai.Runtime + one of the
	// three built-in prompts; missing runtime makes them no-op.
	clarifier := &aiapps.Clarifier{Runtime: aiRuntime}
	negotiator := &aiapps.Negotiator{Runtime: aiRuntime}
	bilingual := &aiapps.Bilingual{Runtime: aiRuntime}
	riskAnalyzer := &aiapps.RiskAnalyzer{Runtime: aiRuntime}

	// Phase 12: compliance seeder + flagger + optional authoritative feed.
	// Production never substitutes demo guidance: with no configured feed the
	// manual refresh route is unavailable, matching the worker's fail-closed
	// behavior. Synthetic items exist only in explicit local development.
	complianceSeeder := compliance.New(queries, eidasEngine)
	complianceFlagger := compliance.NewFlagger(queries)
	var complianceFeed compliance.Feed
	if cfg.ComplianceFeedURL != "" {
		complianceFeed = compliance.NewHTTPFeed(cfg.ComplianceFeedURL, config.IsLocalDevelopment(cfg.PublicURL))
	} else if config.IsLocalDevelopment(cfg.PublicURL) {
		complianceFeed = &compliance.SyntheticFeed{Items: compliance.DevelopmentSampleFeedItems()}
	}

	// v1.1 billing. A real provider (Mollie) is mandatory outside local dev;
	// config.Load fails boot before this point if it is absent. The forgeable
	// auto-completing MockProvider runs only on an explicit loopback deployment.
	// Keeping that boundary here too ensures production can never construct a
	// nil engine that silently bypasses quotas and paid-feature checks.
	var billingEngine *billing.Engine
	switch {
	case cfg.BillingProvider == "mollie":
		billingProvider := billing.NewMollieProvider(cfg.MollieAPIKey, cfg.MollieBaseURL, cfg.MollieWebhookPathSecret)
		billingWebhookURL := cfg.PublicURL + "/webhooks/billing/" + cfg.MollieWebhookPathSecret
		billingEngine = billing.New(queries, billingProvider, cfg.PublicURL, billingWebhookURL)
	case config.IsLocalDevelopment(cfg.PublicURL):
		billingWebhookURL := cfg.PublicURL + "/webhooks/billing/" + cfg.MollieWebhookPathSecret
		billingEngine = billing.New(queries, billing.MockProvider{}, cfg.PublicURL, billingWebhookURL)
	}
	if !config.IsLocalDevelopment(cfg.PublicURL) && billingEngine == nil {
		return errors.New("billing: production engine unavailable; HASH_BILLING_PROVIDER=mollie is required")
	}
	// Boot assertion: HasFeature now fails closed on an unresolvable plan, so a missing
	// "free" seed would 402 every paid feature for every org silently. Catch that at
	// deploy time (not in support tickets) in any non-dev instance.
	if !config.IsLocalDevelopment(cfg.PublicURL) {
		if _, ferr := queries.GetBillingPlanBySlug(ctx, "free"); ferr != nil {
			return fmt.Errorf("billing: free plan not seeded (apply migration 00021 before serving): %w", ferr)
		}
	}

	// Document lifecycle engine (send/void/remind). REST, MCP, and the worker
	// all route through it so the magic-token TTL, variable freeze, eIDAS
	// guard, and billing quota are enforced in exactly one place.
	sendEngine := &send.Engine{
		Pool:        pool,
		Queries:     queries,
		Audit:       auditLog,
		Mailer:      mailer,
		Resolver:    resolverEngine,
		EIDAS:       eidasEngine,
		Billing:     billingEngine,
		Envelopes:   envelopesEngine,
		Storage:     store,
		PublicURL:   cfg.PublicURL,
		OrgName:     cfg.OperatorName,
		Environment: cfg.Environment,
	}

	// v1.1 Yjs collaborative editing hub. One per process; the in-memory
	// room map carries connections across the running pod. Horizontal
	// scale-out (room migration via Redis) is a v1.2 concern; single-pod
	// is fine for the v1.1 customer set.
	collabHub := collab.NewHub(queries)

	// MCP server is built last so it can reference every dependency
	// (signer + evidence + branding resolver + envelopes + eidas + AI
	// apps) by value without us having to wire late-bound setters.
	mcpServer := mcp.New(mcp.Deps{
		Pool:           pool,
		Queries:        queries,
		Storage:        store,
		PDF:            pdfClient,
		Audit:          auditLog,
		Mailer:         mailer,
		Versions:       versionsEngine,
		Resolver:       resolverEngine,
		AIRuntime:      aiRuntime,
		Envelopes:      envelopesEngine,
		EIDAS:          eidasEngine,
		Evidence:       evidenceBuilder,
		Clarifier:      clarifier,
		Negotiator:     negotiator,
		Bilingual:      bilingual,
		RiskAnalyzer:   riskAnalyzer,
		Compliance:     complianceSeeder,
		Billing:        billingEngine,
		Send:           sendEngine,
		PublicURL:      cfg.PublicURL,
		Environment:    cfg.Environment,
		WebhookSecrets: webhookKeys,
		RenderEmail:    renderEmailForMCP(cfg.OperatorName),
	})

	srv := &handler.Server{
		Pool:                       pool,
		Queries:                    queries,
		Storage:                    store,
		Audit:                      auditLog,
		OIDC:                       oidc,
		Cookies:                    cookies,
		APIKeys:                    apiKeys,
		MCP:                        mcpServer,
		Sign:                       signEngine,
		Send:                       sendEngine,
		Mailer:                     mailer,
		Versions:                   versionsEngine,
		Resolver:                   resolverEngine,
		AIRuntime:                  aiRuntime,
		BrandingResolver:           brandingResolver,
		Envelopes:                  envelopesEngine,
		EIDAS:                      eidasEngine,
		BrightCRMWebhookSecret:     cfg.BrightCRMWebhookSecret,
		WebhookSecrets:             webhookKeys,
		EvidenceTrustedPublicKeys:  trustedEvidenceKeys,
		EvidenceManifestPublicKeys: []string{signer.PublicKeyBase64()},
		Evidence:                   evidenceBuilder,
		Clarifier:                  clarifier,
		Negotiator:                 negotiator,
		Bilingual:                  bilingual,
		RiskAnalyzer:               riskAnalyzer,
		Compliance:                 complianceSeeder,
		ComplianceFlagger:          complianceFlagger,
		ComplianceFeed:             complianceFeed,
		Billing:                    billingEngine,
		Collab:                     collabHub,
		Frontend:                   frontendHandler(),
		OrgName:                    cfg.OperatorName,
		OperatorName:               cfg.OperatorName,
		PrivacyContact:             cfg.PrivacyContact,
		SupervisoryAuthority:       cfg.SupervisoryAuthority,
		PrivacyPolicyURL:           cfg.PrivacyPolicyURL,
		PublicURL:                  cfg.PublicURL,
		Release:                    cfg.Release,
		Environment:                cfg.Environment,
		ProxyAuth:                  cfg.ProxyAuth,
		ActionSecret:               cfg.SignerTokenKey,
		AISealKey:                  aiSealKey(cfg),
		AIEUHosts:                  strings.Split(strings.ReplaceAll(cfg.AIEUHostsAllowlist, " ", ""), ","),
		CSPScriptSrc:               frontendScriptCSP(), // allow the SvelteKit inline bootstrap under strict CSP
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	serveErr := make(chan error, 1)

	go func() {
		slog.Info("hash listening", "addr", httpServer.Addr, "public_url", cfg.PublicURL)
		serveErr <- httpServer.ListenAndServe()
	}()

	select {
	case <-stop:
		// Normal operator/supervisor shutdown continues below.
	case leaseErr := <-productionLeaseLost:
		// The advisory lock is session-scoped. Losing its dedicated connection
		// means the database may already have granted the singleton lease to a
		// different process, so continuing would make every in-memory rate limit
		// non-aggregate. Close the listener before deferred database cleanup can
		// release the lease, then let the supervisor restart us fail closed.
		if closeErr := httpServer.Close(); closeErr != nil {
			slog.Error("close listener after production singleton lease loss", "err", closeErr)
		}
		return fmt.Errorf("production singleton lease lost; refusing to serve with unenforced aggregate signer limits: %w", leaseErr)
	case listenErr := <-serveErr:
		// Docker restart policies do not restart a process merely because its
		// health check is failing. If the listener exits while main keeps waiting
		// for a signal, the container can remain permanently unavailable. Return
		// the error so main exits non-zero and the supervisor restarts it.
		if listenErr == nil || errors.Is(listenErr, http.ErrServerClosed) {
			return errors.New("http server stopped unexpectedly")
		}
		return fmt.Errorf("http server failed: %w", listenErr)
	}
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	// Flush every live collab room so a SIGTERM/deploy doesn't drop edits
	// accumulated since each room's last periodic flush.
	collabHub.Shutdown(shutdownCtx)
	return nil
}

func serverPoolConfig(dsn, environment string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx pool config: %w", err)
	}
	minimum := int32(2)
	if environment == "production" {
		minimum = 3 // singleton lease + clarification lock + independent audit tx
	}
	if cfg.MaxConns < minimum {
		return nil, fmt.Errorf("database pool max connections is %d; %s requires at least %d", cfg.MaxConns, environment, minimum)
	}
	return cfg, nil
}

func acquireProductionServerLease(ctx context.Context, acquire productionServerLeaseAcquire) (productionServerLease, error) {
	lease, err := acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire dedicated production singleton connection: %w", err)
	}
	var acquired bool
	if err := lease.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", productionServerLockKey).Scan(&acquired); err != nil { //nolint:rawsql
		lease.Release()
		return nil, fmt.Errorf("acquire production singleton advisory lock: %w", err)
	}
	if !acquired {
		lease.Release()
		return nil, errors.New("another production Hash HTTP server holds the singleton lease; shared signer rate limiting is unavailable")
	}
	return lease, nil
}

func monitorProductionServerLease(ctx context.Context, lease productionServerLease) <-chan error {
	lost := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(productionLeaseCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(ctx, productionLeaseCheckTimeout)
				err := verifyProductionServerLease(checkCtx, lease)
				cancel()
				if err == nil {
					continue
				}
				select {
				case lost <- err:
				case <-ctx.Done():
				}
				return
			}
		}
	}()
	return lost
}

func verifyProductionServerLease(ctx context.Context, lease productionServerLease) error {
	// A session advisory lock survives until its exact PostgreSQL connection
	// closes. A successful query proves that session is still alive; pgx does
	// not transparently replace the connection behind an acquired pool lease.
	var one int
	if err := lease.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil { //nolint:rawsql
		return fmt.Errorf("production singleton connection failed: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("production singleton connection returned %d, want 1", one)
	}
	return nil
}

func runMigrations(ctx context.Context, dsn string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}
	// Use a single connection wrapped via stdlib for goose.
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close()
	return mdb.RunMigrations(db)
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func evidenceTrustedPublicKeys(current, historicalCSV string) []string {
	keys := make([]string, 0, 1+strings.Count(historicalCSV, ",")+1)
	seen := map[string]struct{}{}
	for _, key := range append([]string{current}, strings.Split(historicalCSV, ",")...) {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}
