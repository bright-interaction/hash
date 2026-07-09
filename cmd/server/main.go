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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/aiapps"
	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/billing"
	"github.com/brightinteraction/hash/internal/branding"
	"github.com/brightinteraction/hash/internal/collab"
	"github.com/brightinteraction/hash/internal/compliance"
	"github.com/brightinteraction/hash/internal/config"
	mdb "github.com/brightinteraction/hash/internal/db"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/eidas"
	"github.com/brightinteraction/hash/internal/envelopes"
	"github.com/brightinteraction/hash/internal/evidence"
	"github.com/brightinteraction/hash/internal/flarereport"
	"github.com/brightinteraction/hash/internal/handler"
	"github.com/brightinteraction/hash/internal/mcp"
	"github.com/brightinteraction/hash/internal/qes"
	"github.com/brightinteraction/hash/internal/qes/trustlist"
	"github.com/brightinteraction/hash/internal/render"
	"github.com/brightinteraction/hash/internal/resolver"
	"github.com/brightinteraction/hash/internal/send"
	"github.com/brightinteraction/hash/internal/sign"
	"github.com/brightinteraction/hash/internal/storage"
	"github.com/brightinteraction/hash/internal/versions"
)

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

	// No-op unless FLARE_DSN is set (injected by the deploy step).
	flarereport.InitFlare("hash", "dev")

	ctx := context.Background()

	// Pool for handlers (sqlc).
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("connect pgx pool: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	// Run migrations against a database/sql handle (goose's interface). We
	// open a separate sql.DB on the same DSN; close it after migrations so we
	// don't double-pool.
	if err := runMigrations(ctx, cfg.DBURL); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	queries := generated.New(pool)

	// Storage.
	store, err := storage.New(ctx, storage.Config{
		Endpoint:  cfg.S3Endpoint,
		Region:    cfg.S3Region,
		Bucket:    cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		UseSSL:    cfg.S3UseSSL,
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
		// In local dev without a working IdP we still want the server to come
		// up (just without /auth/login working). Log loudly and continue.
		slog.Warn("OIDC init failed; /auth/login will not work", "err", err)
		oidc = nil
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
	resolverEngine := resolver.New(queries,
		resolver.NewCRMDealSource(cfg.BrightCRMURL, cfg.BrightCRMToken),
		resolver.NewCRMContactSource(cfg.BrightCRMURL, cfg.BrightCRMToken),
		resolver.NewScannerFindingSource(cfg.ScannerURL, cfg.ScannerToken),
		&resolver.OrgSettingSource{Q: queries},
		resolver.AgentComputedSource{},
	)

	signer, err := sign.NewCertSigner(cfg.AuditPrivateKey)
	if err != nil {
		slog.Warn("audit cert signer init failed; certificates will be unsigned", "err", err)
	}
	if signer == nil {
		// First-boot: no key configured. Generate one in-memory for the
		// process lifetime; production should set HASH_AUDIT_PRIVATE_KEY
		// to a stable value so signatures verify across restarts.
		signer, err = sign.GenerateCertSigner()
		if err != nil {
			slog.Warn("could not generate audit signer", "err", err)
		} else {
			slog.Info("ephemeral audit signer generated", "public_key_b64", signer.PublicKeyBase64())
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
		OrgName:      "Bright Interaction",
		BaseURL:      cfg.PublicURL,
		ActionSecret: cfg.SignerTokenKey,
		BrandingCSS: func(ctx context.Context, doc *generated.Document) string {
			if doc == nil {
				return branding.DefaultBranding().CSSVariables()
			}
			b, err := brandingResolver.Resolve(ctx, doc.OrgID, doc.ID)
			if err != nil {
				return branding.DefaultBranding().CSSVariables()
			}
			return b.CSSVariables()
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
	evidenceBuilder := &evidence.Builder{
		Q:            queries,
		Storage:      store,
		Versions:     versionsEngine,
		OTSAnchor:    otsAnchor,
		PublicKeyPEM: signerPEM(signer),
		Issuer:       "Hash / Bright Interaction AB",
	}

	// Phase 11 AI-app helpers. Each wraps the ai.Runtime + one of the
	// three built-in prompts; missing runtime makes them no-op.
	clarifier := &aiapps.Clarifier{Runtime: aiRuntime}
	negotiator := &aiapps.Negotiator{Runtime: aiRuntime}
	bilingual := &aiapps.Bilingual{Runtime: aiRuntime}
	riskAnalyzer := &aiapps.RiskAnalyzer{Runtime: aiRuntime}

	// Phase 12: compliance seeder + flagger + optional EDPB feed. Feed
	// URL empty means the manual /compliance/flag-run endpoint uses the
	// SampleFeedItems starter set; the worker tick short-circuits.
	complianceSeeder := compliance.New(queries, eidasEngine)
	complianceFlagger := compliance.NewFlagger(queries)
	var complianceFeed compliance.Feed
	if cfg.ComplianceFeedURL != "" {
		complianceFeed = compliance.NewHTTPFeed(cfg.ComplianceFeedURL)
	} else {
		complianceFeed = &compliance.SyntheticFeed{Items: compliance.SampleFeedItems()}
	}

	// v1.1 QES: feature-flagged QTSP routing. 'mock' is the laptop/e2e
	// default so the surface stays callable without live Idura creds.
	// 'idura' switches to the live BankID-via-Idura provider.
	var qesProvider qes.Provider = qes.NoopProvider{}
	switch cfg.QESProvider {
	case "mock":
		qesProvider = qes.MockProvider{}
	case "idura":
		qesProvider = qes.NewIduraProvider(cfg.QESIduraBaseURL, cfg.QESIduraAPIKey, cfg.QESIduraTenant)
	}
	qesEngine := qes.New(queries, qesProvider, cfg.PublicURL)
	if tl, err := trustlist.Load(cfg.QESTrustListPath); err != nil {
		// Misconfigured path is a hard error so a missing / unreadable
		// trust list never silently falls through to "accept every chain".
		return fmt.Errorf("qes trust list: %w", err)
	} else if tl != nil {
		qesEngine.TrustList = tl
		slog.Info("qes trust list loaded", "source", tl.Source(), "trusted_roots", tl.Count())
	}

	// v1.1 billing. A real provider (Mollie) is wired ONLY when explicitly
	// configured; the forgeable auto-completing MockProvider runs ONLY in local
	// dev. In any other case (an SES-only prod with billing unset) billingEngine
	// stays nil, so the public /webhooks/billing route and the /billing checkout
	// route never register (server.go gates both on s.Billing != nil). This
	// closes the self-upgrade hole where unset-in-prod silently served the mock
	// webhook, which accepts an unsigned invoice.paid event and flips any org to
	// a paid plan for free.
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
		Pool:      pool,
		Queries:   queries,
		Audit:     auditLog,
		Mailer:    mailer,
		Resolver:  resolverEngine,
		EIDAS:     eidasEngine,
		Billing:   billingEngine,
		Envelopes: envelopesEngine,
		PublicURL: cfg.PublicURL,
		OrgName:   "Bright Interaction",
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
		Pool:         pool,
		Queries:      queries,
		Storage:      store,
		PDF:          pdfClient,
		Audit:        auditLog,
		Mailer:       mailer,
		Versions:     versionsEngine,
		Resolver:     resolverEngine,
		AIRuntime:    aiRuntime,
		Envelopes:    envelopesEngine,
		EIDAS:        eidasEngine,
		Evidence:     evidenceBuilder,
		Clarifier:    clarifier,
		Negotiator:   negotiator,
		Bilingual:    bilingual,
		RiskAnalyzer: riskAnalyzer,
		Compliance:   complianceSeeder,
		QES:          qesEngine,
		Billing:      billingEngine,
		Send:         sendEngine,
		PublicURL:    cfg.PublicURL,
		RenderEmail:  renderEmailForMCP("Bright Interaction"),
	})

	srv := &handler.Server{
		Pool:                   pool,
		Queries:                queries,
		Storage:                store,
		Audit:                  auditLog,
		OIDC:                   oidc,
		Cookies:                cookies,
		APIKeys:                apiKeys,
		MCP:                    mcpServer,
		Sign:                   signEngine,
		Send:                   sendEngine,
		Mailer:                 mailer,
		Versions:               versionsEngine,
		Resolver:               resolverEngine,
		AIRuntime:              aiRuntime,
		BrandingResolver:       brandingResolver,
		Envelopes:              envelopesEngine,
		EIDAS:                  eidasEngine,
		BrightCRMWebhookSecret: cfg.BrightCRMWebhookSecret,
		Evidence:               evidenceBuilder,
		Clarifier:              clarifier,
		Negotiator:             negotiator,
		Bilingual:              bilingual,
		RiskAnalyzer:           riskAnalyzer,
		Compliance:             complianceSeeder,
		ComplianceFlagger:      complianceFlagger,
		ComplianceFeed:         complianceFeed,
		QES:                    qesEngine,
		Billing:                billingEngine,
		Collab:                 collabHub,
		Frontend:               frontendHandler(),
		OrgName:                "Bright Interaction",
		PublicURL:              cfg.PublicURL,
		ActionSecret:           cfg.SignerTokenKey,
		AISealKey:              aiSealKey(cfg),
		AIEUHosts:              strings.Split(strings.ReplaceAll(cfg.AIEUHostsAllowlist, " ", ""), ","),
		CSPScriptSrc:           frontendScriptCSP(), // allow the SvelteKit inline bootstrap under strict CSP
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("hash listening", "addr", httpServer.Addr, "public_url", cfg.PublicURL)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "err", err)
		}
	}()

	<-stop
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
