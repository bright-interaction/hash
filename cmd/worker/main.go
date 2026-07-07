// Package main runs background workers: webhook re-drives, reminder fires,
// expiration sweeps. Three independent loops on different cadences. Each
// loop logs but never panics; transient errors trigger a retry on the next
// tick.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/branding"
	"github.com/brightinteraction/hash/internal/compliance"
	"github.com/brightinteraction/hash/internal/config"
	mdb "github.com/brightinteraction/hash/internal/db"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/envelopes"
	"github.com/brightinteraction/hash/internal/render"
	"github.com/brightinteraction/hash/internal/send"
	"github.com/brightinteraction/hash/internal/sign"
	"github.com/brightinteraction/hash/internal/storage"
)

// runWorker invokes fn under a deferred panic recovery so a single crash in
// a background goroutine cannot silently kill a worker loop. Panics are
// logged with a full stack trace; the goroutine exits cleanly (compose
// restarts the worker container if every loop dies). Mirrors the dockyard
// runWorker pattern shipped 2026-05-21.
func runWorker(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("worker loop panicked",
				"loop", name,
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
	}()
	fn()
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		slog.Error("pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Run migrations from the worker too so a fresh deploy boots cleanly
	// even if the server hasn't started yet.
	if err := runMigrations(cfg.DBURL); err != nil {
		slog.Error("migrations", "err", err)
		os.Exit(1)
	}
	queries := generated.New(pool)
	auditLog := audit.New(queries, pool)
	// Worker-emitted events (document.expired, reminder.sent) must fan out to
	// customer webhooks too; previously only the server registered this hook,
	// so those events never reached subscribers.
	dispatch.RegisterWebhookFanout(auditLog, queries)

	var mailer dispatch.Mailer = dispatch.NoopMailer{}
	if cfg.SMTPHost != "" && cfg.SMTPFrom != "" {
		if m, err := dispatch.NewSMTPMailer(dispatch.SMTPConfig{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser,
			Password: cfg.SMTPPassword, From: cfg.SMTPFrom,
		}); err == nil {
			mailer = m
		} else {
			slog.Warn("smtp init failed; using noop", "err", err)
		}
	}

	// Engines + direct sends enqueue into email_deliveries (durable); only the
	// email-dispatch loop below talks to SMTP, so a transient outage retries
	// instead of dropping the message. `mailer` above is the real SMTP sender,
	// reused by that loop.
	queueMailer := dispatch.QueueingMailer{Q: queries}

	dispatcher := dispatch.NewDispatcher(dispatch.SignaturePair{
		Primary:  cfg.WebhookSecret,
		Previous: cfg.WebhookSecretPrevious,
	})
	dispatcher.AllowPrivate = config.IsLocalDevelopment(cfg.PublicURL)

	// Phase 12.2: optional EDPB feed + flagger. Empty endpoint disables
	// the rollup loop entirely (it short-circuits with a single info log).
	var feed compliance.Feed
	if cfg.ComplianceFeedURL != "" {
		feed = compliance.NewHTTPFeed(cfg.ComplianceFeedURL)
	}

	// Signing engine for the finalize-retry loop. Mirrors the server's wiring
	// (storage + Gotenberg + cert signer + branding/envelope callbacks) so a
	// worker-driven finalize produces a byte-identical final PDF + audit cert
	// to the inline path. CRITICAL: the worker must read the SAME
	// HASH_AUDIT_PRIVATE_KEY as the server, else retry-finalized certs would
	// be signed by a different ed25519 key.
	var signEngine *sign.Engine
	store, serr := storage.New(ctx, storage.Config{
		Endpoint:  cfg.S3Endpoint,
		Region:    cfg.S3Region,
		Bucket:    cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		UseSSL:    cfg.S3UseSSL,
	})
	if serr != nil {
		slog.Warn("worker: storage init failed; finalize-retry disabled", "err", serr)
	} else {
		signer, kerr := sign.NewCertSigner(cfg.AuditPrivateKey)
		if kerr != nil || signer == nil {
			slog.Warn("worker: audit cert signer init failed; finalize-retry certs may be unsigned", "err", kerr)
		}
		brandingResolver := branding.NewResolver(queries)
		envelopesEngine := envelopes.New(queries)
		signEngine = &sign.Engine{
			Pool:    pool,
			Queries: queries,
			Storage: store,
			PDF:     render.NewGotenberg(cfg.GotenbergURL),
			Audit:   auditLog,
			Mailer:  queueMailer,
			Signer:  signer,
			OrgName: "Bright Interaction",
			BaseURL: cfg.PublicURL,
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
	}

	// Lifecycle engine for the reminder loop. Remind only needs
	// queries/audit/mailer/pool, so the freeze/eIDAS/billing/envelope deps stay
	// nil here (those are send-only and the worker never sends).
	sendEngine := &send.Engine{
		Pool:      pool,
		Queries:   queries,
		Audit:     auditLog,
		Mailer:    queueMailer,
		PublicURL: cfg.PublicURL,
		OrgName:   "Bright Interaction",
	}

	w := &worker{
		pool:              pool,
		queries:           queries,
		audit:             auditLog,
		mailer:            queueMailer,
		emailSender:       mailer,
		dispatcher:        dispatcher,
		signEngine:        signEngine,
		sendEngine:        sendEngine,
		baseURL:           cfg.PublicURL,
		orgName:           "Bright Interaction",
		complianceFeed:    feed,
		complianceFlagger: compliance.NewFlagger(queries),
	}

	// Seven loops. Different cadences so a slow database query in one
	// loop doesn't starve another. Each runs under runWorker so a panic
	// in one loop logs + exits without taking down the others or the
	// process.
	go runWorker("reminders", func() { w.loopReminders(ctx) })
	go runWorker("expirations", func() { w.loopExpirations(ctx) })
	go runWorker("webhook_redrive", func() { w.loopWebhookRedrive(ctx) })
	go runWorker("email_dispatch", func() { w.loopEmailDispatch(ctx) })
	go runWorker("telemetry_rollup", func() { w.loopTelemetryRollup(ctx) })
	go runWorker("compliance_rollup", func() { w.loopComplianceRollup(ctx) })
	go runWorker("quota_warnings", func() { w.loopQuotaWarnings(ctx) })
	go runWorker("soft_delete_purge", func() { w.loopSoftDeletePurge(ctx) })
	go runWorker("finalize_retry", func() { w.loopFinalizeRetry(ctx) })

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("hash worker started")
	<-stop
	slog.Info("worker shutting down")
}

type worker struct {
	pool        *pgxpool.Pool
	queries     *generated.Queries
	audit       *audit.Logger
	mailer      dispatch.Mailer // queue-backed: enqueues into email_deliveries
	emailSender dispatch.Mailer // real SMTP, used only by loopEmailDispatch
	dispatcher  *dispatch.Dispatcher
	// signEngine drives the finalize-retry loop. nil when storage init failed
	// at boot, in which case the loop short-circuits.
	signEngine *sign.Engine
	// sendEngine drives reminder re-minting through the shared lifecycle engine
	// so worker-minted links always carry an expiry.
	sendEngine *send.Engine
	baseURL    string
	orgName    string

	// Phase 12.2: nil when HASH_COMPLIANCE_FEED_URL is unset, so
	// the compliance rollup loop short-circuits with a single info log.
	complianceFeed    compliance.Feed
	complianceFlagger *compliance.Flagger
}

// loopReminders fires reminder emails on the schedule_json cadence.
func (w *worker) loopReminders(ctx context.Context) {
	tick := time.NewTicker(60 * time.Minute)
	defer tick.Stop()
	w.runRemindersOnce(ctx) // run immediately on boot too
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runRemindersOnce(ctx)
		}
	}
}

func (w *worker) runRemindersOnce(ctx context.Context) {
	due, err := w.queries.GetDueReminders(ctx, 100)
	if err != nil {
		slog.Warn("reminders: get due", "err", err)
		return
	}
	for _, rem := range due {
		w.fireReminder(ctx, rem)
	}
}

func (w *worker) fireReminder(ctx context.Context, rem *generated.Reminder) {
	doc, err := w.queries.GetDocumentByID(ctx, rem.DocumentID)
	if err != nil {
		slog.Warn("reminders: load document", "doc_id", rem.DocumentID, "err", err)
		return
	}
	if doc.Status != "sent" && doc.Status != "in_progress" {
		// Cancel: doc moved out of the remindable window.
		_ = w.queries.CancelReminder(ctx, rem.DocumentID)
		return
	}

	// Route the mint + email + audit through the shared lifecycle engine so the
	// reminder link always carries an expiry. The raw UPDATE this replaced left
	// magic_token_expires_at NULL, so worker-minted reminder links never
	// expired (and re-mints of post-expiry links would otherwise be born dead).
	senderEmail := ""
	if sender, serr := w.queries.GetUser(ctx, doc.SenderID); serr == nil {
		senderEmail = sender.Email
	}
	if w.sendEngine != nil {
		if _, rerr := w.sendEngine.Remind(ctx, send.Actor{
			OrgID: doc.OrgID, Email: senderEmail, Via: "worker",
		}, doc.ID, true); rerr != nil {
			slog.Warn("reminders: engine remind failed", "document_id", doc.ID, "err", rerr)
		}
	}

	// The worker still owns the schedule advance.
	next, fires := nextReminderTime(rem.ScheduleJson, int(rem.FiresRemaining))
	if err := w.queries.AdvanceReminder(ctx, generated.AdvanceReminderParams{
		DocumentID: rem.DocumentID,
		NextFireAt: pgtype.Timestamptz{Time: next, Valid: true},
	}); err != nil {
		// If AdvanceReminder fails the loop fires again next tick, which is the
		// desired safety: better re-send the same reminder than skip a future one.
		slog.Warn("reminders: advance failed", "err", err, "document_id", doc.ID, "fires", fires)
	}
}

// nextReminderTime walks schedule_json and returns when the next reminder
// should fire after the current one. Schedule shape: [{"days_after_send": N}, ...].
func nextReminderTime(scheduleJSON []byte, firesRemaining int) (time.Time, int) {
	var schedule []struct {
		DaysAfterSend int `json:"days_after_send"`
	}
	_ = json.Unmarshal(scheduleJSON, &schedule)
	// firesRemaining starts at len(schedule); after this fire it drops by 1
	// (the AdvanceReminder query handles the decrement). We pick the next
	// entry from the schedule by index.
	idx := len(schedule) - firesRemaining + 1
	if idx >= 0 && idx < len(schedule) {
		return time.Now().Add(time.Duration(schedule[idx].DaysAfterSend) * 24 * time.Hour), firesRemaining - 1
	}
	// No more entries: fire-and-done.
	return time.Now().Add(365 * 24 * time.Hour), 0
}

// loopExpirations transitions sent / in_progress documents past expires_at.
func (w *worker) loopExpirations(ctx context.Context) {
	tick := time.NewTicker(60 * time.Minute)
	defer tick.Stop()
	w.runExpirationsOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runExpirationsOnce(ctx)
		}
	}
}

func (w *worker) runExpirationsOnce(ctx context.Context) {
	docs, err := w.queries.GetExpirableDocuments(ctx, 100)
	if err != nil {
		slog.Warn("expirations: list", "err", err)
		return
	}
	for _, d := range docs {
		if _, err := w.queries.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
			ID: d.ID, OrgID: d.OrgID, Status: "expired",
		}); err != nil {
			continue
		}
		_, _ = w.audit.Log(ctx, audit.Entry{
			OrgID: d.OrgID, DocumentID: &d.ID,
			Kind: audit.KindDocumentExpired,
		})
		// Cancel the reminder schedule.
		_ = w.queries.CancelReminder(ctx, d.ID)
	}
}

// loopWebhookRedrive ships pending + retrying deliveries until success or
// the backoff schedule is exhausted.
func (w *worker) loopWebhookRedrive(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	w.runWebhookRedriveOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runWebhookRedriveOnce(ctx)
		}
	}
}

func (w *worker) runWebhookRedriveOnce(ctx context.Context) {
	pending, err := w.queries.ListPendingDeliveries(ctx, 50)
	if err != nil {
		slog.Warn("webhooks: list pending", "err", err)
		return
	}
	for _, d := range pending {
		w.attemptDelivery(ctx, d)
	}
}

func (w *worker) attemptDelivery(ctx context.Context, d *generated.WebhookDelivery) {
	endpoint, err := w.loadEndpoint(ctx, d.EndpointID)
	if err != nil {
		_ = w.queries.MarkDeliveryFailed(ctx, generated.MarkDeliveryFailedParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: 0, Valid: true},
			LastError: pgtype.Text{String: "endpoint missing", Valid: true},
		})
		return
	}
	ev, err := dispatch.LoadEvent(ctx, w.queries, d.EventID)
	if err != nil {
		_ = w.queries.MarkDeliveryFailed(ctx, generated.MarkDeliveryFailedParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: 0, Valid: true},
			LastError: pgtype.Text{String: "event missing: " + err.Error(), Valid: true},
		})
		return
	}

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	res := w.dispatcher.DispatchWithSecret(cctx, endpoint.Url, endpoint.Secret, ev)
	cancel()

	if res.Err == nil && res.Status >= 200 && res.Status < 300 {
		_ = w.queries.MarkDeliveryDelivered(ctx, generated.MarkDeliveryDeliveredParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: int32(res.Status), Valid: true},
		})
		return
	}

	// Schedule next retry or mark failed.
	next, ok := dispatch.Backoff(int(d.Attempts) + 1)
	errMsg := ""
	if res.Err != nil {
		errMsg = res.Err.Error()
	} else {
		errMsg = fmt.Sprintf("status=%d body=%s", res.Status, truncate(res.Body, 200))
	}
	if !ok {
		_ = w.queries.MarkDeliveryFailed(ctx, generated.MarkDeliveryFailedParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: int32(res.Status), Valid: true},
			LastError: pgtype.Text{String: errMsg, Valid: true},
		})
		return
	}
	_ = w.queries.MarkDeliveryRetrying(ctx, generated.MarkDeliveryRetryingParams{
		ID: d.ID, LastStatusCode: pgtype.Int4{Int32: int32(res.Status), Valid: true},
		LastError:     pgtype.Text{String: errMsg, Valid: true},
		NextAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(next), Valid: true},
	})
}

// loopEmailDispatch drains the durable email queue, sending each message over
// real SMTP with backoff retries. Mirrors the webhook redrive loop so a
// transient SMTP outage retries instead of dropping invites/reminders.
func (w *worker) loopEmailDispatch(ctx context.Context) {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	w.runEmailDispatchOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runEmailDispatchOnce(ctx)
		}
	}
}

func (w *worker) runEmailDispatchOnce(ctx context.Context) {
	due, err := w.queries.ListDueEmailDeliveries(ctx, 50)
	if err != nil {
		slog.Warn("email_dispatch: list due", "err", err)
		return
	}
	for _, d := range due {
		w.attemptEmail(ctx, d)
	}
}

func (w *worker) attemptEmail(ctx context.Context, d *generated.EmailDelivery) {
	var headers map[string]string
	if len(d.HeadersJson) > 0 {
		_ = json.Unmarshal(d.HeadersJson, &headers)
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := w.emailSender.Send(sctx, dispatch.Message{
		To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody,
		ReplyTo: d.ReplyTo, FromName: d.FromName, Headers: headers,
	})
	cancel()
	if err == nil {
		_ = w.queries.MarkEmailDeliverySent(ctx, d.ID)
		return
	}
	next, ok := dispatch.Backoff(int(d.Attempts) + 1)
	if !ok {
		_ = w.queries.MarkEmailDeliveryFailed(ctx, generated.MarkEmailDeliveryFailedParams{
			ID: d.ID, LastError: truncate(err.Error(), 500),
		})
		return
	}
	_ = w.queries.MarkEmailDeliveryRetrying(ctx, generated.MarkEmailDeliveryRetryingParams{
		ID:            d.ID,
		LastError:     truncate(err.Error(), 500),
		NextAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(next), Valid: true},
	})
}

func (w *worker) loadEndpoint(ctx context.Context, id uuid.UUID) (*generated.WebhookEndpoint, error) {
	row := w.pool.QueryRow(ctx,
		`SELECT id, org_id, url, secret_ref, secret, events_subscribed, active, created_at FROM webhook_endpoints WHERE id = $1`, id)
	var ep generated.WebhookEndpoint
	if err := row.Scan(&ep.ID, &ep.OrgID, &ep.Url, &ep.SecretRef, &ep.Secret, &ep.EventsSubscribed, &ep.Active, &ep.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("not found: %s", id)
		}
		return nil, err
	}
	return &ep, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func runMigrations(dsn string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close()
	return mdb.RunMigrations(db)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
