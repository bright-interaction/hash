// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package main runs background workers: webhook re-drives, reminder fires,
// expiration sweeps, email delivery, and compliance/retention jobs. Independent
// loops run on different cadences. Each
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
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/config"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

// Invites and other transactional mail are user-facing, synchronous workflow
// outcomes even though delivery is durably queued. A 20-second poll made a
// freshly-sent document appear to have lost its invitation for most of that
// window. One query per second keeps delivery near-real-time without coupling
// request handlers to SMTP availability.
const emailDispatchPollInterval = time.Second

// runWorker supervises one critical loop. A panic or unexpected return makes
// the process unhealthy immediately so Compose/systemd can restart all loops;
// keeping the process alive after (for example) expiration or finalize-retry
// died would present a dangerously false healthy state.
func runWorker(ctx context.Context, name string, fn func()) {
	superviseWorker(ctx, name, fn, flarereport.CaptureWorkerFatal, os.Exit)
}

// optionalWorkerConfigured gates optional loops before their goroutine is
// launched. Once configured, they use the same fail-fast supervisor as every
// critical loop.
func optionalWorkerConfigured(name string, configured bool) bool {
	if !configured {
		slog.Info("optional worker loop disabled by configuration", "loop", name)
		return false
	}
	return true
}

// superviseWorker accepts its synchronous reporter and terminator as
// dependencies so report-before-exit behavior can be tested without network
// access or exiting the test process.
func superviseWorker(ctx context.Context, name string, fn func(), reportFatal func(string, bool), terminate func(int)) {
	defer func() {
		if recover() != nil {
			// Do not log the recovered value: warn/error logs are exported to a
			// shared observability boundary and panic payloads are arbitrary data.
			slog.Error("worker loop panicked", "loop", name)
			reportFatal(name, true)
			terminate(1)
		}
	}()
	fn()
	if ctx.Err() != nil {
		slog.Info("worker loop stopped", "loop", name, "reason", ctx.Err())
		return
	}
	slog.Error("worker loop exited unexpectedly", "loop", name)
	reportFatal(name, false)
	terminate(1)
}

func initWorkerObservability(release, environment string) bool {
	return flarereport.InitFlare("hash-worker", release, environment)
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
	// The worker is the sole SMTP sender and owns every background lifecycle
	// loop. Give it a distinct heartbeat/log identity so silence or a crash loop
	// cannot be mistaken for a healthy HTTP server. An absent/invalid DSN remains
	// a fail-safe no-op and never blocks local or self-hosted startup.
	initWorkerObservability(cfg.Release, cfg.Environment)

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
	webhookKeys, err := webhooksecret.NewKeyringHex(
		cfg.WebhookEncryptionKey, cfg.WebhookEncryptionKeyPrevious,
	)
	if err != nil {
		slog.Error("webhook encryption keyring", "err", err)
		os.Exit(1)
	}
	webhookSecrets, err := webhooksecret.NewManager(pool, webhookKeys, cfg.WebhookSecret)
	if err != nil {
		slog.Error("webhook secret manager", "err", err)
		os.Exit(1)
	}
	webhookBackfill, err := webhookSecrets.Backfill(ctx)
	if err != nil {
		slog.Error("webhook secret backfill", "err", err)
		os.Exit(1)
	}
	slog.Info("webhook secrets verified at rest",
		"rows", webhookBackfill.Rows,
		"encrypted_legacy", webhookBackfill.EncryptedLegacy,
		"rewrapped_previous_key", webhookBackfill.RewrappedPreviousKey,
		"cleared_plaintext", webhookBackfill.ClearedPlaintext,
	)
	auditLog := audit.New(queries, pool)
	// Worker-emitted events (document.expired, reminder.sent) must fan out to
	// customer webhooks too; previously only the server registered this hook,
	// so those events never reached subscribers.
	dispatch.RegisterWebhookFanout(auditLog, queries)

	mailer, err := dispatch.NewSMTPMailer(dispatch.SMTPConfig{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser,
		Password: cfg.SMTPPassword, From: cfg.SMTPFrom,
	})
	if err != nil {
		slog.Error("smtp init", "err", err)
		os.Exit(1)
	}

	// Engines + direct sends enqueue into email_deliveries (durable); only the
	// email-dispatch loop below talks to SMTP, so a transient outage retries
	// instead of dropping the message. `mailer` above is the real SMTP sender,
	// reused by that loop.
	queueMailer := dispatch.QueueingMailer{Q: queries}

	// Endpoint secrets are resolved and authenticated by webhookSecrets. Keep the
	// dispatcher's legacy instance fallback empty so no future call can silently
	// bypass a failed ciphertext authentication.
	dispatcher := dispatch.NewDispatcher(dispatch.SignaturePair{})
	dispatcher.AllowPrivate = config.IsLocalDevelopment(cfg.PublicURL)

	// Phase 12.2: optional EDPB feed + flagger. Empty endpoint disables
	// the rollup loop entirely (it short-circuits with a single info log).
	var feed compliance.Feed
	if cfg.ComplianceFeedURL != "" {
		feed = compliance.NewHTTPFeed(cfg.ComplianceFeedURL, config.IsLocalDevelopment(cfg.PublicURL))
	}

	// Signing engine for the finalize-retry loop. Mirrors the server's wiring
	// (storage + Gotenberg + cert signer + branding/envelope callbacks) so a
	// worker-driven finalize produces a byte-identical final PDF + audit cert
	// to the inline path. CRITICAL: the worker must read the SAME
	// HASH_AUDIT_PRIVATE_KEY as the server, else retry-finalized certs would
	// be signed by a different ed25519 key.
	var signEngine *sign.Engine
	store, serr := storage.New(ctx, storage.Config{
		Endpoint:          cfg.S3Endpoint,
		Region:            cfg.S3Region,
		Bucket:            cfg.S3Bucket,
		AccessKey:         cfg.S3AccessKey,
		SecretKey:         cfg.S3SecretKey,
		UseSSL:            cfg.S3UseSSL,
		RequireObjectLock: !config.IsLocalDevelopment(cfg.PublicURL),
	})
	if serr != nil {
		slog.Error("worker: storage init failed", "err", serr)
		os.Exit(1)
	}
	signer, kerr := sign.NewCertSigner(cfg.AuditPrivateKey)
	if kerr != nil || signer == nil {
		slog.Error("worker: audit cert signer init failed", "err", kerr)
		os.Exit(1)
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
		OrgName: cfg.OperatorName,
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

	// Lifecycle engine for reminders and durable send-sealing recovery. Draft
	// preparation (resolver/billing) has already completed before the sealing
	// intent commits; recovery rechecks the frozen envelope/eIDAS/source state,
	// applies retention idempotently, then atomically mints links/outbox/audit.
	sendEngine := &send.Engine{
		Pool:      pool,
		Queries:   queries,
		Audit:     auditLog,
		Mailer:    queueMailer,
		EIDAS:     eidas.New(queries),
		Envelopes: envelopesEngine,
		Storage:   store,
		PublicURL: cfg.PublicURL,
		OrgName:   cfg.OperatorName,
	}

	w := &worker{
		pool:              pool,
		queries:           queries,
		audit:             auditLog,
		mailer:            queueMailer,
		emailSender:       mailer,
		dispatcher:        dispatcher,
		webhookSecrets:    webhookSecrets,
		signEngine:        signEngine,
		storage:           store,
		sendEngine:        sendEngine,
		baseURL:           cfg.PublicURL,
		orgName:           cfg.OperatorName,
		complianceFeed:    feed,
		complianceFlagger: compliance.NewFlagger(queries),
	}

	// Independent loops use different cadences so a slow database query in one
	// loop doesn't starve another. Each configured loop runs under fatal
	// supervision so a panic or unexpected return lets the process supervisor
	// restart the complete worker.
	go runWorker(ctx, "reminders", func() { w.loopReminders(ctx) })
	go runWorker(ctx, "expirations", func() { w.loopExpirations(ctx) })
	go runWorker(ctx, "webhook_redrive", func() { w.loopWebhookRedrive(ctx) })
	go runWorker(ctx, "email_dispatch", func() { w.loopEmailDispatch(ctx) })
	go runWorker(ctx, "telemetry_rollup", func() { w.loopTelemetryRollup(ctx) })
	if optionalWorkerConfigured("compliance_rollup", w.complianceFlagger != nil && w.complianceFeed != nil) {
		go runWorker(ctx, "compliance_rollup", func() { w.loopComplianceRollup(ctx) })
	}
	go runWorker(ctx, "quota_warnings", func() { w.loopQuotaWarnings(ctx) })
	go runWorker(ctx, "soft_delete_purge", func() { w.loopSoftDeletePurge(ctx) })
	go runWorker(ctx, "finalize_retry", func() { w.loopFinalizeRetry(ctx) })
	go runWorker(ctx, "send_sealing", func() { w.loopSendSealing(ctx) })

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("hash worker started")
	<-stop
	slog.Info("worker shutting down")
	// Mark loop returns as expected before deferred resource cleanup begins.
	// In particular, pool.Close must not race a still-live supervision context
	// and turn a graceful SIGTERM into exit status 1.
	cancel()
}

// loopSendSealing closes the S3/SQL crash window in Send. Any process exit or
// commit failure after a document enters non-editable `sealing` is recovered
// from the durable intent; a post-retention failure can never fall back to an
// ordinary deletable draft.
func (w *worker) loopSendSealing(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	w.runSendSealingOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runSendSealingOnce(ctx)
		}
	}
}

func (w *worker) runSendSealingOnce(ctx context.Context) {
	if w.sendEngine == nil {
		slog.Warn("send_sealing: lifecycle engine unavailable")
		return
	}
	intents, err := w.queries.ListPendingSendSealingIntents(ctx, 50)
	if err != nil {
		slog.Warn("send_sealing: list intents", "err", err)
		return
	}
	for _, intent := range intents {
		if intent == nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := w.sendEngine.ResumeSendSealing(rctx, intent.DocumentID, intent.OrgID)
		cancel()
		if err != nil {
			slog.Warn("send_sealing: resume failed", "document_id", intent.DocumentID, "err", err)
		}
	}
}

type worker struct {
	pool           *pgxpool.Pool
	queries        *generated.Queries
	audit          *audit.Logger
	mailer         dispatch.Mailer // queue-backed: enqueues into email_deliveries
	emailSender    dispatch.Mailer // real SMTP, used only by loopEmailDispatch
	dispatcher     *dispatch.Dispatcher
	webhookSecrets *webhooksecret.Manager
	// signEngine drives the finalize-retry loop. nil when storage init failed
	// at boot, in which case the loop short-circuits.
	signEngine *sign.Engine
	// storage is shared with signEngine and used by the soft-delete purge to
	// remove document-owned source PDFs before their DB rows are hard-deleted.
	// nil when object-storage initialization failed; purge then retains any row
	// that still needs object cleanup for a later retry.
	storage purgeObjectDeleter
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
	if w.sendEngine == nil {
		slog.Warn("reminders: lifecycle engine unavailable", "document_id", doc.ID)
		return
	}
	if _, rerr := w.sendEngine.Remind(ctx, send.Actor{
		OrgID: doc.OrgID, Email: senderEmail, Via: "worker",
	}, doc.ID, true); rerr != nil {
		slog.Warn("reminders: engine remind failed", "document_id", doc.ID, "err", rerr)
		// Leave the schedule due. A later worker tick retries token rotation,
		// outbox persistence, and audit as one transaction.
		return
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
		transitioned, err := w.expireDocument(ctx, d)
		if err != nil {
			slog.Warn("expirations: transition failed", "document_id", d.ID, "err", err)
			continue
		}
		if !transitioned {
			continue
		}
	}
}

// expireDocument delegates to the shared lifecycle engine so envelope wrappers
// and children expire atomically under the same parent-first lock order used by
// send, void, topology changes, and finalize.
func (w *worker) expireDocument(ctx context.Context, candidate *generated.Document) (bool, error) {
	if w.sendEngine == nil {
		return false, errors.New("expiration lifecycle engine unavailable")
	}
	return w.sendEngine.Expire(ctx, candidate)
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
	// The event ledger is the durable webhook outbox boundary. Reconstruct any
	// fan-out row that was lost if the server/worker exited after committing an
	// event but before its asynchronous audit hook ran.
	if _, err := w.queries.ReconcileMissingWebhookDeliveries(ctx, 500); err != nil {
		slog.Warn("webhooks: reconcile missing deliveries", "err", err)
		// Existing deliveries can still make progress while reconciliation is
		// temporarily unavailable, so continue to the claim step.
	}

	pending, err := w.queries.ClaimDueWebhookDeliveries(ctx, 50)
	if err != nil {
		slog.Warn("webhooks: claim due", "err", err)
		return
	}
	for _, d := range pending {
		w.attemptDelivery(ctx, d)
	}
}

func (w *worker) attemptDelivery(ctx context.Context, d *generated.WebhookDelivery) {
	endpointURL, signingSecret, err := w.webhookSecrets.Endpoint(ctx, d.EndpointID)
	if err != nil {
		slog.Error("webhooks: endpoint secret unavailable", "endpoint_id", d.EndpointID, "err", err)
		_ = w.queries.MarkDeliveryFailed(ctx, generated.MarkDeliveryFailedParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: 0, Valid: true},
			LastError: pgtype.Text{String: "endpoint secret unavailable", Valid: true},
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
	res := w.dispatcher.DispatchWithSecret(cctx, endpointURL, signingSecret, ev)
	cancel()

	if res.Err == nil && res.Status >= 200 && res.Status < 300 {
		_ = w.queries.MarkDeliveryDelivered(ctx, generated.MarkDeliveryDeliveredParams{
			ID: d.ID, LastStatusCode: pgtype.Int4{Int32: int32(res.Status), Valid: true},
		})
		return
	}

	// Schedule next retry or mark failed.
	// Attempts is incremented only when the failure below is persisted, so the
	// claimed row still carries the number of prior failed sends. Passing +1
	// skipped the documented one-minute first retry and exhausted the schedule
	// one slot early.
	next, ok := dispatch.Backoff(int(d.Attempts))
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
	tick := time.NewTicker(emailDispatchPollInterval)
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
	due, err := w.queries.ClaimDueEmailDeliveries(ctx, 50)
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
	// The claimed row has not recorded this failure yet; use the number of prior
	// failures so a first SMTP outage retries after one minute.
	next, ok := dispatch.Backoff(int(d.Attempts))
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
