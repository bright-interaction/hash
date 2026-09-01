// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
)

func TestAutomationSignatureRequestIsAtomicConcurrentAndReplaySafeE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	auditLog := audit.New(q, pool)

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Automation request " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@automation.test", Name: "Automation Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	tree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "intro", Type: blocks.TypeParagraph, Text: "Agreement for {{customer.name}}"},
		{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	template, err := q.CreateBlocksTemplate(ctx, generated.CreateBlocksTemplateParams{
		OrgID: org.ID, Name: "Partner agreement", BlocksJson: blocksJSON,
		VariablesJson: json.RawMessage(`{"customer.name":"Template default"}`), CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sendEngine := &send.Engine{
		Pool: pool, Queries: q, Audit: auditLog, Mailer: dispatch.NoopMailer{},
		PublicURL: "https://hash.example.test", OrgName: "Hash E2E",
	}
	server := &Server{Pool: pool, Queries: q, Audit: auditLog, Send: sendEngine}
	prepared, requestHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: template.ID.String(), Name: "Ada partner agreement", LawfulBasis: "contract",
		Variables:  map[string]string{"customer.name": "Ada"},
		Recipients: []automationSignatureRecipientInput{{Email: "ada@example.test", Name: "Ada", Locale: "en"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	processInput := automationSignatureRequestProcessInput{
		User:    auth.SessionUser{UserID: user.ID, OrgID: org.ID, Role: user.Role, Email: user.Email},
		Request: prepared, IdempotencyKeyHash: automationIdempotencyKeyHash("e2e-send-" + uuid.NewString()),
		RequestHash: requestHash, IP: "127.0.0.1", UserAgent: "hash-e2e",
	}

	first, err := server.processAutomationSignatureRequest(ctx, processInput)
	if err != nil {
		t.Fatalf("first composite request: %v", err)
	}
	if first.Replayed || first.Status != "sent" || first.AutomationRequestID == uuid.Nil || first.DocumentID == uuid.Nil {
		t.Fatalf("first response = %#v", first)
	}
	replayed, err := server.processAutomationSignatureRequest(ctx, processInput)
	if err != nil {
		t.Fatalf("replay composite request: %v", err)
	}
	if !replayed.Replayed || replayed.AutomationRequestID != first.AutomationRequestID || replayed.DocumentID != first.DocumentID || replayed.Status != "sent" {
		t.Fatalf("replay response = %#v, first = %#v", replayed, first)
	}
	document, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: first.DocumentID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	variables, err := blocks.ParseVariableValues(document.VariablesJson)
	if err != nil || variables["customer.name"] != "Ada" {
		t.Fatalf("frozen variables = %#v/%v", variables, err)
	}
	versions, err := q.CountDocumentVersions(ctx, document.ID)
	if err != nil || versions != 1 {
		t.Fatalf("document versions = %d/%v, want 1", versions, err)
	}
	var documentCount, recipientCount int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM documents WHERE org_id = $1 AND template_id = $2),
		(SELECT count(*) FROM recipients WHERE document_id = $3)`, org.ID, template.ID, document.ID).Scan(&documentCount, &recipientCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if documentCount != 1 || recipientCount != 1 {
		t.Fatalf("replay created documents/recipients = %d/%d, want 1/1", documentCount, recipientCount)
	}
	// Every later Hash lifecycle callback carries a durable Hash-owned
	// correlation back to this command. The producer can persist the composite
	// response once, then update CRM state from signed callbacks without Hash
	// retaining the producer's raw idempotency key.
	var sentEventID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM events WHERE document_id = $1 AND kind = 'document.sent' ORDER BY created_at LIMIT 1`, first.DocumentID).Scan(&sentEventID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	lifecycleEvent, err := dispatch.LoadEvent(ctx, q, sentEventID)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycleEvent.AutomationRequestID != first.AutomationRequestID.String() {
		t.Fatalf("lifecycle automation_request_id = %q, want %q",
			lifecycleEvent.AutomationRequestID, first.AutomationRequestID)
	}

	collision := processInput
	collision.RequestHash[0] ^= 0xff
	if _, err := server.processAutomationSignatureRequest(ctx, collision); !errors.Is(err, errAutomationIdempotencyConflict) {
		t.Fatalf("same key/different request error = %v", err)
	}

	// A command can materialize successfully and then sit in a retry queue. The
	// replay must re-check the persisted absolute deadline instead of sending a
	// draft whose signing links are already too close to expiry.
	expiringPrepared, expiringHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: template.ID.String(), Name: "Expiring partner agreement", LawfulBasis: "contract",
		Variables:  map[string]string{"customer.name": "Grace"},
		Recipients: []automationSignatureRecipientInput{{Email: "grace@example.test", Name: "Grace", Locale: "en"}},
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	expiringInput := automationSignatureRequestProcessInput{
		User: processInput.User, Request: expiringPrepared,
		IdempotencyKeyHash: automationIdempotencyKeyHash("e2e-expiring-" + uuid.NewString()),
		RequestHash:        expiringHash, IP: "127.0.0.1", UserAgent: "hash-e2e",
	}
	expiringRequest, _, err := server.materializeAutomationSignatureRequest(ctx, expiringInput)
	if err != nil {
		t.Fatal(err)
	}
	expiringDocumentID := uuid.UUID(expiringRequest.DocumentID.Bytes)
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '4 minutes' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if _, err := server.processAutomationSignatureRequest(ctx, expiringInput); !errors.Is(err, errAutomationExpiryTooSoon) {
		t.Fatalf("delayed replay expiry error = %v, want ErrAutomationExpiryTooSoon", err)
	}
	var expiringStatus string
	var expiringInviteEvents int
	if err := pool.QueryRow(ctx, `SELECT status FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, expiringDocumentID).Scan(&expiringInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "draft" || expiringInviteEvents != 0 {
		t.Fatalf("delayed replay status/invites = %s/%d, want draft/0", expiringStatus, expiringInviteEvents)
	}

	stageExpiringSealing := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '10 minutes' WHERE id = $1 AND status = 'draft'`, expiringDocumentID); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		tq := generated.New(tx)
		if _, err := tq.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
			DocumentID: expiringDocumentID, OrgID: org.ID, LawfulBasis: "contract", Via: "automation",
			ConfirmedBy: pgtype.UUID{Bytes: user.ID, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tq.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
			DocumentID: expiringDocumentID, OrgID: org.ID,
			ActorUserID: pgtype.UUID{Bytes: user.ID, Valid: true}, ActorEmail: user.Email,
			ActorIp: "127.0.0.1", Via: "automation", Tool: "signature_request",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tq.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: expiringDocumentID, OrgID: org.ID}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Before retention begins, a now-too-close deadline unwinds sealing back to
	// a truthful editable draft and consumes the intent atomically.
	stageExpiringSealing()
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '4 minutes' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if _, err := sendEngine.ResumeSendSealing(ctx, expiringDocumentID, org.ID); !errors.Is(err, send.ErrExpiryTooSoon) {
		t.Fatalf("reversible expired sealing error = %v, want ErrExpiryTooSoon", err)
	}
	var expiringIntentCount int
	if err := pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM send_sealing_intents WHERE document_id = $1) FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus, &expiringIntentCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "draft" || expiringIntentCount != 0 {
		t.Fatalf("reversible sealing status/intents = %s/%d, want draft/0", expiringStatus, expiringIntentCount)
	}

	// Once the retention-start marker is durable, recovery must never return to
	// draft. If the absolute deadline elapsed meanwhile, finish the evidence
	// epoch and land atomically in expired without invitations or born-expired
	// links.
	stageExpiringSealing()
	if rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: expiringDocumentID, OrgID: org.ID}); err != nil || rows != 1 {
		t.Fatalf("mark retention started rows/error = %d/%v", rows, err)
	}
	if rows, err := q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: expiringDocumentID, OrgID: org.ID}); err != nil || rows != 1 {
		t.Fatalf("mark retention complete rows/error = %d/%v", rows, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() - interval '1 minute' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	expiredRecovery, err := sendEngine.ResumeSendSealing(ctx, expiringDocumentID, org.ID)
	if err != nil {
		t.Fatalf("irreversible expired sealing recovery: %v", err)
	}
	if expiredRecovery.Status != "expired" || len(expiredRecovery.Links) != 0 {
		t.Fatalf("irreversible expired recovery = %#v, want expired with no links", expiredRecovery)
	}
	var expiredEvents int
	if err := pool.QueryRow(ctx, `SELECT status,
		(SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'),
		(SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'document.expired')
		FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus, &expiringInviteEvents, &expiredEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "expired" || expiringInviteEvents != 0 || expiredEvents != 1 {
		t.Fatalf("irreversible recovery status/invites/expired-events = %s/%d/%d, want expired/0/1", expiringStatus, expiringInviteEvents, expiredEvents)
	}

	// Race the complete materialize + sealing + send path. Both calls must
	// recover one durable command result rather than enqueueing two ceremonies.
	completeConcurrent := processInput
	completeConcurrent.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-complete-concurrent-" + uuid.NewString())
	completeResponses := make(chan struct {
		response automationSignatureRequestResponse
		err      error
	}, 2)
	completeStart := make(chan struct{})
	var completeReady sync.WaitGroup
	completeReady.Add(2)
	for range 2 {
		go func() {
			completeReady.Done()
			<-completeStart
			response, callErr := server.processAutomationSignatureRequest(ctx, completeConcurrent)
			completeResponses <- struct {
				response automationSignatureRequestResponse
				err      error
			}{response: response, err: callErr}
		}()
	}
	completeReady.Wait()
	close(completeStart)
	var completeRequestID, completeDocumentID uuid.UUID
	for range 2 {
		result := <-completeResponses
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.Status != "sent" {
			t.Fatalf("complete concurrent status = %q, want sent", result.response.Status)
		}
		if completeRequestID == uuid.Nil {
			completeRequestID = result.response.AutomationRequestID
			completeDocumentID = result.response.DocumentID
		} else if result.response.AutomationRequestID != completeRequestID || result.response.DocumentID != completeDocumentID {
			t.Fatalf("complete concurrent commands diverged: %#v", result.response)
		}
	}
	var completeDocumentCount, completeInviteEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE id = $1`, completeDocumentID).Scan(&completeDocumentCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, completeDocumentID).Scan(&completeInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if completeDocumentCount != 1 || completeInviteEvents != 1 {
		t.Fatalf("complete concurrency docs/invite events = %d/%d, want 1/1", completeDocumentCount, completeInviteEvents)
	}
	// A recovery worker can race a successful completion after selecting the
	// now-consumed intent. It must converge from the authoritative send proof
	// without recreating bearer links or reporting a false retry failure.
	alreadyCompleted, err := sendEngine.ResumeSendSealing(ctx, completeDocumentID, org.ID)
	if err != nil || alreadyCompleted.Status != "sent" || len(alreadyCompleted.Links) != 0 {
		t.Fatalf("post-completion recovery = %#v/%v, want sent without reconstructed links", alreadyCompleted, err)
	}
	if _, err := q.RequestChangesOnDocument(ctx, generated.RequestChangesOnDocumentParams{ID: completeDocumentID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&sign.Engine{Pool: pool, Queries: q, Audit: auditLog}).Revise(ctx, org.ID, completeDocumentID); err != nil {
		t.Fatal(err)
	}
	if _, err := server.processAutomationSignatureRequest(ctx, completeConcurrent); !errors.Is(err, errAutomationCeremonySuperseded) {
		t.Fatalf("revised ceremony replay error = %v, want superseded conflict", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, completeDocumentID).Scan(&completeInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if completeInviteEvents != 1 {
		t.Fatalf("revised replay added invite events: got %d, want 1", completeInviteEvents)
	}

	// Exercise the claim race separately from Send: both callers must converge
	// on the same prepared draft and exactly one may report first materialization.
	concurrent := processInput
	concurrent.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-concurrent-" + uuid.NewString())
	responses := make(chan struct {
		request  *generated.AutomationSignatureRequest
		replayed bool
		err      error
	}, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			request, wasReplay, callErr := server.materializeAutomationSignatureRequest(ctx, concurrent)
			responses <- struct {
				request  *generated.AutomationSignatureRequest
				replayed bool
				err      error
			}{request: request, replayed: wasReplay, err: callErr}
		}()
	}
	ready.Wait()
	close(start)
	var concurrentID, concurrentDocumentID uuid.UUID
	firstCount, replayCount := 0, 0
	for range 2 {
		result := <-responses
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.replayed {
			replayCount++
		} else {
			firstCount++
		}
		if concurrentID == uuid.Nil {
			concurrentID = result.request.ID
			concurrentDocumentID = uuid.UUID(result.request.DocumentID.Bytes)
		} else if result.request.ID != concurrentID || uuid.UUID(result.request.DocumentID.Bytes) != concurrentDocumentID {
			t.Fatalf("concurrent claims diverged: %#v", result.request)
		}
	}
	if firstCount != 1 || replayCount != 1 {
		t.Fatalf("concurrent first/replay = %d/%d, want 1/1", firstCount, replayCount)
	}

	// Simulate the existing hard purge of an abandoned draft. ON DELETE SET
	// NULL must retain the key/request digest so a late retry can only return a
	// tombstone, never create another document.
	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1 AND status = 'draft'`, concurrentDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	tombstone, err := q.GetAutomationSignatureRequest(ctx, generated.GetAutomationSignatureRequestParams{ID: concurrentID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if tombstone.DocumentID.Valid {
		t.Fatalf("hard-deleted draft still bound to document %s", uuid.UUID(tombstone.DocumentID.Bytes))
	}

	// A quota rejection must roll back the claimed idempotency row, document,
	// recipients, version, and audits. Otherwise 402 responses silently strand
	// PII-bearing drafts which themselves consume more quota.
	billingEngine := billing.New(q, billing.MockProvider{}, "", "")
	plan, _, err := billingEngine.PlanForOrg(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DocumentQuotaMonthly <= 0 {
		t.Fatal("fixture free plan must have a document quota")
	}
	var documentsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE org_id = $1`, org.ID).Scan(&documentsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	for documentsBefore < int(plan.DocumentQuotaMonthly) {
		if _, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID: org.ID, Name: "quota fixture", BlocksJson: blocksJSON,
			VariablesJson: json.RawMessage(`{"customer.name":"fixture"}`), SenderID: user.ID,
		}); err != nil {
			t.Fatal(err)
		}
		documentsBefore++
	}
	var requestsBefore, recipientsBefore, eventsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM automation_signature_requests WHERE org_id = $1`, org.ID).Scan(&requestsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id = $1`, org.ID).Scan(&recipientsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1`, org.ID).Scan(&eventsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	server.Billing = billingEngine
	quotaInput := processInput
	quotaInput.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-quota-" + uuid.NewString())
	if _, _, err := server.materializeAutomationSignatureRequest(ctx, quotaInput); !errors.Is(err, billing.ErrQuotaExceeded) {
		t.Fatalf("quota materialization error = %v, want ErrQuotaExceeded", err)
	}
	var documentsAfter, requestsAfter, recipientsAfter, eventsAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE org_id = $1`, org.ID).Scan(&documentsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM automation_signature_requests WHERE org_id = $1`, org.ID).Scan(&requestsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id = $1`, org.ID).Scan(&recipientsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1`, org.ID).Scan(&eventsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if documentsAfter != documentsBefore || requestsAfter != requestsBefore || recipientsAfter != recipientsBefore || eventsAfter != eventsBefore {
		t.Fatalf("quota rollback leaked rows docs %d/%d requests %d/%d recipients %d/%d events %d/%d",
			documentsBefore, documentsAfter, requestsBefore, requestsAfter,
			recipientsBefore, recipientsAfter, eventsBefore, eventsAfter)
	}
}
