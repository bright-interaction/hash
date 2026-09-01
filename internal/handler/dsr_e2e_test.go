// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestDSRErasureRollsBackEverySideEffectWhenSignatureScrubFailsE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID := setupDSRE2E(t)
	doc, recipient := seedDSRRecipientE2E(t, ctx, pool, q, orgID, userID, true)
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
		SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	suffix := strings.ReplaceAll(recipient.ID.String(), "-", "")
	functionName := "hash_test_fail_signature_scrub_" + suffix
	triggerName := "hash_test_fail_signature_scrub_trg_" + suffix
	createFunction := fmt.Sprintf(`
CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
  IF OLD.recipient_id = '%s'::uuid THEN
    RAISE EXCEPTION 'forced signature scrub failure';
  END IF;
  RETURN NEW;
END
$body$`, functionName, recipient.ID) //nolint:gosec -- identifier and literal derive from a parsed UUID
	if _, err := pool.Exec(ctx, createFunction); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE UPDATE ON signatures FOR EACH ROW EXECUTE FUNCTION "%s"()`, triggerName, functionName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON signatures`, triggerName)) //nolint:rawsql,gosec
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, functionName))           //nolint:rawsql,gosec
	}()

	recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
	if recorder.Code < 500 {
		t.Fatalf("forced signature scrub failure status = %d, want 5xx; body=%s", recorder.Code, recorder.Body.String())
	}
	freshDSR, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if freshDSR.Status != "open" || freshDSR.SubjectEmail != recipient.Email || freshDSR.SubjectName != recipient.Name {
		t.Fatalf("DSR escaped rollback: status/email/name = %q/%q/%q", freshDSR.Status, freshDSR.SubjectEmail, freshDSR.SubjectName)
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if freshRecipient.Email != recipient.Email || freshRecipient.Name != recipient.Name {
		t.Fatalf("recipient escaped rollback: email/name = %q/%q", freshRecipient.Email, freshRecipient.Name)
	}
	signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil || len(signatures) != 1 {
		t.Fatalf("signatures after rollback = %d, err=%v", len(signatures), err)
	}
	if signatures[0].TypedName != "Original Legal Name" || !signatures[0].SignerUa.Valid {
		t.Fatalf("signature escaped rollback: %#v", signatures[0])
	}
	var terminalEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1 AND kind IN ('data_subject.anonymized','data_subject.fulfilled')`, orgID).Scan(&terminalEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if terminalEvents != 0 {
		t.Fatalf("terminal DSR audit events after rollback = %d, want 0", terminalEvents)
	}
}

func TestDSRConcurrentTerminalTransitionsHaveOneWinnerE2E(t *testing.T) {
	ctx, _, q, server, orgID, userID := setupDSRE2E(t)
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, SubjectEmail: "subject@example.test", SubjectName: "Subject", Kind: "access", RequestedVia: "sender",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	statuses := []string{"fulfilled", "denied"}
	results := make(chan int, len(statuses))
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(statuses))
	for _, status := range statuses {
		status := status
		go func() {
			ready.Done()
			<-start
			results <- transitionDSRE2E(server, orgID, userID, dsr.ID, status).Code
		}()
	}
	ready.Wait()
	close(start)
	counts := map[int]int{}
	for range statuses {
		counts[<-results]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent transition statuses = %#v, want one 200 and one 409", counts)
	}
	fresh, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != "fulfilled" && fresh.Status != "denied" {
		t.Fatalf("terminal status = %q", fresh.Status)
	}
}

func setupDSRE2E(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
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
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	server := &Server{Pool: pool, Queries: q, Audit: audit.New(q, pool)}
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "DSR atomicity " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@dsr.test", Name: "DPO", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, q, server, org.ID, user.ID
}

func seedDSRRecipientE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, orgID, userID uuid.UUID, completed bool) (*generated.Document, *generated.Recipient) {
	t.Helper()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: orgID, Name: "DSR evidence", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: userID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: "original@example.test", Name: "Original Name", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fieldID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO document_fields (document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct, required, options_json)
VALUES ($1,$2,'signature',1,0,0,10,5,true,'[]'::jsonb) RETURNING id`, doc.ID, recipient.ID).Scan(&fieldID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	txq := q.WithTx(tx)
	if _, err := txq.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: orgID}); err != nil {
		t.Fatal(err)
	}
	if _, err := txq.InsertSignature(ctx, generated.InsertSignatureParams{
		DocumentID: doc.ID, RecipientID: recipient.ID, FieldID: fieldID, Font: "serif", TypedName: "Original Legal Name",
		ImageStorageKey: "org/" + orgID.String() + "/documents/" + doc.ID.String() + "/signatures/" + recipient.ID.String() + ".png",
		ImageSha256:     make([]byte, 32),
		ImageVersionID:  pgtype.Text{String: "test-image-version-1", Valid: true}, SignerUa: pgtype.Text{String: "test-agent", Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := txq.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: recipient.ID, DocumentID: doc.ID, Status: "signed", DeclinedReason: pgtype.Text{},
	}); err != nil {
		t.Fatal(err)
	}
	doc, err = txq.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{ID: doc.ID, OrgID: orgID, Status: "in_progress"})
	if err != nil {
		t.Fatal(err)
	}
	pendingSigned, err := audit.New(q, pool).LogTx(ctx, tx, audit.Entry{
		OrgID: orgID, DocumentID: &doc.ID, RecipientID: &recipient.ID,
		Kind: audit.KindDocumentSigned, Payload: map[string]any{"fixture": "dsr-e2e"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pendingSigned)
	if completed {
		doc = completeDSRDocumentE2E(t, ctx, pool, q, doc)
	}
	return doc, recipient
}

func sendDSRDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
	recipient *generated.Recipient,
) *generated.Document {
	t.Helper()
	sealingTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealingTx.Rollback(ctx) }()
	sealingQ := q.WithTx(sealingTx)
	if _, err := sealingQ.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
		ActorUserID: pgtype.UUID{Bytes: doc.SenderID, Valid: true},
		ActorEmail:  "dpo@dsr.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "dsr-fixture",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sealingQ.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		t.Fatal(err)
	}
	if err := sealingTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture send retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture send retention complete: rows=%d err=%v", rows, err)
	}

	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	publishQ := q.WithTx(publishTx)
	sent, err := publishQ.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: recipient.ID, DocumentID: doc.ID})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture recipient sent: rows=%d err=%v", rows, err)
	}
	canonicalEpoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, publishTx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentSent,
		Payload: map[string]any{
			article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1,
			article13.AuditRequiredNoticeSentAtKey: canonicalEpoch,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		t.Fatalf("delete DSR fixture send intent: rows=%d err=%v", rows, err)
	}
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return sent
}

func completeDSRDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
) *generated.Document {
	t.Helper()
	claimed, err := q.BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
		RetentionYears: int32(article13.RetentionYearsV1), ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !claimed.CompletionEffectiveAtBound || !claimed.CompletionEffectiveAt.Valid || !claimed.FinalizationRetainUntil.Valid {
		t.Fatalf("DSR fixture finalization lacks durable commitments: %+v", claimed)
	}
	digest := make([]byte, 32)
	digest[0] = 3
	digestHex := hex.EncodeToString(digest)
	artifactDir := "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/"
	intent, err := q.CreateDocumentFinalizationIntent(ctx, generated.CreateDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Mode: "signature",
		CompletionEffectiveAt: claimed.CompletionEffectiveAt, RetainUntil: claimed.FinalizationRetainUntil,
		FinalPdfKey: artifactDir + "final-" + digestHex + ".pdf", FinalPdfSha256: digest,
		FinalPdfVersionID: pgtype.Text{String: "dsr-final-version-1", Valid: true},
		AuditCertKey:      artifactDir + "audit-" + digestHex + ".pdf", AuditCertSha256: digest,
		AuditCertVersionID: pgtype.Text{String: "dsr-cert-version-1", Valid: true},
		AuditPayloadKey:    artifactDir + "audit-payload-" + digestHex + ".txt", AuditPayloadSha256: digest,
		AuditPayloadVersionID: pgtype.Text{String: "dsr-payload-version-1", Valid: true},
		AuditSignatureKey:     artifactDir + "audit-signature-" + digestHex + ".txt", AuditSignatureSha256: digest,
		AuditSignatureVersionID: pgtype.Text{String: "dsr-audit-signature-version-1", Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkDocumentFinalizationRetentionStarted(ctx, generated.MarkDocumentFinalizationRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture finalization retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkDocumentFinalizationRetentionComplete(ctx, generated.MarkDocumentFinalizationRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture finalization retention complete: rows=%d err=%v", rows, err)
	}

	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	publishQ := q.WithTx(publishTx)
	if _, err := publishQ.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		t.Fatal(err)
	}
	if _, err := publishQ.GetDocumentFinalizationIntentForUpdate(ctx, generated.GetDocumentFinalizationIntentForUpdateParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := publishQ.CompleteDocumentFinalization(ctx, generated.CompleteDocumentFinalizationParams{
		FinalPdfKey: pgtype.Text{String: intent.FinalPdfKey, Valid: true}, FinalPdfSha256: intent.FinalPdfSha256,
		FinalPdfVersionID: intent.FinalPdfVersionID,
		AuditCertKey:      pgtype.Text{String: intent.AuditCertKey, Valid: true}, AuditCertSha256: intent.AuditCertSha256,
		AuditCertVersionID: intent.AuditCertVersionID,
		AuditPayloadKey:    pgtype.Text{String: intent.AuditPayloadKey, Valid: true}, AuditPayloadSha256: intent.AuditPayloadSha256,
		AuditPayloadVersionID: intent.AuditPayloadVersionID,
		AuditSignatureKey:     pgtype.Text{String: intent.AuditSignatureKey, Valid: true}, AuditSignatureSha256: intent.AuditSignatureSha256,
		AuditSignatureVersionID: intent.AuditSignatureVersionID,
		ID:                      doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, publishTx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentCompleted,
		Payload: map[string]any{"fixture": "dsr-e2e"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.DeleteDocumentFinalizationIntent(ctx, generated.DeleteDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("delete DSR fixture finalization intent: rows=%d err=%v", rows, err)
	}
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return completed
}

func transitionDSRE2E(server *Server, orgID, userID, requestID uuid.UUID, status string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), auth.UserIDKey, userID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, orgID)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", requestID.String())
	ctx = context.WithValue(ctx, chi.RouteCtxKey, routeContext)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/dsr/"+requestID.String(), strings.NewReader(`{"status":"`+status+`"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handleTransitionDSR(recorder, req)
	return recorder
}
