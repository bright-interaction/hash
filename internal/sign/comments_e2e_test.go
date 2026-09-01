// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package sign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestCommentsSerializeWithFinalizationAndRollbackOnAuditFailureE2E(t *testing.T) {
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
	engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.QueueingMailer{Q: q}}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "comment atomicity " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@comment.test", Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "comment atomicity", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@recipient.comment.test", Name: "Recipient", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, "UPDATE documents SET status = 'sent', sent_at = $2 WHERE id = $1", doc.ID, sentAt); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	doc, err = q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}

	// Force only this document's comment audit insert to fail. Because the
	// comment row and LogTx share a transaction, neither author path may leave a
	// comment behind.
	suffix := strings.ReplaceAll(doc.ID.String(), "-", "")
	functionName := "hash_test_fail_comment_" + suffix
	triggerName := "hash_test_fail_comment_trg_" + suffix
	createFunction := fmt.Sprintf(`
CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
  IF NEW.document_id = '%s'::uuid AND NEW.kind = 'document.comment_posted' THEN
    RAISE EXCEPTION 'forced comment audit failure';
  END IF;
  RETURN NEW;
END
$body$`, functionName, doc.ID) //nolint:gosec -- identifier and literal derive from a parsed UUID
	if _, err := pool.Exec(ctx, createFunction); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	createTrigger := fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION "%s"()`, triggerName, functionName)
	if _, err := pool.Exec(ctx, createTrigger); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON events`, triggerName)) //nolint:rawsql,gosec
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, functionName))       //nolint:rawsql,gosec
	}()

	if _, err := engine.SenderComment(ctx, org.ID, doc.ID, user.ID, user.Name, "sender body"); err == nil {
		t.Fatal("sender comment succeeded despite forced audit failure")
	}
	assertCommentCountE2E(t, ctx, pool, doc.ID, 0)
	assertCommentEventCountE2E(t, ctx, pool, doc.ID, 0)
	assertEmailDeliveryCountE2E(t, ctx, pool, []string{user.Email, recipient.Email}, 0)

	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER "%s" ON events`, triggerName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION "%s"()`, functionName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}

	// Production uses QueueingMailer. Force its email outbox insert to fail and
	// prove both supported comment authoring paths roll the comment and audit event
	// back with it instead of acknowledging a comment whose notification vanished.
	deliveryFunctionName := "hash_test_fail_comment_delivery_" + suffix
	deliveryTriggerName := "hash_test_fail_comment_delivery_trg_" + suffix
	createDeliveryFunction := fmt.Sprintf(`
CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
  RAISE EXCEPTION 'forced comment email enqueue failure';
END
$body$`, deliveryFunctionName)
	if _, err := pool.Exec(ctx, createDeliveryFunction); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	createDeliveryTrigger := fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON email_deliveries FOR EACH ROW EXECUTE FUNCTION "%s"()`, deliveryTriggerName, deliveryFunctionName)
	if _, err := pool.Exec(ctx, createDeliveryTrigger); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON email_deliveries`, deliveryTriggerName)) //nolint:rawsql,gosec
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, deliveryFunctionName))                 //nolint:rawsql,gosec
	}()

	if _, err := engine.SenderComment(ctx, org.ID, doc.ID, user.ID, user.Name, "sender delivery failure"); err == nil {
		t.Fatal("sender comment committed despite forced email enqueue failure")
	}
	rc := &RecipientContext{
		Document: doc,
		Recipient: &generated.GetRecipientByTokenHashRow{
			ID: recipient.ID, DocumentID: doc.ID, Role: recipient.Role,
			Email: recipient.Email, Name: recipient.Name, DocOrgID: org.ID,
		},
	}
	if _, err := engine.SignerComment(ctx, rc, "signer delivery failure", ParticipantResponseEvidence{
		Notice: testArticle13NoticeEvidence(t, rc),
	}); err == nil {
		t.Fatal("signer comment committed despite forced email enqueue failure")
	}
	assertCommentCountE2E(t, ctx, pool, doc.ID, 0)
	assertCommentEventCountE2E(t, ctx, pool, doc.ID, 0)
	assertEmailDeliveryCountE2E(t, ctx, pool, []string{user.Email, recipient.Email}, 0)

	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER "%s" ON email_deliveries`, deliveryTriggerName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION "%s"()`, deliveryFunctionName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}

	// Hold the same parent row lock finalization uses, change the state, and
	// prove a stale sender comment blocks until the transition commits. It must
	// then re-read finalizing and reject without inserting anything.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT id FROM documents WHERE id = $1 FOR UPDATE", doc.ID); err != nil { //nolint:rawsql
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE documents SET status = 'finalizing', completion_effective_at = now() WHERE id = $1", doc.ID); err != nil { //nolint:rawsql
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	commentResult := make(chan error, 1)
	go func() {
		_, commentErr := engine.SenderComment(ctx, org.ID, doc.ID, user.ID, user.Name, "stale sender body")
		commentResult <- commentErr
	}()
	select {
	case err := <-commentResult:
		_ = tx.Rollback(ctx)
		t.Fatalf("sender comment bypassed the finalization row lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-commentResult:
		if !errors.Is(err, ErrDocumentNotCommentable) {
			t.Fatalf("stale sender comment returned %v, want ErrDocumentNotCommentable", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender comment did not unblock after finalization commit")
	}
	assertCommentCountE2E(t, ctx, pool, doc.ID, 0)
}

// Simulate the lookup-to-lock window directly: the request authenticates and
// constructs evidence from epoch one, then a resend advances sent_at before the
// mutation acquires its document lock. The authoritative locked-row check must
// reject without changing recipient state or emitting a viewed event.
func TestMarkViewedRejectsPreResendNoticeEpochE2E(t *testing.T) {
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
	engine := &Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool)}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "notice epoch " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@epoch.test", Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "notice epoch", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@recipient.epoch.test", Name: "Recipient", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	epochOne := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `UPDATE documents SET status = 'sent', sent_at = $2 WHERE id = $1`, doc.ID, epochOne); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	doc, err = q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	rc := &RecipientContext{
		Document: doc,
		Recipient: &generated.GetRecipientByTokenHashRow{
			ID: recipient.ID, DocumentID: doc.ID, Role: recipient.Role, Status: recipient.Status,
			Email: recipient.Email, Name: recipient.Name, DocOrgID: org.ID,
		},
	}
	evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, rc)}

	if _, err := pool.Exec(ctx, `UPDATE documents SET sent_at = $2 WHERE id = $1`, doc.ID, epochOne.Add(time.Minute)); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := engine.MarkViewed(ctx, rc, evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatalf("MarkViewed() stale epoch error = %v, want ErrInvalidNoticeEvidence", err)
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if freshRecipient.Status != "pending" {
		t.Fatalf("stale epoch mutated recipient status to %q", freshRecipient.Status)
	}
	var viewedEvents int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'document.viewed'`, doc.ID,
	).Scan(&viewedEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if viewedEvents != 0 {
		t.Fatalf("stale epoch emitted %d viewed events", viewedEvents)
	}
}

func assertCommentCountE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, documentID uuid.UUID, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM document_comments WHERE document_id = $1", documentID).Scan(&count); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("comment rows = %d, want %d", count, want)
	}
}

func assertEmailDeliveryCountE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, recipients []string, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM email_deliveries WHERE to_email = ANY($1::text[])", recipients).Scan(&count); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("email delivery rows = %d, want %d", count, want)
	}
}

func assertCommentEventCountE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, documentID uuid.UUID, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'document.comment_posted'", documentID).Scan(&count); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("comment audit events = %d, want %d", count, want)
	}
}
