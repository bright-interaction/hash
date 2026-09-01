// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

func TestWebhookOutboxReconcilesCrashWindowAndLeasesExactlyOnce(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migConn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migConn.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{
		Name: "webhook outbox " + uuid.NewString(), Plan: "pro",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpointID := uuid.New()
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	keys, err := webhooksecret.NewKeyringHex(hex.EncodeToString(keyBytes), "")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := webhooksecret.Mint()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := keys.SealNew(org.ID, endpointID, secret)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := q.CreateWebhookEndpoint(ctx, generated.CreateWebhookEndpointParams{
		ID: endpointID, OrgID: org.ID, Url: "https://example.test/events", SecretRef: "test",
		SecretCiphertext: ciphertext, EventsSubscribed: []string{audit.KindDocumentCreated},
	})
	if err != nil {
		t.Fatal(err)
	}

	eventID, err := audit.New(q, pool).Log(ctx, audit.Entry{
		OrgID: org.ID, Kind: audit.KindDocumentCreated,
		Payload: map[string]any{"source": "reconciliation-test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := q.ReconcileMissingWebhookDeliveries(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 1 {
		t.Fatalf("first reconciliation inserted %d rows, want 1", inserted)
	}
	inserted, err = q.ReconcileMissingWebhookDeliveries(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 0 {
		t.Fatalf("idempotent reconciliation inserted %d rows, want 0", inserted)
	}

	claimed, err := q.ClaimDueWebhookDeliveries(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].EndpointID != endpoint.ID || claimed[0].EventID != eventID {
		t.Fatalf("first claim = %+v, want endpoint/event %s/%s", claimed, endpoint.ID, eventID)
	}
	claimedAgain, err := q.ClaimDueWebhookDeliveries(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimedAgain) != 0 {
		t.Fatalf("leased delivery was claimed concurrently: %+v", claimedAgain)
	}

	// The unique endpoint/event key also makes the low-latency audit hook safe
	// to race the reconciliation worker.
	duplicate, err := q.EnqueueWebhookDelivery(ctx, generated.EnqueueWebhookDeliveryParams{
		EndpointID: endpoint.ID, EventID: eventID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != claimed[0].ID {
		t.Fatalf("idempotent enqueue returned a different delivery %s, want %s", duplicate.ID, claimed[0].ID)
	}
}

func TestAuditSubjectIDsSurviveLiveRowDeletion(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migConn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migConn.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "audit subject " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@audit.test", Name: "Audit User", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "deletable draft", BlocksJson: []byte(`{"version":1,"blocks":[]}`),
		VariablesJson: []byte(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, recipientParams(doc.ID))
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := audit.New(q, pool).Log(ctx, audit.Entry{
		OrgID: org.ID, DocumentID: &doc.ID, RecipientID: &recipient.ID,
		ActorUserID: &user.ID, Kind: audit.KindDocumentUpdated,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: recipient.ID, DocumentID: doc.ID}); err != nil {
		t.Fatal(err)
	}
	row, err := q.GetEventByID(ctx, eventID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.RecipientID.Valid || uuid.UUID(row.RecipientID.Bytes) != recipient.ID {
		t.Fatalf("hash-bound recipient id mutated after deletion: %+v", row.RecipientID)
	}
	outbound, err := dispatch.LoadEvent(ctx, q, eventID)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Document["id"] != doc.ID.String() || outbound.Recipient["id"] != recipient.ID.String() {
		t.Fatalf("outbound correlation ids = document:%v recipient:%v", outbound.Document, outbound.Recipient)
	}
}
