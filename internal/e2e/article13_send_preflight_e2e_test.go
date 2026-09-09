// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
)

func TestSignerDisclosurePreflightFailsBeforeSendRetentionBoundary(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig)
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{
		Name: "disclosure preflight " + uuid.NewString(), Plan: "pro",
	})
	if err != nil {
		t.Fatal(err)
	}
	validUser, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@preflight.test", Name: "Disclosure Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidContactUser, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: "not-an-email-" + uuid.NewString(), Name: "Invalid Contact Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := &send.Engine{
		Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.NoopMailer{},
		PublicURL: "http://localhost:8080", OrgName: "E2E",
	}

	createDraft := func(t *testing.T, name string, senderID uuid.UUID) *generated.Document {
		t.Helper()
		tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
			{ID: "body", Type: blocks.TypeParagraph, Text: "Disclosure preflight contract."},
			{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
		}}
		blockJSON, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID: org.ID, Name: name, BlocksJson: blockJSON,
			VariablesJson: json.RawMessage(`{}`), SenderID: senderID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateRecipient(ctx, recipientParams(doc.ID)); err != nil {
			t.Fatal(err)
		}
		return doc
	}

	assertDraftWithoutIntent := func(t *testing.T, original *generated.Document, wantConfirmation bool) *generated.Document {
		t.Helper()
		doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: original.ID, OrgID: org.ID})
		if err != nil {
			t.Fatal(err)
		}
		if doc.Status != "draft" {
			t.Fatalf("document status = %q, want draft", doc.Status)
		}
		if doc.EvidenceVersionPinsRequired != original.EvidenceVersionPinsRequired {
			t.Fatalf("evidence-version pin policy changed from %t to %t", original.EvidenceVersionPinsRequired, doc.EvidenceVersionPinsRequired)
		}
		if doc.SentAt.Valid || doc.Article13NoticeEpochAt.Valid {
			t.Fatalf("invalid disclosure allocated a send epoch: sent_at=%#v article13_epoch=%#v", doc.SentAt, doc.Article13NoticeEpochAt)
		}
		if _, err := q.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{
			DocumentID: original.ID, OrgID: org.ID,
		}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("send sealing intent error = %v, want pgx.ErrNoRows", err)
		}
		_, confirmationErr := q.GetDocumentLawfulBasisConfirmation(ctx, generated.GetDocumentLawfulBasisConfirmationParams{
			DocumentID: original.ID, OrgID: org.ID,
		})
		if wantConfirmation && confirmationErr != nil {
			t.Fatalf("expected pre-existing lawful-basis confirmation: %v", confirmationErr)
		}
		if !wantConfirmation && !errors.Is(confirmationErr, pgx.ErrNoRows) {
			t.Fatalf("lawful-basis confirmation escaped rolled-back send: %v", confirmationErr)
		}
		return doc
	}

	for _, test := range []struct {
		name         string
		documentName string
		user         *generated.User
	}{
		{name: "control character document name", documentName: "Agreement\nInjected", user: validUser},
		{name: "overlong rendered document name", documentName: strings.Repeat("x", 1900), user: validUser},
		{name: "invalid frozen controller contact", documentName: "Customer agreement", user: invalidContactUser},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := createDraft(t, test.documentName, test.user.ID)
			_, err := engine.Send(ctx, send.Actor{
				UserID: &test.user.ID, OrgID: org.ID, Email: test.user.Email,
				Via: "test", LawfulBasis: "contract",
			}, doc.ID)
			if !errors.Is(err, send.ErrInvalidSignerDisclosure) {
				t.Fatalf("Send() error = %v, want ErrInvalidSignerDisclosure", err)
			}
			assertDraftWithoutIntent(t, doc, false)
		})
	}

	t.Run("legacy reversible sealing intent is aborted before retention", func(t *testing.T) {
		doc := createDraft(t, "Agreement\nInjected", validUser.ID)
		if _, err := q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
			DocumentID: doc.ID, OrgID: org.ID, LawfulBasis: "contract",
			ConfirmedBy: pgtype.UUID{Bytes: validUser.ID, Valid: true}, Via: "test",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
			DocumentID: doc.ID, OrgID: org.ID,
			ActorUserID: pgtype.UUID{Bytes: validUser.ID, Valid: true},
			ActorEmail:  validUser.Email, ActorIp: "127.0.0.1", Via: "test",
		}); err != nil {
			t.Fatal(err)
		}
		seedCompleteFrozenBrandingFixture(t, ctx, pool, doc.ID)
		if _, err := q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{
			ID: doc.ID, OrgID: org.ID,
		}); err != nil {
			t.Fatal(err)
		}

		_, err := engine.ResumeSendSealing(ctx, doc.ID, org.ID)
		if !errors.Is(err, send.ErrInvalidSignerDisclosure) {
			t.Fatalf("ResumeSendSealing() error = %v, want ErrInvalidSignerDisclosure", err)
		}
		assertDraftWithoutIntent(t, doc, true)
	})
}
