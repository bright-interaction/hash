// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build demo

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
)

// TestCommentThread verifies the shared comment thread: both the signer and the
// sender can post, and both reads return the full ordered thread.
func TestCommentThread(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	dmust(t, err, "parse dsn")
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	dmust(t, mdb.RunMigrations(migConn), "migrations")
	_ = migConn.Close()
	pool, err := pgxpool.New(ctx, dsn)
	dmust(t, err, "pool")
	defer pool.Close()
	q := generated.New(pool)
	signEng := &sign.Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.NoopMailer{}, OrgName: "Bright Interaction", BaseURL: "http://localhost:8080"}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Comment Test AB", Plan: "pro"})
	dmust(t, err, "org")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: demoEmail(), Name: "Sender", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	dmust(t, err, "user")
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "Avtal", BlocksJson: []byte(`{"version":1,"blocks":[{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`), VariablesJson: []byte(`{}`), SenderID: user.ID})
	dmust(t, err, "doc")
	_, hash, err := auth.MintMagicToken()
	dmust(t, err, "token")
	rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: "client@example.com", Name: "Client", OrderIndex: 0, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true}, Locale: "sv"})
	dmust(t, err, "recipient")
	sendEng := &send.Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.NoopMailer{}, PublicURL: "http://localhost:8080", OrgName: "Bright Interaction"}
	result, err := sendEng.Send(ctx, send.Actor{UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "demo", LawfulBasis: "contract"}, doc.ID)
	dmust(t, err, "activate comment ceremony through durable send")
	if result.Status != "sent" {
		t.Fatalf("send status = %q, want sent", result.Status)
	}

	// Signer asks a question.
	rc, err := signEng.LookupByRecipientID(ctx, rec.ID, org.ID)
	dmust(t, err, "lookup")
	_, err = signEng.SignerComment(ctx, rc, "Kan vi flytta leveransdatumet?", sign.ParticipantResponseEvidence{
		Notice: testArticle13NoticeEvidence(t, rc),
	})
	dmust(t, err, "signer comment")

	// Sender answers.
	_, err = signEng.SenderComment(ctx, org.ID, doc.ID, user.ID, "Sender", "Ja, vi flyttar en vecka.")
	dmust(t, err, "sender comment")

	thread, err := q.ListComments(ctx, doc.ID)
	dmust(t, err, "list comments")
	if len(thread) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(thread))
	}
	if thread[0].AuthorSide != "signer" || thread[1].AuthorSide != "sender" {
		t.Fatalf("unexpected order/sides: %s then %s", thread[0].AuthorSide, thread[1].AuthorSide)
	}

	t.Log("comment thread OK: notice-gated signer + sender posts")
}
