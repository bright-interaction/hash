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

	"github.com/brightinteraction/hash/internal/actiontoken"
	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	mdb "github.com/brightinteraction/hash/internal/db"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/sign"
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
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "Avtal", BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{}`), SenderID: user.ID})
	dmust(t, err, "doc")
	_, hash, err := auth.MintMagicToken()
	dmust(t, err, "token")
	rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: "client@example.com", Name: "Client", OrderIndex: 0, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true}, Locale: "sv"})
	dmust(t, err, "recipient")

	// Signer asks a question.
	rc, err := signEng.LookupByRecipientID(ctx, rec.ID, org.ID)
	dmust(t, err, "lookup")
	_, err = signEng.SignerComment(ctx, rc, "Kan vi flytta leveransdatumet?")
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

	// Email-reply path: a recipient replies by id (as the one-click link does).
	_, err = signEng.CommentAsRecipient(ctx, org.ID, doc.ID, rec.ID, "Tack, det fungerar.")
	dmust(t, err, "comment as recipient")
	thread2, err := q.ListComments(ctx, doc.ID)
	dmust(t, err, "list comments 2")
	if len(thread2) != 3 || thread2[2].AuthorSide != "signer" || thread2[2].RecipientID.Bytes != rec.ID {
		t.Fatalf("expected a 3rd signer comment from the recipient, got %d", len(thread2))
	}

	// If the server secret is present, mint a real reply URL to exercise the
	// live /a/comment endpoint by hand.
	if secret := os.Getenv("HASH_SIGNER_TOKEN_KEY"); secret != "" {
		url := "http://localhost:8080/a/comment?t=" + actiontoken.Mint(secret, actiontoken.Claims{
			Kind: "comment", OrgID: org.ID.String(), DocID: doc.ID.String(), TargetID: rec.ID.String(), Action: "reply",
		}, time.Now(), time.Hour)
		t.Logf("REPLY_URL=%s", url)
	}
	t.Log("comment thread OK: signer + sender + email-reply posts")
}
