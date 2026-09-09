// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build demo

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
)

// TestChangeRequestFlow exercises the negotiation loop end to end: send -> signer
// requests changes -> document pauses -> sender revises (back to draft) -> re-send
// -> signer signs -> completed.
func TestChangeRequestFlow(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	s3ep := os.Getenv("HASH_E2E_S3_ENDPOINT")
	gote := os.Getenv("HASH_E2E_GOTENBERG_URL")
	if dsn == "" || s3ep == "" || gote == "" {
		t.Skip("set HASH_E2E_DB_URL, HASH_E2E_S3_ENDPOINT, HASH_E2E_GOTENBERG_URL to run")
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
	auditLog := audit.New(q, pool)

	store, err := storage.New(ctx, e2eStorageConfig(t, "hash-e2e"))
	dmust(t, err, "storage")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	dmust(t, err, "ed25519")
	signer, err := sign.NewCertSigner(base64.StdEncoding.EncodeToString(priv.Seed()))
	dmust(t, err, "cert signer")
	gotenberg := render.NewGotenberg(gote)

	sendEng := &send.Engine{Pool: pool, Queries: q, Audit: auditLog, Mailer: dispatch.NoopMailer{}, PublicURL: "http://localhost:8080", OrgName: "Bright Interaction"}
	signEng := &sign.Engine{Pool: pool, Queries: q, Storage: store, PDF: gotenberg, Audit: auditLog, Signer: signer, OrgName: "Bright Interaction", BaseURL: "http://localhost:8080"}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Changes Test AB", Plan: "pro"})
	dmust(t, err, "org")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: demoEmail(), Name: "Sender", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	dmust(t, err, "user")

	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "h", Type: blocks.TypeHeading, Attrs: map[string]any{"level": 1}, Text: "Avtal"},
		{ID: "p", Type: blocks.TypeParagraph, Text: "Pris {{price}} kr."},
		{ID: "sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer", "label": "Underskrift"}},
	}}
	blocksJSON, _ := json.Marshal(tree)
	varsJSON, _ := json.Marshal(map[string]string{"price": "15 000"})
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "Avtal", BlocksJson: blocksJSON, VariablesJson: varsJSON, SenderID: user.ID})
	dmust(t, err, "doc")

	mkRecipient := func() *generated.Recipient {
		_, hash, herr := auth.MintMagicToken()
		dmust(t, herr, "token")
		rec, rerr := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: "client@example.com", Name: "Client", OrderIndex: 0, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true}, Locale: "sv"})
		dmust(t, rerr, "recipient")
		return rec
	}
	rec := mkRecipient()
	_, err = sendEng.Send(ctx, send.Actor{UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "test", LawfulBasis: "contract"}, doc.ID)
	dmust(t, err, "send")
	sentRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: org.ID})
	dmust(t, err, "load sent recipient")
	oldTokenHash := append([]byte(nil), sentRec.MagicTokenHash...)

	// Signer requests changes instead of signing.
	rc, err := signEng.LookupByToken(ctx, oldTokenHash)
	dmust(t, err, "lookup")
	notice := testArticle13NoticeEvidence(t, rc)
	dmust(t, signEng.RequestChanges(ctx, rc, sign.ChangeRequestInput{
		Message: "Sänk priset och lägg till en garanti.", BlockID: "p", Quote: "Pris {{price}} kr.", Proposed: "Pris 12 000 kr.",
		IP: "203.0.113.5", UserAgent: "test", Notice: notice,
	}), "request changes")

	paused, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	dmust(t, err, "reload paused")
	if paused.Status != "changes_requested" {
		t.Fatalf("expected changes_requested, got %s", paused.Status)
	}
	crs, err := q.ListChangeRequests(ctx, doc.ID)
	dmust(t, err, "list crs")
	if len(crs) != 1 || crs[0].Status != "open" {
		t.Fatalf("expected 1 open change request, got %+v", crs)
	}
	// Signing must be refused while paused.
	if _, serr := signEng.Sign(ctx, rc, sign.SignInput{
		TypedName: "Client", Font: "Caveat", IP: "203.0.113.5", UserAgent: "test", Notice: notice,
	}); serr == nil {
		t.Fatal("signing should be refused while changes are requested")
	}

	// Auto-apply on approve: with the org in auto_apply mode, approving swaps
	// the marked text for the proposed text in the block.
	_, err = q.SetOrgChangeApprovalMode(ctx, generated.SetOrgChangeApprovalModeParams{ID: org.ID, ChangeApprovalMode: "auto_apply"})
	dmust(t, err, "set auto_apply")
	_, err = signEng.ResolveChange(ctx, org.ID, doc.ID, crs[0].ID, true)
	dmust(t, err, "approve change")
	applied, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	dmust(t, err, "reload applied")
	if !strings.Contains(string(applied.BlocksJson), "Pris 12 000 kr.") {
		t.Fatalf("expected auto-applied proposed text in blocks, got %s", string(applied.BlocksJson))
	}

	// Sender revises -> back to draft, requests resolved, recipient reset.
	revised, err := signEng.Revise(ctx, org.ID, doc.ID)
	dmust(t, err, "revise")
	if revised.Status != "draft" {
		t.Fatalf("expected draft after revise, got %s", revised.Status)
	}
	crs2, err := q.ListChangeRequests(ctx, doc.ID)
	dmust(t, err, "list crs2")
	if crs2[0].Status != "resolved" {
		t.Fatalf("expected resolved change request, got %s", crs2[0].Status)
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: org.ID})
	dmust(t, err, "fresh rec")
	if freshRec.Status != "pending" {
		t.Fatalf("expected recipient reset to pending, got %s", freshRec.Status)
	}
	if !freshRec.MagicTokenExpiresAt.Valid || freshRec.MagicTokenExpiresAt.Time.After(time.Now()) {
		t.Fatalf("expected revise to expire the old ceremony token, got %+v", freshRec.MagicTokenExpiresAt)
	}
	if _, staleErr := signEng.LookupByToken(ctx, oldTokenHash); staleErr == nil {
		t.Fatal("old signer token still reads the reopened draft")
	}

	// Re-send the revised draft and sign to completion.
	_, err = sendEng.Send(ctx, send.Actor{UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "test", LawfulBasis: "contract"}, doc.ID)
	dmust(t, err, "re-send")
	resentRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: org.ID})
	dmust(t, err, "load re-sent recipient")
	if string(resentRec.MagicTokenHash) == string(oldTokenHash) {
		t.Fatal("re-send did not mint a fresh ceremony credential")
	}
	rc2, err := signEng.LookupByToken(ctx, resentRec.MagicTokenHash)
	dmust(t, err, "lookup2")
	res, err := signEng.Sign(ctx, rc2, sign.SignInput{
		TypedName: "Client", Font: "Caveat", IP: "203.0.113.5", UserAgent: "test",
		Notice: testArticle13NoticeEvidence(t, rc2),
	})
	dmust(t, err, "sign")
	if !res.Completed {
		t.Fatalf("expected completed after re-sign, got %+v", res)
	}
	t.Log("change-request loop OK: send -> request -> revise -> re-send -> sign -> completed")
}
