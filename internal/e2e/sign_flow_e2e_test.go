//go:build e2e

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

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/blocks"
	mdb "github.com/brightinteraction/hash/internal/db"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/render"
	"github.com/brightinteraction/hash/internal/send"
	"github.com/brightinteraction/hash/internal/sign"
	"github.com/brightinteraction/hash/internal/storage"
)

// TestSendSignStampE2E drives the real send -> sign -> finalize loop against a
// live Postgres + MinIO + Gotenberg and asserts a completed document with a
// stored, downloadable final PDF + audit certificate. It is the programmatic
// twin of the browser flow (Playwright UI smoke is a follow-up).
//
// Skips unless HASH_E2E_* env is set; the hash-ci `e2e` job provides the
// service containers.
func TestSendSignStampE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	s3ep := os.Getenv("HASH_E2E_S3_ENDPOINT")
	gote := os.Getenv("HASH_E2E_GOTENBERG_URL")
	if dsn == "" || s3ep == "" || gote == "" {
		t.Skip("set HASH_E2E_DB_URL, HASH_E2E_S3_ENDPOINT, HASH_E2E_GOTENBERG_URL to run")
	}
	ctx := context.Background()

	// Migrations (goose, via a stdlib *sql.DB like the server does).
	cfg, err := pgxpool.ParseConfig(dsn)
	must(t, err, "parse dsn")
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	must(t, mdb.RunMigrations(migConn), "run migrations")
	_ = migConn.Close()

	pool, err := pgxpool.New(ctx, dsn)
	must(t, err, "pool")
	defer pool.Close()
	q := generated.New(pool)
	auditLog := audit.New(q, pool)

	store, err := storage.New(ctx, storage.Config{
		Endpoint:  s3ep,
		Region:    "eu-central-1",
		Bucket:    "hash-e2e",
		AccessKey: os.Getenv("HASH_E2E_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("HASH_E2E_S3_SECRET_KEY"),
		UseSSL:    false,
	})
	must(t, err, "storage init")

	// Ephemeral ed25519 audit-cert signer (deterministic verification isn't
	// asserted here; we only need finalize to produce a signed cert).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err, "generate ed25519 key")
	signer, err := sign.NewCertSigner(base64.StdEncoding.EncodeToString(priv.Seed()))
	must(t, err, "cert signer")

	gotenberg := render.NewGotenberg(gote)

	sendEng := &send.Engine{
		Pool: pool, Queries: q, Audit: auditLog, Mailer: dispatch.NoopMailer{},
		PublicURL: "http://localhost:8080", OrgName: "E2E",
	}
	signEng := &sign.Engine{
		Pool: pool, Queries: q, Storage: store, PDF: gotenberg, Audit: auditLog,
		Signer: signer, OrgName: "E2E", BaseURL: "http://localhost:8080",
	}

	// Seed org + owner (the org bootstrap user; "owner" is the top RBAC role
	// and can send). Role must satisfy the users.role CHECK from migration
	// 00001: one of ('owner','sender','viewer'). "admin" is not valid.
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "E2E Org", Plan: "pro"})
	must(t, err, "create org")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uniqueEmail(), Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	must(t, err, "create user")

	// Block document with one signer signature field.
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p1", Type: blocks.TypeParagraph, Text: "This NDA is between E2E Org and the counterparty."},
		{ID: "sig1", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	blocksJSON, err := json.Marshal(tree)
	must(t, err, "marshal block tree")
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "E2E NDA", BlocksJson: blocksJSON,
		VariablesJson: json.RawMessage("{}"), SenderID: user.ID,
	})
	must(t, err, "create document")

	// Signer recipient with an initial magic token (Send re-mints with expiry).
	_, hash, err := auth.MintMagicToken()
	must(t, err, "mint magic token")
	rec, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uniqueEmail(), Name: "Jane Signer",
		OrderIndex: 0, MagicTokenHash: hash,
		MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true},
		Locale:              "sv",
	})
	must(t, err, "create recipient")

	// Send (draft -> sent).
	sendRes, err := sendEng.Send(ctx, send.Actor{
		UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "worker",
	}, doc.ID)
	must(t, err, "send")
	if sendRes.Status != "sent" {
		t.Fatalf("send status = %q, want sent", sendRes.Status)
	}

	// Sign (resolve the recipient context without the plaintext token, like the
	// QES callback path) -> finalize (only signer -> completed).
	rc, err := signEng.LookupByRecipientID(ctx, rec.ID, org.ID)
	must(t, err, "lookup recipient context")
	signRes, err := signEng.Sign(ctx, rc, sign.SignInput{
		TypedName: "Jane Signer", Font: "Caveat", IP: "127.0.0.1", UserAgent: "e2e",
	})
	must(t, err, "sign")
	if !signRes.Completed {
		t.Fatalf("expected completed after the only signer signed; status=%q", signRes.Status)
	}
	if signRes.FinalPDFKey == "" {
		t.Fatal("expected a final PDF key")
	}

	// The stamped final PDF is stored and is a real PDF.
	pdfBytes, err := store.Get(ctx, signRes.FinalPDFKey)
	must(t, err, "fetch final pdf")
	if len(pdfBytes) < 1000 || !strings.HasPrefix(string(pdfBytes), "%PDF-") {
		t.Fatalf("final pdf looks wrong: %d bytes, prefix %q", len(pdfBytes), safePrefix(pdfBytes))
	}

	// Document is completed with both artefact keys persisted.
	got, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	must(t, err, "reload document")
	if got.Status != "completed" {
		t.Fatalf("document status = %q, want completed", got.Status)
	}
	if !got.FinalPdfKey.Valid || !got.AuditCertKey.Valid {
		t.Fatalf("final/cert keys not persisted: final=%v cert=%v", got.FinalPdfKey.Valid, got.AuditCertKey.Valid)
	}
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func uniqueEmail() string { return uuid.NewString() + "@e2e.example" }

func safePrefix(b []byte) string {
	if len(b) > 8 {
		b = b[:8]
	}
	return string(b)
}
