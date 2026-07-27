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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/agreement"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
)

// TestDemoArtifacts authors a realistic consulting agreement with {{variable}}
// placeholders + a signature-field placeholder, runs the full send -> sign ->
// finalize flow with dummy data, and writes the produced PDFs (the signed
// document and the ed25519-signed audit certificate) to a folder you can open.
// It is the artifact twin of the browser flow: you see exactly how a placeholder
// becomes real data and how the signature lands in the final document.
//
//	go test -tags demo ./internal/e2e/ -run TestDemoArtifacts -v
//
// Needs the same HASH_E2E_* env as the e2e test (live pg + minio + gotenberg).
func TestDemoArtifacts(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	s3ep := os.Getenv("HASH_E2E_S3_ENDPOINT")
	gote := os.Getenv("HASH_E2E_GOTENBERG_URL")
	if dsn == "" || s3ep == "" || gote == "" {
		t.Skip("set HASH_E2E_DB_URL, HASH_E2E_S3_ENDPOINT, HASH_E2E_GOTENBERG_URL to run")
	}
	outDir := os.Getenv("HASH_DEMO_OUT")
	if outDir == "" {
		home, _ := os.UserHomeDir()
		outDir = filepath.Join(home, "Desktop", "hash-demo")
	}
	dmust(t, os.MkdirAll(outDir, 0o755), "mkdir out")
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	dmust(t, err, "parse dsn")
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	dmust(t, mdb.RunMigrations(migConn), "run migrations")
	_ = migConn.Close()

	pool, err := pgxpool.New(ctx, dsn)
	dmust(t, err, "pool")
	defer pool.Close()
	q := generated.New(pool)
	auditLog := audit.New(q, pool)

	store, err := storage.New(ctx, storage.Config{
		Endpoint: s3ep, Region: "eu-central-1", Bucket: "hash-e2e",
		AccessKey: os.Getenv("HASH_E2E_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("HASH_E2E_S3_SECRET_KEY"),
		UseSSL:    false,
	})
	dmust(t, err, "storage init")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	dmust(t, err, "ed25519")
	signer, err := sign.NewCertSigner(base64.StdEncoding.EncodeToString(priv.Seed()))
	dmust(t, err, "cert signer")
	gotenberg := render.NewGotenberg(gote)

	sendEng := &send.Engine{Pool: pool, Queries: q, Audit: auditLog, Mailer: dispatch.NoopMailer{}, PublicURL: "http://localhost:8080", OrgName: "Bright Interaction"}
	signEng := &sign.Engine{Pool: pool, Queries: q, Storage: store, PDF: gotenberg, Audit: auditLog, Signer: signer, OrgName: "Bright Interaction", BaseURL: "http://localhost:8080"}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Bright Interaction AB", Plan: "pro"})
	dmust(t, err, "org")
	_, err = q.UpsertOrgBranding(ctx, biBranding(org.ID))
	dmust(t, err, "branding")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: demoEmail(), Name: "Tom Isgren", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	dmust(t, err, "user")

	blocksJSON, varsJSON := demoContract()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "Pilotavtal - Demobolaget", BlocksJson: blocksJSON,
		VariablesJson: varsJSON, SenderID: user.ID,
	})
	dmust(t, err, "create doc")
	// Sender dictates the document's default language before sending. Recipients
	// added without an explicit locale inherit this (the cascade lives in the
	// recipient handlers); the whole ceremony then opens in one language.
	_, err = q.SetDocumentDefaultLocale(ctx, generated.SetDocumentDefaultLocaleParams{ID: doc.ID, OrgID: org.ID, DefaultLocale: "sv"})
	dmust(t, err, "set default locale")

	// Both parties e-sign: the provider (role "approver") counter-signs and the
	// client (role "signer") signs. The document completes only after both.
	mkRecipient := func(role, email, name string, order int32) *generated.Recipient {
		_, hash, merr := auth.MintMagicToken()
		dmust(t, merr, "mint token "+role)
		rrec, rerr := q.CreateRecipient(ctx, generated.CreateRecipientParams{
			DocumentID: doc.ID, Role: role, Email: email, Name: name,
			OrderIndex: order, MagicTokenHash: hash,
			MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true},
			Locale:              "sv",
		})
		dmust(t, rerr, "create recipient "+role)
		return rrec
	}
	provRec := mkRecipient("approver", "avtal@brightinteraction.com", "Tom Isgren", 0)
	rec := mkRecipient("signer", "anna@demobolaget.example", "Anna Exempel", 1)

	_, err = sendEng.Send(ctx, send.Actor{UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "demo"}, doc.ID)
	dmust(t, err, "send")

	signOne := func(recID uuid.UUID, who, typed string) *sign.Result {
		rc, lerr := signEng.LookupByRecipientID(ctx, recID, org.ID)
		dmust(t, lerr, "lookup "+who)
		res, serr := signEng.Sign(ctx, rc, sign.SignInput{TypedName: typed, Font: "Caveat", IP: "203.0.113.10", UserAgent: "Mozilla/5.0 (demo signer)"})
		dmust(t, serr, "sign "+who)
		return res
	}
	_ = signOne(provRec.ID, "provider", "Tom Isgren")
	signRes := signOne(rec.ID, "client", "Anna Exempel")
	if !signRes.Completed || signRes.FinalPDFKey == "" {
		t.Fatalf("expected completed with a final pdf; got completed=%v key=%q", signRes.Completed, signRes.FinalPDFKey)
	}

	got, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	dmust(t, err, "reload doc")

	write := func(name, key string) string {
		b, gerr := store.Get(ctx, key)
		dmust(t, gerr, "fetch "+name)
		path := filepath.Join(outDir, name)
		dmust(t, os.WriteFile(path, b, 0o644), "write "+name)
		fmt.Printf("  wrote %s (%d bytes)\n", path, len(b))
		return path
	}
	fmt.Println("DEMO ARTIFACTS:")
	signedPath := write("signed-consulting-agreement.pdf", got.FinalPdfKey.String)
	certPath := ""
	if got.AuditCertKey.Valid {
		certPath = write("audit-certificate.pdf", got.AuditCertKey.String)
	}

	// Open them so the design is immediately visible (best-effort; macOS `open`).
	for _, p := range []string{signedPath, certPath} {
		if p != "" {
			_ = exec.Command("open", p).Run()
		}
	}
	fmt.Printf("\nDocument %q -> status %s. Signer: %s. Open the folder: %s\n", doc.Name, got.Status, rec.Name, outDir)
}

// biBranding is the Bright Interaction customer-facing palette (cyan accent on
// warm white, near-black text, Geist headings + Inter body) from the brand source
// of truth (Hive/concepts/design-principles.md -> brightinteraction.com). Applied
// to the demo org so the rendered document + audit cert carry the brand.
func biBranding(orgID uuid.UUID) generated.UpsertOrgBrandingParams {
	return generated.UpsertOrgBrandingParams{
		OrgID:          orgID,
		PrimaryHex:     "#18181b", // headings (near-black)
		AccentHex:      "#0E7490", // cyan-700, AA on white: links + quote rule
		SurfaceHex:     "#FFFFFF",
		TextHex:        "#18181b",
		MutedHex:       "#52525b",
		LogoUrl:        "",
		LogoAlt:        "Bright Interaction",
		FontHeading:    "Geist",
		FontBody:       "Inter",
		SignatureColor: "#18181b",
	}
}

// demoContract returns the built-in Swedish services agreement starter (the same
// reusable template a tenant seeds from the Templates page), flavoured with the
// demo pilot data so the demo artifacts and the live signer ceremony
// show the real, table-rich document. Single source of truth lives in the
// internal/agreement package.
func demoContract() (blocksJSON, varsJSON []byte) {
	vars := map[string]string{}
	for k, v := range agreement.ServicesAgreement.Variables {
		vars[k] = v
	}
	vars["client"] = "Demobolaget AB"
	vars["client_orgnr"] = "5566XX-XXXX"
	vars["client_signatory"] = "Anna Exempel"
	vars["client_title"] = "VD"
	vars["effective_date"] = time.Now().Format("2006-01-02")
	blocksJSON, _ = json.Marshal(agreement.ServicesAgreement.Tree)
	varsJSON, _ = json.Marshal(vars)
	return blocksJSON, varsJSON
}

// TestDemoLiveSigner seeds a SENT consulting agreement and prints the live signer
// URL, leaving it open so you can complete the ceremony in a browser against a
// locally-running server. It does NOT sign. Run with the same HASH_E2E_* env;
// HASH_DEMO_PUBLIC_URL controls the host in the printed link (default :8080).
//
//	go test -tags demo ./internal/e2e/ -run TestDemoLiveSigner -v
func TestDemoLiveSigner(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_* to run")
	}
	pubURL := os.Getenv("HASH_DEMO_PUBLIC_URL")
	if pubURL == "" {
		pubURL = "http://localhost:8080"
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

	sendEng := &send.Engine{Pool: pool, Queries: q, Audit: audit.New(q, pool), Mailer: dispatch.NoopMailer{}, PublicURL: pubURL, OrgName: "Bright Interaction"}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Bright Interaction AB", Plan: "pro"})
	dmust(t, err, "org")
	_, err = q.UpsertOrgBranding(ctx, biBranding(org.ID))
	dmust(t, err, "branding")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: demoEmail(), Name: "Tom Isgren", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	dmust(t, err, "user")
	blocksJSON, varsJSON := demoContract()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, Name: "Pilotavtal - Demobolaget (LIVE)", BlocksJson: blocksJSON, VariablesJson: varsJSON, SenderID: user.ID})
	dmust(t, err, "doc")
	_, err = q.SetDocumentDefaultLocale(ctx, generated.SetDocumentDefaultLocaleParams{ID: doc.ID, OrgID: org.ID, DefaultLocale: "sv"})
	dmust(t, err, "set default locale")
	// Both parties: provider (approver) + client (signer). The send guard
	// requires a recipient for every signature-field role.
	for _, rcp := range []struct{ role, email, name string }{
		{"approver", "avtal@brightinteraction.com", "Tom Isgren"},
		{"signer", "anna@demobolaget.example", "Anna Exempel"},
	} {
		_, hash, herr := auth.MintMagicToken()
		dmust(t, herr, "token "+rcp.role)
		_, rerr := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: rcp.role, Email: rcp.email, Name: rcp.name, OrderIndex: 0, MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true}, Locale: "sv"})
		dmust(t, rerr, "recipient "+rcp.role)
	}
	res, err := sendEng.Send(ctx, send.Actor{UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "demo"}, doc.ID)
	dmust(t, err, "send")
	clientURL := ""
	for _, l := range res.Links {
		if l.Role == "signer" {
			clientURL = l.URL
		}
	}
	if clientURL == "" {
		t.Fatal("no signer link returned")
	}
	fmt.Printf("\nLIVE SIGNER URL (open in a browser; no login needed):\n  %s\n\nDocument: %q  Signer: Anna Exempel\n", clientURL, doc.Name)
}

func dmust(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func demoEmail() string { return uuid.NewString() + "@demo.example" }
