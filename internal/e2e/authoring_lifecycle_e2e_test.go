// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestAuthoringMutationsRejectActiveAndCompletedDocuments(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "authoring lifecycle " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@authoring.test", Name: "Lifecycle Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"sent", "in_progress", "completed"} {
		t.Run(status, func(t *testing.T) {
			doc, rec, field := seedAuthoringDraft(t, ctx, q, org.ID, user.ID)
			doc = sendAuthoringDocumentE2E(t, ctx, pool, q, doc, rec)
			wantSignatures := 0
			if status == "in_progress" || status == "completed" {
				doc = signAuthoringDocumentE2E(t, ctx, pool, q, doc, rec, field)
				wantSignatures = 1
			}
			if status == "completed" {
				doc = completeAuthoringDocumentE2E(t, ctx, pool, q, doc)
			}
			if doc.Status != status {
				t.Fatalf("fixture status = %q, want %q", doc.Status, status)
			}

			if _, err := q.CreateRecipient(ctx, recipientParams(doc.ID)); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("CreateRecipient on %s: err=%v, want pgx.ErrNoRows", status, err)
			}
			if _, err := q.UpdateRecipient(ctx, generated.UpdateRecipientParams{
				ID: rec.ID, DocumentID: doc.ID, Email: "changed@example.test", Name: rec.Name,
				Role: rec.Role, OrderIndex: rec.OrderIndex, Locale: rec.Locale,
			}); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("UpdateRecipient on %s: err=%v, want pgx.ErrNoRows", status, err)
			}
			if _, err := q.CreateDraftField(ctx, draftFieldParams(doc.ID, rec.ID)); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("CreateDraftField on %s: err=%v, want pgx.ErrNoRows", status, err)
			}
			if _, err := q.DeleteFieldByID(ctx, generated.DeleteFieldByIDParams{ID: field.ID, OrgID: org.ID}); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("DeleteFieldByID on %s: err=%v, want pgx.ErrNoRows", status, err)
			}
			if _, err := q.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: rec.ID, DocumentID: doc.ID}); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("DeleteRecipient on %s: err=%v, want pgx.ErrNoRows", status, err)
			}

			var signatures int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM signatures WHERE document_id = $1", doc.ID).Scan(&signatures); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
			if signatures != wantSignatures {
				t.Fatalf("signature evidence count after rejected %s deletes = %d, want %d", status, signatures, wantSignatures)
			}
			var recipients, fields int
			if err := pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM recipients WHERE id = $1),
				(SELECT count(*) FROM document_fields WHERE id = $2)`, rec.ID, field.ID).Scan(&recipients, &fields); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
			if recipients != 1 || fields != 1 {
				t.Fatalf("authoring evidence after rejected %s deletes: recipients=%d fields=%d, want 1/1", status, recipients, fields)
			}
		})
	}

	t.Run("send lock wins stale delete", func(t *testing.T) {
		doc, rec, field := seedAuthoringDraft(t, ctx, q, org.ID, user.ID)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		txq := q.WithTx(tx)
		if _, err := txq.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
			DocumentID: doc.ID, OrgID: doc.OrgID,
			ActorUserID: pgtype.UUID{Bytes: user.ID, Valid: true},
			ActorEmail:  user.Email, ActorIp: "127.0.0.1", Via: "e2e", Tool: "authoring-lock",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := txq.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
			t.Fatal(err)
		}

		deleteResult := make(chan error, 1)
		go func() {
			_, deleteErr := q.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: rec.ID, DocumentID: doc.ID})
			deleteResult <- deleteErr
		}()
		select {
		case err := <-deleteResult:
			t.Fatalf("delete returned before the send transaction released its document lock: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-deleteResult:
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("stale delete after send commit: err=%v, want pgx.ErrNoRows", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("stale delete did not unblock after send commit")
		}
		rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
			DocumentID: doc.ID, OrgID: doc.OrgID,
		})
		if err != nil || rows != 1 {
			t.Fatalf("mark locked send retention started: rows=%d err=%v", rows, err)
		}
		rows, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
			DocumentID: doc.ID, OrgID: doc.OrgID,
		})
		if err != nil || rows != 1 {
			t.Fatalf("mark locked send retention complete: rows=%d err=%v", rows, err)
		}
		publishTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = publishTx.Rollback(ctx) }()
		_, pending := completeAuthoringSendSealingTxE2E(t, ctx, pool, q, publishTx, doc, rec)
		if err := publishTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		audit.New(q, pool).Publish(pending)
		var recipients, fields int
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM recipients WHERE id = $1),
			(SELECT count(*) FROM document_fields WHERE id = $2)`, rec.ID, field.ID).Scan(&recipients, &fields); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if recipients != 1 || fields != 1 {
			t.Fatalf("authoring rows after stale delete: recipients=%d fields=%d, want 1/1", recipients, fields)
		}
	})
}

func TestAuthoringMutationsAllowDraftDocuments(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "draft authoring " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@authoring.test", Name: "Draft Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := q.CreateRecipient(ctx, recipientParams(doc.ID))
	if err != nil {
		t.Fatalf("CreateRecipient draft: %v", err)
	}
	if _, err := q.UpdateRecipient(ctx, generated.UpdateRecipientParams{
		ID: rec.ID, DocumentID: doc.ID, Email: "updated@example.test", Name: rec.Name,
		Role: rec.Role, OrderIndex: rec.OrderIndex, Locale: rec.Locale,
	}); err != nil {
		t.Fatalf("UpdateRecipient draft: %v", err)
	}
	field, err := q.CreateDraftField(ctx, draftFieldParams(doc.ID, rec.ID))
	if err != nil {
		t.Fatalf("CreateDraftField draft: %v", err)
	}
	if _, err := q.DeleteFieldByID(ctx, generated.DeleteFieldByIDParams{ID: field.ID, OrgID: org.ID}); err != nil {
		t.Fatalf("DeleteFieldByID draft: %v", err)
	}
	if _, err := q.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: rec.ID, DocumentID: doc.ID}); err != nil {
		t.Fatalf("DeleteRecipient draft: %v", err)
	}
}

func TestLegacyPDFTemplateClonePinsExactVersionDuringSealing(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "legacy template pin " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@version-pin.test", Name: "Version Pin Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	digest[0] = 1
	legacyTemplate, err := q.CreatePDFTemplate(ctx, generated.CreatePDFTemplateParams{
		OrgID: org.ID, Name: "legacy PDF", PdfStorageKey: pgtype.Text{String: "org/legacy/template.pdf", Valid: true},
		PdfSha256: digest, EvidenceVersionPinRequired: false,
		PageCount: pgtype.Int4{Int32: 1, Valid: true}, FieldsJson: json.RawMessage(`[]`), CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacyTemplate.EvidenceVersionPinRequired || legacyTemplate.PdfStorageVersionID.Valid {
		t.Fatal("legacy template was not stored with an explicit nullable pin state")
	}
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID: org.ID, TemplateID: pgtype.UUID{Bytes: legacyTemplate.ID, Valid: true}, Name: "legacy clone",
		PdfStorageKey: legacyTemplate.PdfStorageKey, PdfSha256: legacyTemplate.PdfSha256,
		PdfStorageVersionID:         legacyTemplate.PdfStorageVersionID,
		EvidenceVersionPinsRequired: legacyTemplate.EvidenceVersionPinRequired, SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.EvidenceVersionPinsRequired || doc.PdfStorageVersionID.Valid {
		t.Fatal("legacy template clone unexpectedly required a missing VersionId while still draft")
	}
	if _, err := q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	pinned, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: "resolved-source-version-1", Valid: true}, ID: doc.ID, OrgID: org.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pinned.EvidenceVersionPinsRequired || !pinned.PdfStorageVersionID.Valid || pinned.PdfStorageVersionID.String != "resolved-source-version-1" {
		t.Fatalf("sealing pin = required %t, VersionId %#v", pinned.EvidenceVersionPinsRequired, pinned.PdfStorageVersionID)
	}
	if _, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: "conflicting-source-version", Valid: true}, ID: doc.ID, OrgID: org.ID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("conflicting VersionId replacement = %v, want pgx.ErrNoRows", err)
	}
}

func TestLegacyActiveEvidencePinsBeforeFinalizationAreOneWay(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "legacy active pin " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@version-pin.test", Name: "Legacy Active Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	digest[0] = 2
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID: org.ID, Name: "pre-migration active PDF",
		PdfStorageKey: pgtype.Text{String: "org/legacy/active-source.pdf", Valid: true}, PdfSha256: digest,
		EvidenceVersionPinsRequired: false, SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, recipientParams(doc.ID))
	if err != nil {
		t.Fatal(err)
	}
	field, err := q.CreateDraftField(ctx, draftFieldParams(doc.ID, recipient.ID))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := q.InsertSignature(ctx, generated.InsertSignatureParams{
		DocumentID: doc.ID, RecipientID: recipient.ID, FieldID: field.ID, Font: "Inter", TypedName: "Legacy Signer",
		ImageStorageKey: "org/legacy/signature.html", ImageSha256: digest,
		ImageVersionID: pgtype.Text{String: "temporary-version", Valid: true}, SignerUa: pgtype.Text{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE signatures
		SET image_version_id = NULL, image_version_pin_required = FALSE
		WHERE id = $1`, signature.ID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	sealingTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealingTx.Rollback(ctx) }()
	sealingQ := q.WithTx(sealingTx)
	if _, err := sealingQ.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: org.ID,
		ActorUserID: pgtype.UUID{Bytes: user.ID, Valid: true},
		ActorEmail:  user.Email, ActorIp: "127.0.0.1", Via: "e2e", Tool: "legacy-active-pin",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sealingQ.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if err := sealingTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: "temporary-active-source-version", Valid: true}, ID: doc.ID, OrgID: org.ID,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: doc.ID, OrgID: org.ID})
	if err != nil || rows != 1 {
		t.Fatalf("mark legacy fixture send retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: doc.ID, OrgID: org.ID})
	if err != nil || rows != 1 {
		t.Fatalf("mark legacy fixture send retention complete: rows=%d err=%v", rows, err)
	}
	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	doc, pendingSent := completeAuthoringSendSealingTxE2E(t, ctx, pool, q, publishTx, doc, recipient)
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pendingSent)

	signTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signTx.Rollback(ctx) }()
	signQ := q.WithTx(signTx)
	if _, err := signQ.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	if err := signQ.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: recipient.ID, DocumentID: doc.ID, Status: "signed", DeclinedReason: pgtype.Text{},
	}); err != nil {
		t.Fatal(err)
	}
	doc, err = signQ.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{ID: doc.ID, OrgID: org.ID, Status: "in_progress"})
	if err != nil {
		t.Fatal(err)
	}
	pendingSigned, err := audit.New(q, pool).LogTx(ctx, signTx, audit.Entry{
		OrgID: org.ID, DocumentID: &doc.ID, RecipientID: &recipient.ID,
		Kind: audit.KindDocumentSigned, Payload: map[string]any{"fixture": "legacy-active-pin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := signTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pendingSigned)
	if _, err := pool.Exec(ctx, `UPDATE documents
		SET pdf_storage_version_id = NULL, evidence_version_pins_required = FALSE
		WHERE id = $1`, doc.ID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}

	const sourceVersion = "resolved-active-source-version"
	pinnedDoc, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: sourceVersion, Valid: true}, ID: doc.ID, OrgID: org.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pinnedDoc.EvidenceVersionPinsRequired || pinnedDoc.PdfStorageVersionID.String != sourceVersion {
		t.Fatalf("active document source pin = %#v", pinnedDoc.PdfStorageVersionID)
	}
	claimed, err := q.BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
		RetentionYears: int32(article13.RetentionYearsV1), ID: doc.ID, OrgID: org.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: sourceVersion, Valid: true}, ID: doc.ID, OrgID: org.ID,
	}); err != nil {
		t.Fatalf("exact source pin retry while finalizing: %v", err)
	}
	if _, err := q.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pgtype.Text{String: "conflicting-source-version", Valid: true}, ID: doc.ID, OrgID: org.ID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("active source VersionId replacement = %v, want pgx.ErrNoRows", err)
	}

	const signatureVersion = "resolved-legacy-signature-version"
	pinnedSignature, err := q.PinLegacySignatureVersion(ctx, generated.PinLegacySignatureVersionParams{
		ImageVersionID: pgtype.Text{String: signatureVersion, Valid: true}, ID: signature.ID, DocumentID: doc.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pinnedSignature.ImageVersionPinRequired || pinnedSignature.ImageVersionID.String != signatureVersion {
		t.Fatalf("legacy signature pin = %#v", pinnedSignature.ImageVersionID)
	}
	if _, err := q.PinLegacySignatureVersion(ctx, generated.PinLegacySignatureVersionParams{
		ImageVersionID: pgtype.Text{String: "conflicting-signature-version", Valid: true}, ID: signature.ID, DocumentID: doc.ID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("signature VersionId replacement = %v, want pgx.ErrNoRows", err)
	}

	artifactDir := "org/" + org.ID.String() + "/documents/" + doc.ID.String() + "/"
	digestHex := hex.EncodeToString(digest)
	if _, err := pool.Exec(ctx, `INSERT INTO document_finalization_intents (
		document_id, org_id, mode, completion_effective_at, retain_until,
		final_pdf_key, final_pdf_sha256,
		audit_cert_key, audit_cert_sha256,
		audit_payload_key, audit_payload_sha256,
		audit_signature_key, audit_signature_sha256,
		evidence_version_pins_required
	) VALUES ($1, $2, 'signature', $3, $4, $5, $6, $7, $6, $8, $6, $9, $6, FALSE)`,
		doc.ID, org.ID, claimed.CompletionEffectiveAt, claimed.FinalizationRetainUntil,
		artifactDir+"final-"+digestHex+".pdf", digest, artifactDir+"audit-"+digestHex+".pdf",
		artifactDir+"audit-payload-"+digestHex+".txt", artifactDir+"audit-signature-"+digestHex+".txt"); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	intentVersions := []string{"version-final", "version-cert", "version-payload", "version-signature"}
	pinnedIntent, err := q.PinLegacyDocumentFinalizationIntentVersions(ctx, generated.PinLegacyDocumentFinalizationIntentVersionsParams{
		FinalPdfVersionID:       pgtype.Text{String: intentVersions[0], Valid: true},
		AuditCertVersionID:      pgtype.Text{String: intentVersions[1], Valid: true},
		AuditPayloadVersionID:   pgtype.Text{String: intentVersions[2], Valid: true},
		AuditSignatureVersionID: pgtype.Text{String: intentVersions[3], Valid: true},
		DocumentID:              doc.ID, OrgID: org.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pinnedIntent.EvidenceVersionPinsRequired ||
		pinnedIntent.FinalPdfVersionID.String != intentVersions[0] ||
		pinnedIntent.AuditCertVersionID.String != intentVersions[1] ||
		pinnedIntent.AuditPayloadVersionID.String != intentVersions[2] ||
		pinnedIntent.AuditSignatureVersionID.String != intentVersions[3] {
		t.Fatal("legacy finalization intent did not pin all artifact VersionIds atomically")
	}
	if _, err := q.PinLegacyDocumentFinalizationIntentVersions(ctx, generated.PinLegacyDocumentFinalizationIntentVersionsParams{
		FinalPdfVersionID:       pgtype.Text{String: "conflicting-final", Valid: true},
		AuditCertVersionID:      pgtype.Text{String: intentVersions[1], Valid: true},
		AuditPayloadVersionID:   pgtype.Text{String: intentVersions[2], Valid: true},
		AuditSignatureVersionID: pgtype.Text{String: intentVersions[3], Valid: true},
		DocumentID:              doc.ID, OrgID: org.ID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("finalization intent VersionId replacement = %v, want pgx.ErrNoRows", err)
	}
}

func seedAuthoringDraft(t *testing.T, ctx context.Context, q *generated.Queries, orgID, userID uuid.UUID) (*generated.Document, *generated.Recipient, *generated.DocumentField) {
	t.Helper()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: orgID, Name: "legal record", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: userID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := q.CreateRecipient(ctx, recipientParams(doc.ID))
	if err != nil {
		t.Fatal(err)
	}
	field, err := q.CreateDraftField(ctx, draftFieldParams(doc.ID, rec.ID))
	if err != nil {
		t.Fatal(err)
	}
	return doc, rec, field
}

func prepareAuthoringSendSealingE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, doc *generated.Document) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	txq := q.WithTx(tx)
	if _, err := txq.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
		ActorUserID: pgtype.UUID{Bytes: doc.SenderID, Valid: true},
		ActorEmail:  "sender@authoring.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "authoring-lifecycle",
	}); err != nil {
		t.Fatal(err)
	}
	sealing, err := txq.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	if !sealing.EvidenceVersionPinsRequired {
		t.Fatal("new authoring fixture did not retain its exact-version policy during sealing")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark send retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark send retention complete: rows=%d err=%v", rows, err)
	}
}

func completeAuthoringSendSealingTxE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	tx pgx.Tx,
	doc *generated.Document,
	recipient *generated.Recipient,
) (*generated.Document, audit.PendingEvent) {
	t.Helper()
	txq := q.WithTx(tx)
	sent, err := txq.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := txq.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: recipient.ID, DocumentID: doc.ID})
	if err != nil || rows != 1 {
		t.Fatalf("mark fixture recipient sent: rows=%d err=%v", rows, err)
	}
	canonicalEpoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, tx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentSent,
		Payload: map[string]any{
			article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1,
			article13.AuditRequiredNoticeSentAtKey: canonicalEpoch,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = txq.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		t.Fatalf("delete published send intent: rows=%d err=%v", rows, err)
	}
	return sent, pending
}

func sendAuthoringDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
	recipient *generated.Recipient,
) *generated.Document {
	t.Helper()
	prepareAuthoringSendSealingE2E(t, ctx, pool, q, doc)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sent, pending := completeAuthoringSendSealingTxE2E(t, ctx, pool, q, tx, doc, recipient)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return sent
}

func signAuthoringDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
	recipient *generated.Recipient,
	field *generated.DocumentField,
) *generated.Document {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	txq := q.WithTx(tx)
	locked, err := txq.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	if locked.Status != "sent" {
		t.Fatalf("document status before fixture signature = %q, want sent", locked.Status)
	}
	digest := make([]byte, 32)
	digest[0] = 1
	if _, err := txq.InsertSignature(ctx, generated.InsertSignatureParams{
		DocumentID: doc.ID, RecipientID: recipient.ID, FieldID: field.ID, Font: "Inter",
		TypedName:       "Synthetic Evidence",
		ImageStorageKey: "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/signatures/" + recipient.ID.String() + ".html",
		ImageSha256:     digest,
		ImageVersionID:  pgtype.Text{String: "authoring-signature-version-1", Valid: true},
		SignerUa:        pgtype.Text{String: "authoring-e2e", Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := txq.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: recipient.ID, DocumentID: doc.ID, Status: "signed", DeclinedReason: pgtype.Text{},
	}); err != nil {
		t.Fatal(err)
	}
	inProgress, err := txq.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{ID: doc.ID, OrgID: doc.OrgID, Status: "in_progress"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, tx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &recipient.ID,
		Kind: audit.KindDocumentSigned, Payload: map[string]any{"fixture": "authoring-lifecycle"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return inProgress
}

func completeAuthoringDocumentE2E(
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
		t.Fatalf("incomplete finalization commitment: %+v", claimed)
	}
	digest := make([]byte, 32)
	digest[0] = 2
	digestHex := hex.EncodeToString(digest)
	artifactDir := "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/"
	intent, err := q.CreateDocumentFinalizationIntent(ctx, generated.CreateDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Mode: "signature",
		CompletionEffectiveAt: claimed.CompletionEffectiveAt, RetainUntil: claimed.FinalizationRetainUntil,
		FinalPdfKey: artifactDir + "final-" + digestHex + ".pdf", FinalPdfSha256: digest,
		FinalPdfVersionID: pgtype.Text{String: "authoring-final-version-1", Valid: true},
		AuditCertKey:      artifactDir + "audit-" + digestHex + ".pdf", AuditCertSha256: digest,
		AuditCertVersionID: pgtype.Text{String: "authoring-cert-version-1", Valid: true},
		AuditPayloadKey:    artifactDir + "audit-payload-" + digestHex + ".txt", AuditPayloadSha256: digest,
		AuditPayloadVersionID: pgtype.Text{String: "authoring-payload-version-1", Valid: true},
		AuditSignatureKey:     artifactDir + "audit-signature-" + digestHex + ".txt", AuditSignatureSha256: digest,
		AuditSignatureVersionID: pgtype.Text{String: "authoring-audit-signature-version-1", Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkDocumentFinalizationRetentionStarted(ctx, generated.MarkDocumentFinalizationRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark finalization retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkDocumentFinalizationRetentionComplete(ctx, generated.MarkDocumentFinalizationRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark finalization retention complete: rows=%d err=%v", rows, err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	txq := q.WithTx(tx)
	completed, err := txq.CompleteDocumentFinalization(ctx, generated.CompleteDocumentFinalizationParams{
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
	pending, err := audit.New(q, pool).LogTx(ctx, tx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentCompleted,
		Payload: map[string]any{"fixture": "authoring-lifecycle"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = txq.DeleteDocumentFinalizationIntent(ctx, generated.DeleteDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("delete published finalization intent: rows=%d err=%v", rows, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return completed
}

func recipientParams(documentID uuid.UUID) generated.CreateRecipientParams {
	return generated.CreateRecipientParams{
		DocumentID: documentID, Role: "signer", Email: uuid.NewString() + "@recipient.test", Name: "Recipient",
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		Locale: "en",
	}
}

func draftFieldParams(documentID, recipientID uuid.UUID) generated.CreateDraftFieldParams {
	zero := pgtype.Numeric{Int: big.NewInt(0), Exp: 0, Valid: true}
	return generated.CreateDraftFieldParams{
		DocumentID: documentID, RecipientID: pgtype.UUID{Bytes: recipientID, Valid: true}, Type: "signature", Page: 1,
		XPct: zero, YPct: zero, WPct: zero, HPct: zero, Required: true, OptionsJson: json.RawMessage(`{}`),
	}
}
