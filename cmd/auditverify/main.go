// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command auditverify verifies every organization's complete immutable event
// chain from one repeatable-read snapshot. It is intentionally read-only and
// exits nonzero on any corrupt, forked, legacy-unverifiable, or incomplete
// chain so deployment automation can use it as a hard cutover gate.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
)

const (
	orgPageSize        = 500
	eventPageSize      = 5000
	maxFailedOrgDetail = 100
)

type estateResult struct {
	OK                               bool                 `json:"ok"`
	Complete                         bool                 `json:"complete"`
	OrgsChecked                      int                  `json:"orgs_checked"`
	EventsChecked                    int                  `json:"events_checked"`
	FailedOrgCount                   int                  `json:"failed_org_count"`
	CompletedEvidenceRootsChecked    int64                `json:"completed_evidence_roots_checked"`
	IncompleteEvidenceRootCount      int64                `json:"incomplete_evidence_root_count"`
	UncommittedEvidenceRootCount     int64                `json:"uncommitted_evidence_root_count"`
	CompletedEnvelopeChildrenChecked int64                `json:"completed_envelope_children_checked"`
	InvalidEnvelopeChildCount        int64                `json:"invalid_envelope_child_count"`
	EvidencePayloadSmoke             string               `json:"evidence_payload_smoke"`
	FailedOrgs                       []failedOrganization `json:"failed_orgs,omitempty"`
	sample                           *evidenceSample      `json:"-"`
}

type failedOrganization struct {
	OrgID        string                  `json:"org_id"`
	Verification audit.ChainVerifyResult `json:"verification"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := os.Getenv("HASH_DB_URL")
	if dsn == "" {
		_, _ = fmt.Fprintln(os.Stderr, "auditverify: HASH_DB_URL is required")
		os.Exit(2)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		// pgx parser errors may quote their input. Never copy a potentially
		// credential-bearing DSN into deployment logs.
		_, _ = fmt.Fprintln(os.Stderr, "auditverify: database configuration is invalid")
		os.Exit(2)
	}
	defer pool.Close()

	result, err := verifyEstate(ctx, pool)
	if err != nil {
		// Query/connection errors are deliberately not rendered: operational
		// errors can carry connection metadata. The hard failure and stable exit
		// code are enough for the release gate; investigate in database logs.
		_, _ = fmt.Fprintln(os.Stderr, "auditverify: database verification could not complete")
		os.Exit(2)
	}
	switch {
	case !result.OK:
		result.EvidencePayloadSmoke = "blocked_by_database_gate"
	case result.sample == nil:
		result.EvidencePayloadSmoke = "skipped_no_completed_root"
	case verifyEvidenceSample(ctx, result.sample) != nil:
		// Treat any parse, digest, trust, storage, or configuration failure as
		// an integrity failure without logging object keys, credentials, or a
		// provider error. Detailed investigation belongs in restricted logs.
		result.OK = false
		result.EvidencePayloadSmoke = "failed"
	default:
		result.EvidencePayloadSmoke = "passed"
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "auditverify: encode result:", err)
		os.Exit(2)
	}
	if !result.OK || !result.Complete {
		os.Exit(1)
	}
}

func verifyEstate(ctx context.Context, pool *pgxpool.Pool) (estateResult, error) {
	result := estateResult{OK: true}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, fmt.Errorf("begin repeatable-read snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := generated.New(tx)

	afterOrgID := uuid.Nil
	for {
		orgIDs, err := q.ListOrgIDsAfter(ctx, generated.ListOrgIDsAfterParams{
			ID: afterOrgID, Limit: orgPageSize,
		})
		if err != nil {
			return result, fmt.Errorf("list organizations: %w", err)
		}
		for _, orgID := range orgIDs {
			verification, err := verifyOrganization(ctx, q, orgID)
			if err != nil {
				return result, fmt.Errorf("verify organization %s: %w", orgID, err)
			}
			result.OrgsChecked++
			result.EventsChecked += verification.TotalChecked
			if !verification.OK || !verification.Complete {
				result.OK = false
				result.FailedOrgCount++
				if len(result.FailedOrgs) < maxFailedOrgDetail {
					result.FailedOrgs = append(result.FailedOrgs, failedOrganization{
						OrgID: orgID.String(), Verification: verification,
					})
				}
			}
		}
		if len(orgIDs) < orgPageSize {
			break
		}
		afterOrgID = orgIDs[len(orgIDs)-1]
	}
	evidenceCounts, err := verifyTerminalEvidenceCommitments(ctx, tx)
	if err != nil {
		return result, fmt.Errorf("verify terminal evidence commitments: %w", err)
	}
	result.CompletedEvidenceRootsChecked = evidenceCounts.CompletedRoots
	result.IncompleteEvidenceRootCount = evidenceCounts.IncompleteRoots
	result.UncommittedEvidenceRootCount = evidenceCounts.UncommittedRoots
	result.CompletedEnvelopeChildrenChecked = evidenceCounts.CompletedChildren
	result.InvalidEnvelopeChildCount = evidenceCounts.InvalidChildren
	result.sample = evidenceCounts.Sample
	if evidenceCounts.IncompleteRoots != 0 || evidenceCounts.UncommittedRoots != 0 || evidenceCounts.InvalidChildren != 0 {
		result.OK = false
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("finish verification snapshot: %w", err)
	}
	result.Complete = true
	return result, nil
}

type terminalEvidenceCounts struct {
	CompletedRoots    int64
	IncompleteRoots   int64
	UncommittedRoots  int64
	CompletedChildren int64
	InvalidChildren   int64
	Sample            *evidenceSample
}

type evidenceSample struct {
	DocumentID                 uuid.UUID
	OrgID                      uuid.UUID
	DocumentName               string
	CompletionEffectiveAtBound bool
	CompletionEffectiveAt      pgtype.Timestamptz
	FinalPDFSHA256             []byte
	PayloadKey                 string
	PayloadSHA256              []byte
	PayloadVersionID           string
	SignatureKey               string
	SignatureSHA256            []byte
	SignatureVersionID         string
}

// verifyTerminalEvidenceCommitments rejects nullable migration gaps rather
// than treating old completed records as exportable evidence. The matching
// completion payload is read from payload_hashed (the byte-exact JSON covered
// by the already-verified org chain), never from the mutable display JSON.
// Envelope children are not independent signed roots; they must inherit the
// exact parent artifact set.
func verifyTerminalEvidenceCommitments(ctx context.Context, tx pgx.Tx) (terminalEvidenceCounts, error) {
	var out terminalEvidenceCounts
	const rootsSQL = `
WITH completed_roots AS (
    SELECT d.*
      FROM documents d
     WHERE d.status = 'completed'
       AND d.parent_envelope_id IS NULL
), classified AS (
    SELECT d.*,
           d.evidence_version_pins_required IS NOT TRUE
           OR (d.pdf_storage_key IS NOT NULL AND (
                 d.pdf_sha256 IS NULL OR octet_length(d.pdf_sha256) <> 32
                 OR NULLIF(btrim(d.pdf_storage_version_id), '') IS NULL
                 OR octet_length(d.pdf_storage_version_id) > 1024
                 OR btrim(d.pdf_storage_version_id) = 'hash:unversioned-development'
              ))
           OR (d.rendered_pdf_key IS NOT NULL AND (
                 d.rendered_pdf_sha IS NULL OR octet_length(d.rendered_pdf_sha) <> 32
                 OR NULLIF(btrim(d.rendered_pdf_version_id), '') IS NULL
                 OR octet_length(d.rendered_pdf_version_id) > 1024
                 OR btrim(d.rendered_pdf_version_id) = 'hash:unversioned-development'
              ))
           OR NULLIF(d.final_pdf_key, '') IS NULL
           OR d.final_pdf_sha IS NULL
           OR octet_length(d.final_pdf_sha) <> 32
           OR regexp_replace(d.final_pdf_key, '^.*/', '') IS DISTINCT FROM
              'final-' || encode(d.final_pdf_sha, 'hex') || '.pdf'
           OR NULLIF(btrim(d.final_pdf_version_id), '') IS NULL
           OR octet_length(d.final_pdf_version_id) > 1024
           OR btrim(d.final_pdf_version_id) = 'hash:unversioned-development'
           OR NULLIF(d.audit_cert_key, '') IS NULL
           OR d.audit_cert_sha256 IS NULL
           OR octet_length(d.audit_cert_sha256) <> 32
           OR regexp_replace(d.audit_cert_key, '^.*/', '') IS DISTINCT FROM
              'audit-' || encode(d.audit_cert_sha256, 'hex') || '.pdf'
           OR NULLIF(btrim(d.audit_cert_version_id), '') IS NULL
           OR octet_length(d.audit_cert_version_id) > 1024
           OR btrim(d.audit_cert_version_id) = 'hash:unversioned-development'
           OR NULLIF(d.audit_payload_key, '') IS NULL
           OR d.audit_payload_sha256 IS NULL
           OR octet_length(d.audit_payload_sha256) <> 32
           OR regexp_replace(d.audit_payload_key, '^.*/', '') IS DISTINCT FROM
              'audit-payload-' || encode(d.audit_payload_sha256, 'hex') || '.txt'
           OR NULLIF(btrim(d.audit_payload_version_id), '') IS NULL
           OR octet_length(d.audit_payload_version_id) > 1024
           OR btrim(d.audit_payload_version_id) = 'hash:unversioned-development'
           OR NULLIF(d.audit_signature_key, '') IS NULL
           OR d.audit_signature_sha256 IS NULL
           OR octet_length(d.audit_signature_sha256) <> 32
           OR regexp_replace(d.audit_signature_key, '^.*/', '') IS DISTINCT FROM
              'audit-signature-' || encode(d.audit_signature_sha256, 'hex') || '.txt'
           OR NULLIF(btrim(d.audit_signature_version_id), '') IS NULL
           OR octet_length(d.audit_signature_version_id) > 1024
           OR btrim(d.audit_signature_version_id) = 'hash:unversioned-development'
           OR d.completion_effective_at IS NULL
           OR d.completed_at IS DISTINCT FROM d.completion_effective_at
           OR CASE
                WHEN d.completion_effective_at_bound THEN
                  d.finalization_retain_until IS NULL
                  OR d.finalization_retain_until <> hash_evidence_retain_until(d.completion_effective_at, 7)
                ELSE d.finalization_retain_until IS NOT NULL
              END
           OR EXISTS (
               SELECT 1
                 FROM documents signed_document
                 JOIN signatures s ON s.document_id = signed_document.id
                WHERE (signed_document.id = d.id OR signed_document.parent_envelope_id = d.id)
                  AND (
                      s.image_version_pin_required IS NOT TRUE
                      OR NULLIF(btrim(s.image_version_id), '') IS NULL
                      OR octet_length(s.image_version_id) > 1024
                      OR btrim(s.image_version_id) = 'hash:unversioned-development'
                      OR NULLIF(s.image_storage_key, '') IS NULL
                      OR s.image_sha256 IS NULL
                      OR octet_length(s.image_sha256) <> 32
                  )
           ) AS incomplete,
           EXISTS (
               SELECT 1
                 FROM events e
                CROSS JOIN LATERAL (
                    SELECT convert_from(e.payload_hashed, 'UTF8')::jsonb AS body
                ) p
                WHERE e.document_id = d.id
                  AND e.org_id = d.org_id
                  AND e.kind = 'document.completed'
                  AND e.payload_hashed IS NOT NULL
                  AND CASE
                        WHEN d.completion_effective_at_bound THEN
                          p.body ->> 'completion_effective_at_bound' = 'true'
                          AND (p.body ->> 'completion_effective_at')::timestamptz = d.completion_effective_at
                          AND (p.body ->> 'retain_until')::timestamptz = d.finalization_retain_until
                        ELSE
                          NOT (p.body ? 'completion_effective_at_bound')
                          AND
                          NOT (p.body ? 'completion_effective_at')
                          AND
                          NOT (p.body ? 'retain_until')
                      END
                  AND p.body ->> 'mode' = CASE WHEN d.requires_signature THEN 'signature' ELSE 'acknowledgement' END
                  AND p.body ->> 'final_pdf_key' = d.final_pdf_key
                  AND p.body ->> 'final_pdf_sha256' = encode(d.final_pdf_sha, 'hex')
                  AND p.body ->> 'final_pdf_version_id' = d.final_pdf_version_id
                  AND p.body ->> 'audit_cert_key' = d.audit_cert_key
                  AND p.body ->> 'audit_cert_sha256' = encode(d.audit_cert_sha256, 'hex')
                  AND p.body ->> 'audit_cert_version_id' = d.audit_cert_version_id
                  AND p.body ->> 'audit_payload_key' = d.audit_payload_key
                  AND p.body ->> 'audit_payload_sha256' = encode(d.audit_payload_sha256, 'hex')
                  AND p.body ->> 'audit_payload_version_id' = d.audit_payload_version_id
                  AND p.body ->> 'audit_signature_key' = d.audit_signature_key
                  AND p.body ->> 'audit_signature_sha256' = encode(d.audit_signature_sha256, 'hex')
                  AND p.body ->> 'audit_signature_version_id' = d.audit_signature_version_id
           ) AS committed
      FROM completed_roots d
)
SELECT count(*)::bigint,
       count(*) FILTER (WHERE incomplete)::bigint,
       count(*) FILTER (WHERE NOT incomplete AND NOT committed)::bigint
  FROM classified`
	if err := tx.QueryRow(ctx, rootsSQL).Scan(
		&out.CompletedRoots, &out.IncompleteRoots, &out.UncommittedRoots,
	); err != nil { //nolint:rawsql -- release-only read from one repeatable-read snapshot
		return out, err
	}

	const childrenSQL = `
SELECT count(*)::bigint,
       count(*) FILTER (
           WHERE parent.id IS NULL
              OR parent.status <> 'completed'
              OR parent.parent_envelope_id IS NOT NULL
              OR child.final_pdf_key IS DISTINCT FROM parent.final_pdf_key
              OR child.final_pdf_sha IS DISTINCT FROM parent.final_pdf_sha
              OR child.final_pdf_version_id IS DISTINCT FROM parent.final_pdf_version_id
              OR child.audit_cert_key IS DISTINCT FROM parent.audit_cert_key
              OR child.audit_cert_sha256 IS DISTINCT FROM parent.audit_cert_sha256
              OR child.audit_cert_version_id IS DISTINCT FROM parent.audit_cert_version_id
              OR child.audit_payload_key IS DISTINCT FROM parent.audit_payload_key
              OR child.audit_payload_sha256 IS DISTINCT FROM parent.audit_payload_sha256
              OR child.audit_payload_version_id IS DISTINCT FROM parent.audit_payload_version_id
              OR child.audit_signature_key IS DISTINCT FROM parent.audit_signature_key
              OR child.audit_signature_sha256 IS DISTINCT FROM parent.audit_signature_sha256
              OR child.audit_signature_version_id IS DISTINCT FROM parent.audit_signature_version_id
              OR child.completion_effective_at_bound IS DISTINCT FROM parent.completion_effective_at_bound
              OR child.finalization_retain_until IS DISTINCT FROM parent.finalization_retain_until
              OR CASE
                   WHEN parent.completion_effective_at_bound THEN
                     child.completion_effective_at IS DISTINCT FROM parent.completion_effective_at
                     OR child.completed_at IS DISTINCT FROM parent.completion_effective_at
                   ELSE
                     child.completion_effective_at IS NULL
                     OR child.completed_at IS DISTINCT FROM child.completion_effective_at
                 END
              OR child.evidence_version_pins_required IS NOT TRUE
              OR (child.pdf_storage_key IS NOT NULL AND (
                    child.pdf_sha256 IS NULL
                    OR octet_length(child.pdf_sha256) <> 32
                    OR NULLIF(btrim(child.pdf_storage_version_id), '') IS NULL
                    OR octet_length(child.pdf_storage_version_id) > 1024
                    OR btrim(child.pdf_storage_version_id) = 'hash:unversioned-development'
                 ))
              OR (child.rendered_pdf_key IS NOT NULL AND (
                    child.rendered_pdf_sha IS NULL
                    OR octet_length(child.rendered_pdf_sha) <> 32
                    OR NULLIF(btrim(child.rendered_pdf_version_id), '') IS NULL
                    OR octet_length(child.rendered_pdf_version_id) > 1024
                    OR btrim(child.rendered_pdf_version_id) = 'hash:unversioned-development'
                 ))
              OR EXISTS (
                  SELECT 1 FROM signatures s
                   WHERE s.document_id = child.id
                     AND (s.image_version_pin_required IS NOT TRUE
                          OR NULLIF(btrim(s.image_version_id), '') IS NULL
                          OR octet_length(s.image_version_id) > 1024
                          OR btrim(s.image_version_id) = 'hash:unversioned-development'
                          OR NULLIF(s.image_storage_key, '') IS NULL
                          OR s.image_sha256 IS NULL
                          OR octet_length(s.image_sha256) <> 32)
              )
       )::bigint
  FROM documents child
  LEFT JOIN documents parent ON parent.id = child.parent_envelope_id
 WHERE child.status = 'completed'
   AND child.parent_envelope_id IS NOT NULL`
	if err := tx.QueryRow(ctx, childrenSQL).Scan(
		&out.CompletedChildren, &out.InvalidChildren,
	); err != nil { //nolint:rawsql -- release-only read from one repeatable-read snapshot
		return out, err
	}
	if out.CompletedRoots > 0 && out.IncompleteRoots == 0 && out.UncommittedRoots == 0 {
		const sampleSQL = `
SELECT id, org_id, name, completion_effective_at_bound, completion_effective_at, final_pdf_sha,
       audit_payload_key, audit_payload_sha256, audit_payload_version_id,
       audit_signature_key, audit_signature_sha256, audit_signature_version_id
  FROM documents
 WHERE status = 'completed'
   AND parent_envelope_id IS NULL
 ORDER BY completed_at ASC NULLS LAST, id ASC
 LIMIT 1`
		sample := &evidenceSample{}
		if err := tx.QueryRow(ctx, sampleSQL).Scan(
			&sample.DocumentID, &sample.OrgID, &sample.DocumentName, &sample.CompletionEffectiveAtBound, &sample.CompletionEffectiveAt, &sample.FinalPDFSHA256,
			&sample.PayloadKey, &sample.PayloadSHA256, &sample.PayloadVersionID,
			&sample.SignatureKey, &sample.SignatureSHA256, &sample.SignatureVersionID,
		); err != nil { //nolint:rawsql -- release-only read from one repeatable-read snapshot
			return out, err
		}
		out.Sample = sample
	}
	return out, nil
}

const maxEvidenceSmokeObjectBytes = 8 << 20

// verifyEvidenceSample is a read-only exact-image smoke against one available
// completed root. It verifies the independently bound sidecar bytes, parses the
// signed non-circular certificate commitments, matches them to the DB root,
// and proves the detached signature against the current/retired trusted keys.
func verifyEvidenceSample(ctx context.Context, sample *evidenceSample) error {
	if sample == nil {
		return errors.New("missing evidence sample")
	}
	cfg, err := config.Load()
	if err != nil {
		return errors.New("invalid runtime configuration")
	}
	mc, err := minio.New(cfg.S3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: cfg.S3UseSSL,
		Region: cfg.S3Region,
	})
	if err != nil {
		return errors.New("object storage initialization failed")
	}
	lockStatus, _, _, _, err := mc.GetObjectLockConfig(ctx, cfg.S3Bucket)
	if err != nil || lockStatus != "Enabled" {
		return errors.New("production evidence bucket object lock is unavailable")
	}
	payload, err := getVerifiedSmokeObject(ctx, mc, cfg.S3Bucket, sample.PayloadKey, sample.PayloadVersionID, sample.PayloadSHA256)
	if err != nil {
		return err
	}
	signature, err := getVerifiedSmokeObject(ctx, mc, cfg.S3Bucket, sample.SignatureKey, sample.SignatureVersionID, sample.SignatureSHA256)
	if err != nil {
		return err
	}
	commitments, err := evidence.ParseCertificateCommitments(payload)
	if err != nil {
		return errors.New("certificate commitment parse failed")
	}
	documentNameSHA := sha256.Sum256([]byte(sample.DocumentName))
	completionCommitmentMatches := commitments.CompletionEffectiveAt == ""
	if sample.CompletionEffectiveAtBound {
		completionCommitmentMatches = sample.CompletionEffectiveAt.Valid && !sample.CompletionEffectiveAt.Time.IsZero() &&
			commitments.CompletionEffectiveAt == sample.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)
	}
	if commitments.DocumentID != sample.DocumentID.String() || commitments.OrgID != sample.OrgID.String() ||
		commitments.DocumentNameSHA256 != fmt.Sprintf("%x", documentNameSHA[:]) ||
		commitments.FinalPDFSHA256 != fmt.Sprintf("%x", sample.FinalPDFSHA256) ||
		!completionCommitmentMatches {
		return errors.New("certificate commitments do not match database root")
	}
	currentSigner, err := sign.NewCertSigner(cfg.AuditPrivateKey)
	if err != nil || currentSigner == nil {
		return errors.New("current audit issuer is unavailable")
	}
	trusted := append([]string{currentSigner.PublicKeyBase64()}, strings.Split(cfg.AuditTrustedPublicKeys, ",")...)
	seen := make(map[string]struct{}, len(trusted))
	verified := false
	for _, publicKey := range trusted {
		publicKey = strings.TrimSpace(publicKey)
		if publicKey == "" {
			continue
		}
		if _, duplicate := seen[publicKey]; duplicate {
			continue
		}
		seen[publicKey] = struct{}{}
		if sign.Verify(publicKey, string(payload), string(signature)) {
			verified = true
		}
	}
	if !verified {
		return errors.New("certificate signature is not trusted")
	}
	return nil
}

type smokeObjectReader interface {
	GetObject(context.Context, string, string, minio.GetObjectOptions) (*minio.Object, error)
}

func getVerifiedSmokeObject(ctx context.Context, mc smokeObjectReader, bucket, key, versionID string, expectedSHA256 []byte) ([]byte, error) {
	if key == "" || strings.TrimSpace(versionID) == "" || len(versionID) > 1024 ||
		strings.TrimSpace(versionID) == storage.DevelopmentVersionID || len(expectedSHA256) != sha256.Size {
		return nil, errors.New("evidence sidecar commitment is incomplete")
	}
	object, err := mc.GetObject(ctx, bucket, key, minio.GetObjectOptions{VersionID: versionID})
	if err != nil {
		return nil, errors.New("read evidence sidecar failed")
	}
	defer object.Close()
	info, err := object.Stat()
	if err != nil || info.VersionID != versionID {
		return nil, errors.New("read evidence sidecar exact version failed")
	}
	body, err := io.ReadAll(io.LimitReader(object, maxEvidenceSmokeObjectBytes+1))
	if err != nil || len(body) > maxEvidenceSmokeObjectBytes {
		return nil, errors.New("read evidence sidecar failed")
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], expectedSHA256) != 1 {
		return nil, errors.New("evidence sidecar digest mismatch")
	}
	return body, nil
}

func verifyOrganization(ctx context.Context, q *generated.Queries, orgID uuid.UUID) (audit.ChainVerifyResult, error) {
	verifier := audit.NewChainVerifier()
	params := generated.ListChainedEventsPageForOrgParams{
		OrgID: orgID, PageLimit: eventPageSize,
	}
	for {
		rows, err := q.ListChainedEventsPageForOrg(ctx, params)
		if err != nil {
			return audit.ChainVerifyResult{}, err
		}
		verifier.VerifyPage(rows)
		if len(rows) < eventPageSize {
			return verifier.Result(), nil
		}
		last := rows[len(rows)-1]
		if last == nil || !last.CreatedAt.Valid {
			return audit.ChainVerifyResult{}, errors.New("event page has no valid terminal cursor")
		}
		params.AfterCreatedAt = last.CreatedAt
		params.AfterID = pgtype.UUID{Bytes: last.ID, Valid: true}
	}
}
