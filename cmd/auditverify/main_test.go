// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

type unexpectedObjectReader struct{}

func (unexpectedObjectReader) GetObject(context.Context, string, string, minio.GetObjectOptions) (*minio.Object, error) {
	panic("GetObject called for an incomplete evidence commitment")
}

func TestGetVerifiedSmokeObjectRejectsIncompleteCommitmentBeforeStorage(t *testing.T) {
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "", "version-1", make([]byte, 32), nil); err == nil {
		t.Fatal("empty evidence key was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "version-1", nil, nil); err == nil {
		t.Fatal("missing evidence digest was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "", make([]byte, 32), nil); err == nil {
		t.Fatal("missing evidence VersionId was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "hash:unversioned-development", make([]byte, 32), nil); err == nil {
		t.Fatal("development VersionId sentinel was accepted by the production verifier")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", " hash:unversioned-development ", make([]byte, 32), nil); err == nil {
		t.Fatal("whitespace-aliased development VersionId sentinel was accepted by the production verifier")
	}
}

func TestEvidenceGetOptionsCarriesSSECAndExactVersion(t *testing.T) {
	key := make([]byte, 32)
	sse, err := encrypt.NewSSEC(key)
	if err != nil {
		t.Fatal(err)
	}
	opts := evidenceGetOptions("provider-version-1", sse)
	if opts.VersionID != "provider-version-1" || opts.ServerSideEncryption == nil || opts.ServerSideEncryption.Type() != encrypt.SSEC {
		t.Fatal("release evidence GET did not retain its exact VersionId and SSE-C policy")
	}
}

func TestEstateJSONDoesNotExposeSampleObjectKeys(t *testing.T) {
	raw, err := json.Marshal(estateResult{
		OK: true,
		sample: &evidenceSample{
			PayloadKey:   "restricted/payload-key",
			SignatureKey: "restricted/signature-key",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "restricted/") {
		t.Fatalf("release result leaked sampled object keys: %s", raw)
	}
}

func TestTerminalEvidenceQueryPreservesLegacyEnvelopeCompletionProvenance(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"child.completion_effective_at_bound IS DISTINCT FROM parent.completion_effective_at_bound",
		"child.finalization_retain_until IS DISTINCT FROM parent.finalization_retain_until",
		"WHEN parent.completion_effective_at_bound THEN",
		"child.completed_at IS DISTINCT FROM parent.completion_effective_at",
		"child.completed_at IS DISTINCT FROM child.completion_effective_at",
		"(p.body ->> 'retain_until')::timestamptz = d.finalization_retain_until",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("terminal envelope verifier lost provenance clause %q", required)
		}
	}
}

func TestImmutableBlockEvidenceRejectsEveryUnpinnedStorageShape(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"fixed terms"}]}`)
	if err := validateImmutableBlockEvidence(valid); err != nil {
		t.Fatalf("canonical static tree rejected: %v", err)
	}

	for name, raw := range map[string][]byte{
		"image":         []byte(`{"version":1,"blocks":[{"id":"outer","type":"callout","content":[{"id":"image","type":"image","attrs":{"storage_key":"org/o/image.png"}}]}]}`),
		"raw-html":      []byte(`{"version":1,"blocks":[{"id":"raw","type":"raw_html","text":"<img src=\"/api/v1/storage/org/o/image.png\">"}]}`),
		"version":       []byte(`{"version":1,"blocks":[{"id":"raw","type":"raw_html","text":"<img src=\"/api/v1/x/../storage/org/o/image.png\">"}]}`),
		"initial-field": []byte(`{"version":1,"blocks":[{"id":"outer","type":"callout","content":[{"id":"initial","type":"initial_field","attrs":{"recipient_role":"signer"}}]}]}`),
		"text-field":    []byte(`{"version":1,"blocks":[{"id":"text","type":"text_field","attrs":{"recipient_role":"signer"}}]}`),
		"date-field":    []byte(`{"version":1,"blocks":[{"id":"date","type":"date_field","attrs":{"recipient_role":"signer"}}]}`),
		"checkbox":      []byte(`{"version":1,"blocks":[{"id":"check","type":"checkbox","attrs":{"recipient_role":"signer"}}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateImmutableBlockEvidence(raw)
			if err == nil {
				t.Fatal("unpinned immutable block evidence was accepted")
			}
		})
	}
	if err := validateImmutableBlockEvidence([]byte(`{"version":1,"blocks":[],"extra":true}`)); err == nil {
		t.Fatal("non-canonical immutable block evidence was accepted")
	}
}

func TestImmutableBlockEvidenceInventoryCoversFrozenStatesVersionsAndEnvelopeChildren(t *testing.T) {
	t.Parallel()
	for _, required := range []string{
		"'sent','in_progress','changes_requested','finalizing','completed','declined','voided','expired'",
		"d.status = 'sealing'",
		"si.document_id = COALESCE(d.parent_envelope_id, d.id)",
		"si.retention_started_at IS NOT NULL",
		"SELECT d.blocks_json",
		"JOIN frozen_documents frozen ON frozen.id = d.id",
		"SELECT v.block_tree_json",
		"JOIN frozen_documents frozen ON frozen.id = v.document_id",
	} {
		if !strings.Contains(immutableBlockEvidenceSQL, required) {
			t.Fatalf("immutable block inventory lost required clause %q", required)
		}
	}
	if strings.Contains(immutableBlockEvidenceSQL, "parent_envelope_id IS NULL") {
		t.Fatal("immutable block inventory excluded envelope children")
	}
}

func TestFrozenBrandingSnapshotRequiresCompleteThemeAndNoLogo(t *testing.T) {
	t.Parallel()
	id := pgtype.UUID{Valid: true}
	textValue := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	valid := []pgtype.Text{
		textValue("#0F172A"), textValue("#3B82F6"), textValue("#FFFFFF"), textValue("#0F172A"), textValue("#64748B"),
		textValue(""), textValue(""), textValue("Inter"), textValue("Inter"), textValue("#0F172A"),
	}
	if !validFrozenBrandingSnapshot(id, valid[0], valid[1], valid[2], valid[3], valid[4], valid[5], valid[6], valid[7], valid[8], valid[9]) {
		t.Fatal("complete logo-free snapshot rejected")
	}
	missing := append([]pgtype.Text(nil), valid...)
	missing[2].Valid = false
	if validFrozenBrandingSnapshot(id, missing[0], missing[1], missing[2], missing[3], missing[4], missing[5], missing[6], missing[7], missing[8], missing[9]) {
		t.Fatal("partial snapshot accepted")
	}
	withLogo := append([]pgtype.Text(nil), valid...)
	withLogo[5].String = "/branding/logo/org.png"
	if validFrozenBrandingSnapshot(id, withLogo[0], withLogo[1], withLogo[2], withLogo[3], withLogo[4], withLogo[5], withLogo[6], withLogo[7], withLogo[8], withLogo[9]) {
		t.Fatal("unpinned production logo snapshot accepted")
	}
	whitespaceLogo := append([]pgtype.Text(nil), valid...)
	whitespaceLogo[5].String = " "
	if validFrozenBrandingSnapshot(id, whitespaceLogo[0], whitespaceLogo[1], whitespaceLogo[2], whitespaceLogo[3], whitespaceLogo[4], whitespaceLogo[5], whitespaceLogo[6], whitespaceLogo[7], whitespaceLogo[8], whitespaceLogo[9]) {
		t.Fatal("non-canonical whitespace logo snapshot accepted")
	}
	noncanonicalFont := append([]pgtype.Text(nil), valid...)
	noncanonicalFont[8].String = "Inter,system-ui"
	if validFrozenBrandingSnapshot(id, noncanonicalFont[0], noncanonicalFont[1], noncanonicalFont[2], noncanonicalFont[3], noncanonicalFont[4], noncanonicalFont[5], noncanonicalFont[6], noncanonicalFont[7], noncanonicalFont[8], noncanonicalFont[9]) {
		t.Fatal("non-canonical frozen font snapshot accepted")
	}
}

func TestFrozenBrandingAuditCoversEveryIrreversibleDocumentAndLegacyLogoRow(t *testing.T) {
	t.Parallel()
	for _, required := range []string{
		"'sent','in_progress','changes_requested','finalizing','completed','declined','voided','expired'",
		"d.status = 'sealing'",
		"si.document_id = COALESCE(d.parent_envelope_id, d.id)",
		"LEFT JOIN document_branding_override snapshot ON snapshot.document_id = frozen.id",
	} {
		if !strings.Contains(frozenBrandingEvidenceSQL, required) {
			t.Fatalf("frozen branding audit lost clause %q", required)
		}
	}
	for _, required := range []string{"FROM org_branding", "FROM document_branding_override", "logo_url <> ''"} {
		if !strings.Contains(unsupportedBrandingLogosSQL, required) {
			t.Fatalf("legacy logo audit lost clause %q", required)
		}
	}
}
