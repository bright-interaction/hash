// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
)

type unexpectedObjectReader struct{}

func (unexpectedObjectReader) GetObject(context.Context, string, string, minio.GetObjectOptions) (*minio.Object, error) {
	panic("GetObject called for an incomplete evidence commitment")
}

func TestGetVerifiedSmokeObjectRejectsIncompleteCommitmentBeforeStorage(t *testing.T) {
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "", "version-1", make([]byte, 32)); err == nil {
		t.Fatal("empty evidence key was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "version-1", nil); err == nil {
		t.Fatal("missing evidence digest was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "", make([]byte, 32)); err == nil {
		t.Fatal("missing evidence VersionId was accepted")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", "hash:unversioned-development", make([]byte, 32)); err == nil {
		t.Fatal("development VersionId sentinel was accepted by the production verifier")
	}
	if _, err := getVerifiedSmokeObject(context.Background(), unexpectedObjectReader{}, "bucket", "key", " hash:unversioned-development ", make([]byte, 32)); err == nil {
		t.Fatal("whitespace-aliased development VersionId sentinel was accepted by the production verifier")
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
