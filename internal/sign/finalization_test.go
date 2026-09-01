// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

type finalizationStorageStub struct {
	objects        map[string][]byte
	retained       []string
	retainUntil    []time.Time
	putRetainUntil []time.Time
	failRetainAt   int
	mutateAfterRet int
}

func (s *finalizationStorageStub) Get(_ context.Context, key string) ([]byte, error) {
	body, ok := s.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), body...), nil
}

func (s *finalizationStorageStub) GetVerified(ctx context.Context, key string, expected []byte) ([]byte, error) {
	body, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], expected) {
		return nil, errors.New("digest mismatch")
	}
	return body, nil
}

func (s *finalizationStorageStub) GetVerifiedVersion(ctx context.Context, key, _ string, expected []byte) ([]byte, error) {
	return s.GetVerified(ctx, key, expected)
}

func (s *finalizationStorageStub) ResolveVerifiedLegacy(ctx context.Context, key string, expected []byte) ([]byte, storage.StoredObject, error) {
	body, err := s.GetVerified(ctx, key, expected)
	ref := storage.StoredObject{VersionID: "version-" + key}
	copy(ref.SHA256[:], expected)
	return body, ref, err
}

func (s *finalizationStorageStub) Put(_ context.Context, key, _ string, body []byte) ([32]byte, error) {
	if s.objects == nil {
		s.objects = make(map[string][]byte)
	}
	s.objects[key] = append([]byte(nil), body...)
	return sha256.Sum256(body), nil
}

func (s *finalizationStorageStub) PutEvidence(ctx context.Context, key, contentType string, body []byte) ([32]byte, error) {
	return s.Put(ctx, key, contentType, body)
}

func (s *finalizationStorageStub) PutVersioned(ctx context.Context, key, contentType string, body []byte) (storage.StoredObject, error) {
	sum, err := s.Put(ctx, key, contentType, body)
	return storage.StoredObject{SHA256: sum, VersionID: "version-" + key}, err
}

func (s *finalizationStorageStub) PutEvidenceVersioned(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) (storage.StoredObject, error) {
	s.putRetainUntil = append(s.putRetainUntil, retainUntil)
	return s.PutVersioned(ctx, key, contentType, body)
}

func (s *finalizationStorageStub) RetainEvidenceVerified(_ context.Context, key string, _ []byte, retainUntil time.Time) error {
	s.retained = append(s.retained, key)
	s.retainUntil = append(s.retainUntil, retainUntil)
	call := len(s.retained)
	if s.failRetainAt > 0 && call == s.failRetainAt {
		return errors.New("retention unavailable")
	}
	if s.mutateAfterRet > 0 && call == s.mutateAfterRet {
		s.objects[key] = []byte("shadow version")
	}
	return nil
}

func (s *finalizationStorageStub) RetainEvidenceVersion(ctx context.Context, key, _ string, expected []byte, retainUntil time.Time) error {
	return s.RetainEvidenceVerified(ctx, key, expected, retainUntil)
}

func finalizationFixture(t *testing.T) (*generated.Document, *generated.DocumentFinalizationIntent, *finalizationStorageStub) {
	t.Helper()
	completionEffectiveAt := pgtype.Timestamptz{
		Time: time.Date(2026, 8, 31, 10, 11, 12, 345678000, time.UTC), Valid: true,
	}
	retainUntil := pgtype.Timestamptz{
		Time: storage.EvidenceRetentionDeadline(completionEffectiveAt.Time, article13.RetentionYearsV1), Valid: true,
	}
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Status: "finalizing", RequiresSignature: true,
		SentAt:                     pgtype.Timestamptz{Time: completionEffectiveAt.Time.Add(-time.Hour), Valid: true},
		CompletionEffectiveAtBound: true,
		CompletionEffectiveAt:      completionEffectiveAt,
		FinalizationRetainUntil:    retainUntil,
	}
	store := &finalizationStorageStub{objects: make(map[string][]byte)}
	base := path.Join("org", doc.OrgID.String(), "documents", doc.ID.String())
	type artifact struct {
		prefix, suffix string
		body           []byte
	}
	artifacts := []artifact{
		{"final-", ".pdf", []byte("final pdf")},
		{"audit-", ".pdf", []byte("audit certificate")},
		{"audit-payload-", ".txt", []byte("signed payload")},
		{"audit-signature-", ".txt", []byte("detached signature")},
	}
	keys := make([]string, len(artifacts))
	digests := make([][]byte, len(artifacts))
	for i, artifact := range artifacts {
		sum := sha256.Sum256(artifact.body)
		digests[i] = append([]byte(nil), sum[:]...)
		keys[i] = path.Join(base, artifact.prefix+fmt.Sprintf("%x", sum)+artifact.suffix)
		store.objects[keys[i]] = append([]byte(nil), artifact.body...)
	}
	intent := &generated.DocumentFinalizationIntent{
		DocumentID: doc.ID, OrgID: doc.OrgID, Mode: "signature",
		CompletionEffectiveAt: completionEffectiveAt,
		RetainUntil:           retainUntil,
		FinalPdfKey:           keys[0], FinalPdfSha256: digests[0], FinalPdfVersionID: pgtype.Text{String: "version-final", Valid: true},
		AuditCertKey: keys[1], AuditCertSha256: digests[1], AuditCertVersionID: pgtype.Text{String: "version-cert", Valid: true},
		AuditPayloadKey: keys[2], AuditPayloadSha256: digests[2], AuditPayloadVersionID: pgtype.Text{String: "version-payload", Valid: true},
		AuditSignatureKey: keys[3], AuditSignatureSha256: digests[3], AuditSignatureVersionID: pgtype.Text{String: "version-signature", Valid: true},
		EvidenceVersionPinsRequired: true,
	}
	return doc, intent, store
}

func TestFinalizationRetentionDeadlineMustFollowAuthoritativeSentEpoch(t *testing.T) {
	doc, _, _ := finalizationFixture(t)
	if _, err := finalizationRetentionDeadline(doc); err != nil {
		t.Fatalf("valid ordered retention commitment rejected: %v", err)
	}
	doc.SentAt = doc.CompletionEffectiveAt
	if _, err := finalizationRetentionDeadline(doc); err == nil {
		t.Fatal("completion equal to sent epoch was accepted")
	}
	doc.SentAt.Time = doc.CompletionEffectiveAt.Time.Add(time.Microsecond)
	if _, err := finalizationRetentionDeadline(doc); err == nil {
		t.Fatal("completion before future monotonic sent epoch was accepted")
	}
}

func TestValidateFinalizationIntentBindsEveryContentAddressedArtifact(t *testing.T) {
	doc, intent, _ := finalizationFixture(t)
	if err := validateFinalizationIntent(doc, intent); err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}

	mutated := *intent
	mutated.AuditCertKey = path.Join(path.Dir(intent.AuditCertKey), "audit-"+fmt.Sprintf("%064x", 1)+".pdf")
	if err := validateFinalizationIntent(doc, &mutated); err == nil {
		t.Fatal("certificate key/digest mismatch must fail closed")
	}
	mutated = *intent
	mutated.AuditSignatureSha256 = []byte{1}
	if err := validateFinalizationIntent(doc, &mutated); err == nil {
		t.Fatal("short sidecar digest must fail closed")
	}
	mutated = *intent
	mutated.RetainUntil.Time = mutated.RetainUntil.Time.Add(time.Second)
	if err := validateFinalizationIntent(doc, &mutated); err == nil {
		t.Fatal("intent retention deadline drift must fail closed")
	}
}

func TestRetainFinalizationArtifactsRetriesAfterPartialCrash(t *testing.T) {
	_, intent, store := finalizationFixture(t)
	store.failRetainAt = 2
	if err := retainFinalizationArtifacts(context.Background(), store, intent); err == nil {
		t.Fatal("partial retention failure must be returned")
	}
	if len(store.retained) != 2 {
		t.Fatalf("first attempt retained %d objects, want 2 calls", len(store.retained))
	}

	// Simulate the retry worker after process exit. Reapplying retention to the
	// already-retained first object is safe and the full tuple completes.
	store.failRetainAt = 0
	if err := retainFinalizationArtifacts(context.Background(), store, intent); err != nil {
		t.Fatalf("retry after partial retention failed: %v", err)
	}
	if len(store.retained) != 6 {
		t.Fatalf("retention calls after retry = %d, want 2 + 4", len(store.retained))
	}
	for i, got := range store.retainUntil {
		if !got.Equal(intent.RetainUntil.Time) {
			t.Fatalf("retention call %d deadline = %s, want stable %s", i, got, intent.RetainUntil.Time)
		}
	}
}

func TestRetainFinalizationArtifactsRejectsPostRetentionShadow(t *testing.T) {
	_, intent, store := finalizationFixture(t)
	store.mutateAfterRet = 4
	if err := retainFinalizationArtifacts(context.Background(), store, intent); err == nil {
		t.Fatal("shadow version after retention must fail digest verification")
	}
}

func TestRetainPinnedSignatureEvidenceUsesFinalizationDeadlineForEveryImage(t *testing.T) {
	doc, intent, store := finalizationFixture(t)
	signatures := make([]*generated.Signature, 0, 2)
	for i, body := range [][]byte{[]byte("signature one"), []byte("signature two")} {
		digest := sha256.Sum256(body)
		key := fmt.Sprintf("signature-%d.html", i+1)
		store.objects[key] = body
		signatures = append(signatures, &generated.Signature{
			ID: uuid.New(), DocumentID: doc.ID,
			ImageStorageKey: key, ImageSha256: digest[:],
			ImageVersionID:          pgtype.Text{String: fmt.Sprintf("version-%d", i+1), Valid: true},
			ImageVersionPinRequired: true,
		})
	}
	if err := retainPinnedSignatureEvidence(context.Background(), store, doc.ID, signatures, intent.RetainUntil.Time); err != nil {
		t.Fatalf("retain signature images: %v", err)
	}
	if len(store.retained) != len(signatures) {
		t.Fatalf("retained signature images = %d, want %d", len(store.retained), len(signatures))
	}
	for i, got := range store.retainUntil {
		if !got.Equal(intent.RetainUntil.Time) {
			t.Fatalf("signature retention call %d deadline = %s, want %s", i, got, intent.RetainUntil.Time)
		}
	}
	malformed := *signatures[0]
	malformed.ImageVersionID = pgtype.Text{}
	if err := retainPinnedSignatureEvidence(context.Background(), store, doc.ID, []*generated.Signature{&malformed}, intent.RetainUntil.Time); err == nil {
		t.Fatal("signature re-retention accepted evidence without an exact VersionId")
	}
}

func TestFinalizationIntentComparisonCoversAllArtifactCommitments(t *testing.T) {
	_, intent, _ := finalizationFixture(t)
	copyIntent := *intent
	if !finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("identical intents should compare equal")
	}
	copyIntent.AuditPayloadKey += ".shadow"
	if finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("changed payload key was not detected")
	}
	copyIntent = *intent
	copyIntent.CompletionEffectiveAt.Time = copyIntent.CompletionEffectiveAt.Time.Add(time.Microsecond)
	if finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("changed completion-effective timestamp was not detected")
	}
	copyIntent = *intent
	copyIntent.RetainUntil.Time = copyIntent.RetainUntil.Time.Add(time.Second)
	if finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("changed retention deadline was not detected")
	}
	copyIntent = *intent
	copyIntent.AuditCertVersionID.String += "-shadow"
	if finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("changed certificate VersionId was not detected")
	}
	copyIntent = *intent
	copyIntent.AuditSignatureSha256 = append([]byte(nil), intent.AuditSignatureSha256...)
	copyIntent.AuditSignatureSha256[0] ^= 0xff
	if finalizationIntentsEqual(intent, &copyIntent) {
		t.Fatal("changed signature digest was not detected")
	}
}

func TestDocumentCompletionAuditPayloadCommitsExactEvidenceTuple(t *testing.T) {
	_, intent, _ := finalizationFixture(t)
	payload, err := documentCompletionAuditPayload(intent)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"mode":                       intent.Mode,
		"completion_effective_at":    "2026-08-31T10:11:12.345678Z",
		"retain_until":               "2033-08-31T10:11:13Z",
		"final_pdf_key":              intent.FinalPdfKey,
		"final_pdf_sha256":           fmt.Sprintf("%x", intent.FinalPdfSha256),
		"final_pdf_version_id":       intent.FinalPdfVersionID.String,
		"audit_cert_key":             intent.AuditCertKey,
		"audit_cert_sha256":          fmt.Sprintf("%x", intent.AuditCertSha256),
		"audit_cert_version_id":      intent.AuditCertVersionID.String,
		"audit_payload_key":          intent.AuditPayloadKey,
		"audit_payload_sha256":       fmt.Sprintf("%x", intent.AuditPayloadSha256),
		"audit_payload_version_id":   intent.AuditPayloadVersionID.String,
		"audit_signature_key":        intent.AuditSignatureKey,
		"audit_signature_sha256":     fmt.Sprintf("%x", intent.AuditSignatureSha256),
		"audit_signature_version_id": intent.AuditSignatureVersionID.String,
	}
	for field, expected := range want {
		if got, ok := payload[field].(string); !ok || got != expected {
			t.Errorf("completion payload %s = %#v, want %q", field, payload[field], expected)
		}
	}
	if bound, ok := payload["completion_effective_at_bound"].(bool); !ok || !bound {
		t.Fatalf("completion payload bound provenance = %#v, want true", payload["completion_effective_at_bound"])
	}
	if len(payload) != len(want)+1 {
		t.Fatalf("completion payload fields = %d, want exact %d-field commitment: %#v", len(payload), len(want)+1, payload)
	}
}

func TestValidateFinalizationIntentRejectsCompletionTimestampDrift(t *testing.T) {
	doc, intent, _ := finalizationFixture(t)
	intent.CompletionEffectiveAt.Time = intent.CompletionEffectiveAt.Time.Add(time.Microsecond)
	if err := validateFinalizationIntent(doc, intent); err == nil {
		t.Fatal("intent/document completion-effective timestamp mismatch must fail closed")
	}
}
