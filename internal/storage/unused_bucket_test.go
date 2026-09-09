// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

type fakeUnusedBucketLister struct {
	versions []minio.ObjectInfo
	uploads  []minio.ObjectMultipartInfo
	opts     minio.ListObjectsOptions
	prefix   string
	recurse  bool
}

func (f *fakeUnusedBucketLister) ListObjects(_ context.Context, _ string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	f.opts = opts
	result := make(chan minio.ObjectInfo, len(f.versions))
	for _, item := range f.versions {
		result <- item
	}
	close(result)
	return result
}

func (f *fakeUnusedBucketLister) ListIncompleteUploads(_ context.Context, _ string, prefix string, recursive bool) <-chan minio.ObjectMultipartInfo {
	f.prefix, f.recurse = prefix, recursive
	result := make(chan minio.ObjectMultipartInfo, len(f.uploads))
	for _, item := range f.uploads {
		result <- item
	}
	close(result)
	return result
}

func testBootstrapEstateIntent() BootstrapEstateIntent {
	nonce := make([]byte, bootstrapEstateNonceBytes)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	payload := append(append([]byte(nil), bootstrapEstatePayloadPrefix...), nonce...)
	digest := sha256.Sum256(payload)
	return BootstrapEstateIntent{
		SchemaVersion:     BootstrapEstateIntentSchemaVersion,
		Candidate:         json.RawMessage(`{"commit_sha":"test"}`),
		Storage:           json.RawMessage(`{"bucket":"hash"}`),
		MarkerKey:         BootstrapEstateMarkerKey,
		MarkerNonceHex:    hex.EncodeToString(nonce),
		MarkerSHA256:      hex.EncodeToString(digest[:]),
		CreatedAt:         "2028-01-02T03:04:05Z",
		RetentionYears:    bootstrapEstateRetentionYears,
		MarkerRetainUntil: "2035-01-02T03:04:05Z",
	}
}

func testBootstrapEstateReceipt() BootstrapEstateReceipt {
	return bootstrapEstateReceiptFor(testBootstrapEstateIntent(), "provider-version-1")
}

func TestCheckBootstrapEstateInventoryDrainsCompleteZeroAndClaimedStates(t *testing.T) {
	empty := &fakeUnusedBucketLister{}
	if err := checkBootstrapEstateInventory(context.Background(), empty, "hash", nil); err != nil {
		t.Fatal(err)
	}
	if !empty.opts.WithVersions || !empty.opts.Recursive || empty.opts.Prefix != "" {
		t.Fatalf("version-list options = %+v", empty.opts)
	}
	if empty.prefix != "" || !empty.recurse {
		t.Fatalf("multipart list prefix=%q recursive=%v", empty.prefix, empty.recurse)
	}

	receipt := testBootstrapEstateReceipt()
	claimed := &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Key: receipt.MarkerKey, VersionID: receipt.MarkerVersionID, IsLatest: true}}}
	if err := checkBootstrapEstateInventory(context.Background(), claimed, "hash", &receipt); err != nil {
		t.Fatalf("exact claimed estate rejected: %v", err)
	}
}

func TestCheckBootstrapEstateInventoryRejectsDebrisMarkersVersionsAndErrors(t *testing.T) {
	receipt := testBootstrapEstateReceipt()
	marker := minio.ObjectInfo{Key: receipt.MarkerKey, VersionID: receipt.MarkerVersionID, IsLatest: true}
	tests := []struct {
		name string
		fake *fakeUnusedBucketLister
	}{
		{"missing-marker", &fakeUnusedBucketLister{}},
		{"changed-marker-version", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Key: receipt.MarkerKey, VersionID: "other"}}}},
		{"additional-key", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, {Key: "org/o/documents/d.pdf", VersionID: "v2"}}}},
		{"additional-marker-version", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, {Key: receipt.MarkerKey, VersionID: "v0"}}}},
		{"marker-delete-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Key: receipt.MarkerKey, VersionID: receipt.MarkerVersionID, IsDeleteMarker: true}}}},
		{"other-delete-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, {Key: "other", VersionID: "v2", IsDeleteMarker: true}}}},
		{"version-provider-error", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Err: errors.New("provider")}}}},
		{"multipart-upload", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker}, uploads: []minio.ObjectMultipartInfo{{Key: "pending", UploadID: "upload-1"}}}},
		{"multipart-provider-error", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker}, uploads: []minio.ObjectMultipartInfo{{Err: errors.New("provider")}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkBootstrapEstateInventory(context.Background(), tc.fake, "hash", &receipt); err == nil {
				t.Fatal("unsafe claimed bucket inventory was accepted")
			}
		})
	}

	for _, item := range []minio.ObjectInfo{
		{Key: "evidence/a", VersionID: "v1"},
		{Key: "evidence/a", VersionID: "v2", IsDeleteMarker: true},
		{Err: errors.New("provider")},
	} {
		if err := checkBootstrapEstateInventory(context.Background(), &fakeUnusedBucketLister{versions: []minio.ObjectInfo{item}}, "hash", nil); err == nil {
			t.Fatal("nonzero unclaimed bucket was accepted")
		}
	}
}

func TestPendingBootstrapEstateAcceptsOnlyEmptyOrExactSingleIntentMarker(t *testing.T) {
	intent := testBootstrapEstateIntent()
	version, present, err := pendingBootstrapEstateVersion(context.Background(), &fakeUnusedBucketLister{}, "hash", intent)
	if err != nil || present || version != "" {
		t.Fatalf("empty pending state = %q/%v/%v", version, present, err)
	}
	exact := &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Key: intent.MarkerKey, VersionID: "provider-version-1"}}}
	version, present, err = pendingBootstrapEstateVersion(context.Background(), exact, "hash", intent)
	if err != nil || !present || version != "provider-version-1" {
		t.Fatalf("exact pending marker state = %q/%v/%v", version, present, err)
	}
	for _, versions := range [][]minio.ObjectInfo{
		{{Key: "other", VersionID: "v1"}},
		{{Key: intent.MarkerKey, VersionID: ""}},
		{{Key: intent.MarkerKey, VersionID: "v1", IsDeleteMarker: true}},
		{{Key: intent.MarkerKey, VersionID: "v1"}, {Key: intent.MarkerKey, VersionID: "v2"}},
	} {
		if _, _, err := pendingBootstrapEstateVersion(context.Background(), &fakeUnusedBucketLister{versions: versions}, "hash", intent); err == nil {
			t.Fatal("unsafe pre-receipt crash state was accepted")
		}
	}
}

func TestCheckBootstrapEstateInventoryFailsClosedOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkBootstrapEstateInventory(ctx, &fakeUnusedBucketLister{}, "hash", nil); err == nil {
		t.Fatal("cancelled zero-state inventory was accepted")
	}
	receipt := testBootstrapEstateReceipt()
	if err := checkBootstrapEstateInventory(ctx, &fakeUnusedBucketLister{}, "hash", &receipt); err == nil {
		t.Fatal("cancelled claimed-estate inventory was accepted")
	}
}

type fakeBootstrapEstateOperations struct {
	version          string
	present          bool
	events           []string
	postInventoryErr error
	verifyErr        error
	protectionErr    error
}

func (f *fakeBootstrapEstateOperations) PendingInventory(_ context.Context, _ BootstrapEstateIntent) (string, bool, error) {
	f.events = append(f.events, "inventory-pending")
	return f.version, f.present, nil
}

func (f *fakeBootstrapEstateOperations) ExactInventory(_ context.Context, _ BootstrapEstateReceipt) error {
	f.events = append(f.events, "inventory-exact")
	return f.postInventoryErr
}

func (f *fakeBootstrapEstateOperations) PutMarker(_ context.Context, _ BootstrapEstateIntent, _ []byte) (string, error) {
	f.events = append(f.events, "put-marker")
	f.version = "provider-version-1"
	return f.version, nil
}

func (f *fakeBootstrapEstateOperations) VerifyExactMarker(_ context.Context, _ BootstrapEstateReceipt) error {
	f.events = append(f.events, "verify-exact")
	return f.verifyErr
}

func (f *fakeBootstrapEstateOperations) ProtectExactMarker(_ context.Context, _ BootstrapEstateReceipt) error {
	f.events = append(f.events, "protect-exact")
	return f.protectionErr
}

func (f *fakeBootstrapEstateOperations) VerifyExactMarkerProtection(_ context.Context, _ BootstrapEstateReceipt) error {
	f.events = append(f.events, "verify-protection")
	return f.protectionErr
}

func TestReconcileBootstrapEstateCrashWindowsAreIdempotentAndOrdered(t *testing.T) {
	intent := testBootstrapEstateIntent()
	for _, test := range []struct {
		name    string
		present bool
		wantPut bool
	}{
		{name: "intent persisted before PUT", present: false, wantPut: true},
		{name: "provider committed before final receipt", present: true, wantPut: false},
		{name: "retention completed before final receipt", present: true, wantPut: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops := &fakeBootstrapEstateOperations{version: "provider-version-1", present: test.present}
			receipt, err := reconcileBootstrapEstate(context.Background(), ops, intent, func(got BootstrapEstateReceipt) error {
				ops.events = append(ops.events, "persist-receipt")
				return got.matchesIntent(intent)
			})
			if err != nil || receipt.MarkerVersionID != "provider-version-1" {
				t.Fatalf("reconcile = %#v, %v", receipt, err)
			}
			want := []string{"inventory-pending"}
			if test.wantPut {
				want = append(want, "put-marker")
			}
			want = append(want, "verify-exact", "protect-exact", "persist-receipt", "inventory-exact", "verify-protection")
			if !reflect.DeepEqual(ops.events, want) {
				t.Fatalf("events = %#v, want %#v", ops.events, want)
			}
		})
	}
}

func TestReconcileBootstrapEstateRetainsReceiptOnPostClaimRace(t *testing.T) {
	intent := testBootstrapEstateIntent()
	ops := &fakeBootstrapEstateOperations{postInventoryErr: errors.New("concurrent durable version")}
	persisted := false
	_, err := reconcileBootstrapEstate(context.Background(), ops, intent, func(BootstrapEstateReceipt) error {
		persisted = true
		return nil
	})
	if err == nil || !persisted {
		t.Fatal("post-PUT race was accepted or its final receipt was not retained")
	}
}

func TestVerifyBootstrapEstateAfterFinalReceiptIsReadOnlyAndExact(t *testing.T) {
	intent := testBootstrapEstateIntent()
	receipt := bootstrapEstateReceiptFor(intent, "provider-version-1")
	ops := &fakeBootstrapEstateOperations{}
	if err := verifyBootstrapEstate(context.Background(), ops, intent, receipt); err != nil {
		t.Fatal(err)
	}
	want := []string{"inventory-exact", "verify-exact", "verify-protection"}
	if !reflect.DeepEqual(ops.events, want) {
		t.Fatalf("verification events = %#v, want %#v", ops.events, want)
	}
}

func TestVerifyBootstrapEstateMarkerAllowsPostCutoverReferencedObjectsWithoutListing(t *testing.T) {
	intent := testBootstrapEstateIntent()
	receipt := bootstrapEstateReceiptFor(intent, "provider-version-1")
	ops := &fakeBootstrapEstateOperations{postInventoryErr: errors.New("legitimate DB-referenced object exists")}
	if err := verifyBootstrapEstateMarker(context.Background(), ops, intent, receipt); err != nil {
		t.Fatal(err)
	}
	want := []string{"verify-exact", "verify-protection"}
	if !reflect.DeepEqual(ops.events, want) {
		t.Fatalf("post-cutover marker events = %#v, want %#v", ops.events, want)
	}
}

func TestCandidateCutoverInventoryAllowsOnlyMarkerAndExactDBReferences(t *testing.T) {
	receipt := testBootstrapEstateReceipt()
	references := []BootstrapEstateReference{
		{Key: "org/o/documents/d/source.pdf", VersionID: "source-v1", SHA256: make([]byte, sha256.Size)},
		{Key: "branding/o/logo.png"},
	}
	fake := &fakeUnusedBucketLister{versions: []minio.ObjectInfo{
		{Key: receipt.MarkerKey, VersionID: receipt.MarkerVersionID},
		{Key: references[0].Key, VersionID: references[0].VersionID},
		{Key: references[1].Key, VersionID: "logo-v1"},
	}}
	resolved, err := checkBootstrapEstateReferencedInventory(context.Background(), fake, "hash", receipt, references)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[references[0].Key].versionID != "source-v1" || resolved[references[1].Key].versionID != "logo-v1" {
		t.Fatalf("resolved candidate-cutover inventory = %#v", resolved)
	}
	if !fake.opts.WithVersions || !fake.opts.Recursive || fake.prefix != "" || !fake.recurse {
		t.Fatal("candidate-cutover inventory did not exhaust versions and multipart uploads")
	}
}

func TestCandidateCutoverInventoryRejectsOrphansVersionsDeletesUploadsAndErrors(t *testing.T) {
	receipt := testBootstrapEstateReceipt()
	reference := BootstrapEstateReference{Key: "org/o/documents/d/source.pdf", VersionID: "source-v1", SHA256: make([]byte, sha256.Size), LegalEvidence: true, RetainUntil: time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)}
	marker := minio.ObjectInfo{Key: receipt.MarkerKey, VersionID: receipt.MarkerVersionID}
	object := minio.ObjectInfo{Key: reference.Key, VersionID: reference.VersionID}
	for _, test := range []struct {
		name string
		fake *fakeUnusedBucketLister
	}{
		{"missing-reference", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker}}},
		{"missing-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{object}}},
		{"changed-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{{Key: receipt.MarkerKey, VersionID: "changed"}, object}}},
		{"orphan-key", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object, {Key: "orphan", VersionID: "v1"}}}},
		{"additional-reference-version", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object, {Key: reference.Key, VersionID: "source-v0"}}}},
		{"reference-delete-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object, {Key: reference.Key, VersionID: "delete", IsDeleteMarker: true}}}},
		{"transient-delete-marker", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object, {Key: "transient/hash-storage-check/x", VersionID: "delete", IsDeleteMarker: true}}}},
		{"incomplete-upload", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object}, uploads: []minio.ObjectMultipartInfo{{Key: "pending", UploadID: "u1"}}}},
		{"version-provider-error", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object, {Err: errors.New("provider")}}}},
		{"multipart-provider-error", &fakeUnusedBucketLister{versions: []minio.ObjectInfo{marker, object}, uploads: []minio.ObjectMultipartInfo{{Err: errors.New("provider")}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := checkBootstrapEstateReferencedInventory(context.Background(), test.fake, "hash", receipt, []BootstrapEstateReference{reference}); err == nil {
				t.Fatal("unsafe candidate-cutover provider state was accepted")
			}
		})
	}
}

func TestCandidateCutoverInventoryRejectsInvalidDBReferencesAndCancellation(t *testing.T) {
	receipt := testBootstrapEstateReceipt()
	for _, reference := range []BootstrapEstateReference{
		{},
		{Key: BootstrapEstateMarkerKey},
		{Key: "duplicate", SHA256: []byte{1}},
		{Key: "legal", VersionID: "v1", LegalEvidence: true},
		{Key: "bad-version", VersionID: DevelopmentVersionID},
	} {
		if _, err := checkBootstrapEstateReferencedInventory(context.Background(), &fakeUnusedBucketLister{}, "hash", receipt, []BootstrapEstateReference{reference}); err == nil {
			t.Fatal("invalid canonical DB reference was accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checkBootstrapEstateReferencedInventory(ctx, &fakeUnusedBucketLister{}, "hash", receipt, nil); err == nil {
		t.Fatal("cancelled candidate-cutover inventory was accepted")
	}
}

func TestCandidateCutoverVerifierReinventoriesAndUsesDBRetentionAndEncryption(t *testing.T) {
	raw, err := os.ReadFile("unused_bucket.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func (c *Client) VerifyBootstrapEstateWithReferences")
	if start < 0 {
		t.Fatal("candidate-cutover verifier is absent")
	}
	body := src[start:]
	if strings.Count(body, "checkBootstrapEstateReferencedInventory(") < 2 {
		t.Fatal("candidate-cutover verifier does not exhaustively re-inventory after exact reads")
	}
	if !strings.Contains(body, "reference.RetainUntil") || !strings.Contains(body, "verifyDataPlaneEncryption") {
		t.Fatal("candidate-cutover verifier does not use exact DB retention and per-object encryption proof")
	}
}

func TestBootstrapEstateIntentAndReceiptRejectChangedIdentity(t *testing.T) {
	validIntent := testBootstrapEstateIntent()
	for name, mutate := range map[string]func(*BootstrapEstateIntent){
		"schema":          func(i *BootstrapEstateIntent) { i.SchemaVersion++ },
		"candidate":       func(i *BootstrapEstateIntent) { i.Candidate = json.RawMessage(`null`) },
		"storage":         func(i *BootstrapEstateIntent) { i.Storage = json.RawMessage(`[]`) },
		"key":             func(i *BootstrapEstateIntent) { i.MarkerKey = "org/attacker" },
		"nonce":           func(i *BootstrapEstateIntent) { i.MarkerNonceHex = "00" },
		"digest":          func(i *BootstrapEstateIntent) { i.MarkerSHA256 = strings.Repeat("0", 64) },
		"created-at":      func(i *BootstrapEstateIntent) { i.CreatedAt = "2028-01-02T03:04:05+01:00" },
		"retention-years": func(i *BootstrapEstateIntent) { i.RetentionYears-- },
		"retention":       func(i *BootstrapEstateIntent) { i.MarkerRetainUntil = "2035-01-02T03:04:05+01:00" },
		"short-retention": func(i *BootstrapEstateIntent) { i.MarkerRetainUntil = "2034-01-02T03:04:05Z" },
	} {
		t.Run("intent-"+name, func(t *testing.T) {
			intent := validIntent
			mutate(&intent)
			if err := intent.Validate(); err == nil {
				t.Fatal("changed intent was accepted")
			}
		})
	}

	validReceipt := bootstrapEstateReceiptFor(validIntent, "provider-version-1")
	for name, mutate := range map[string]func(*BootstrapEstateReceipt){
		"schema":      func(r *BootstrapEstateReceipt) { r.SchemaVersion++ },
		"key":         func(r *BootstrapEstateReceipt) { r.MarkerKey = "org/attacker" },
		"version":     func(r *BootstrapEstateReceipt) { r.MarkerVersionID = "" },
		"development": func(r *BootstrapEstateReceipt) { r.MarkerVersionID = DevelopmentVersionID },
		"digest":      func(r *BootstrapEstateReceipt) { r.MarkerSHA256 = "ABC" },
		"retention":   func(r *BootstrapEstateReceipt) { r.MarkerRetainUntil = "never" },
	} {
		t.Run("receipt-"+name, func(t *testing.T) {
			receipt := validReceipt
			mutate(&receipt)
			if err := receipt.Validate(); err == nil {
				t.Fatal("changed receipt was accepted")
			}
		})
	}
}
