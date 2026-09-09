// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"

	"github.com/bright-interaction/hash/internal/s3policy"
)

func TestReadBounded(t *testing.T) {
	got, err := readBounded(bytes.NewBufferString("12345"), 5)
	if err != nil || string(got) != "12345" {
		t.Fatalf("exact-limit read = %q, %v", got, err)
	}
	if _, err := readBounded(bytes.NewBufferString("123456"), 5); err == nil {
		t.Fatal("oversized object must fail closed")
	}
}

func TestValidateEndpointTransportRejectsExternalPlaintext(t *testing.T) {
	for _, endpoint := range []string{
		"storage.example.com:9000",
		"203.0.113.10:9000",
		"[2001:db8::1]:9000",
		"MINIO:9000",
		"minio:9000 ",
		"http://minio:9000",
		"minio:9000.example.com",
		"localhost:9000/path",
		"localhost:not-a-port",
	} {
		if err := s3policy.ValidateEndpointTransport(endpoint, false, false); err == nil {
			t.Errorf("production plaintext endpoint %q was accepted", endpoint)
		}
		if err := s3policy.ValidateEndpointTransport(endpoint, false, true); err == nil {
			t.Errorf("development opt-in accepted external/malformed plaintext endpoint %q", endpoint)
		}
	}
}

func TestValidateEndpointTransportAllowsOnlyExactProductionOrLocalDevelopment(t *testing.T) {
	if err := s3policy.ValidateEndpointTransport("minio:9000", false, false); err != nil {
		t.Fatalf("canonical production MinIO rejected: %v", err)
	}
	for _, endpoint := range []string{
		"localhost:9000",
		"127.0.0.1:49152",
		"[::1]:49152",
		"hash-minio:9000",
		"hash-e2e-minio:9000",
	} {
		if err := s3policy.ValidateEndpointTransport(endpoint, false, true); err != nil {
			t.Errorf("local development endpoint %q rejected: %v", endpoint, err)
		}
	}
	if err := s3policy.ValidateEndpointTransport("storage.example.com:443", true, false); err != nil {
		t.Fatalf("TLS endpoint rejected before provider initialization: %v", err)
	}
}

func TestValidateBucketVersioningEnabledRequiresExplicitEnabled(t *testing.T) {
	if err := validateBucketVersioningEnabled(minio.Enabled); err != nil {
		t.Fatalf("enabled versioning rejected: %v", err)
	}
	for _, status := range []string{"", minio.Suspended, "Disabled", "enabled"} {
		if err := validateBucketVersioningEnabled(status); err == nil {
			t.Errorf("unsafe bucket versioning status %q accepted", status)
		}
	}
}

func TestGetVerifiedRejectsInvalidExpectedDigestBeforeStorageAccess(t *testing.T) {
	c := &Client{}
	if _, err := c.GetVerified(context.Background(), "evidence.pdf", nil); err == nil {
		t.Fatal("missing committed digest must fail closed")
	}
	short := sha256.Sum256([]byte("present only to make the test intent explicit"))
	if _, err := c.GetVerified(context.Background(), "evidence.pdf", short[:31]); err == nil {
		t.Fatal("short committed digest must fail closed")
	}
}

func TestPinnedVersionIDValidationMatchesDatabaseBounds(t *testing.T) {
	production := &Client{requireEvidenceLock: true}
	development := &Client{}
	for _, versionID := range []string{"", " \t", strings.Repeat("v", maxPersistedVersionIDBytes+1), DevelopmentVersionID, " " + DevelopmentVersionID + " "} {
		if err := production.validatePinnedVersionID(versionID); err == nil {
			t.Fatalf("production accepted invalid VersionId %q", versionID)
		}
	}
	if err := production.validatePinnedVersionID(strings.Repeat("v", maxPersistedVersionIDBytes)); err != nil {
		t.Fatalf("production rejected maximum-length VersionId: %v", err)
	}
	if err := development.validatePinnedVersionID(DevelopmentVersionID); err != nil {
		t.Fatalf("development sentinel rejected locally: %v", err)
	}
}

func TestPersistableVersionIDFailsClosedInProduction(t *testing.T) {
	production := &Client{requireEvidenceLock: true}
	for _, versionID := range []string{"", strings.Repeat("v", maxPersistedVersionIDBytes+1), DevelopmentVersionID, " " + DevelopmentVersionID + " "} {
		if _, err := production.persistableVersionID("legal/object", versionID); err == nil {
			t.Fatalf("production accepted provider VersionId %q", versionID)
		}
	}
	development := &Client{}
	got, err := development.persistableVersionID("local/object", "")
	if err != nil || got != DevelopmentVersionID {
		t.Fatalf("local unversioned identity = %q, %v", got, err)
	}
	opaque := " provider-version-id "
	got, err = development.persistableVersionID("local/object", opaque)
	if err != nil || got != opaque {
		t.Fatalf("opaque provider identity = %q, %v; want byte-exact %q", got, err, opaque)
	}
}

func TestUnpinnedWritesFailClosedBeforeProviderAccessInProduction(t *testing.T) {
	client := &Client{requireEvidenceLock: true}
	payload := []byte("must never reach the object provider")

	if _, err := client.Put(context.Background(), "mutable/branding/logo.png", "image/png", payload); !errors.Is(err, errUnpinnedProductionWrite) {
		t.Fatalf("Put error = %v, want unpinned-write refusal", err)
	}

	stream := bytes.NewReader(payload)
	if err := client.PutStream(context.Background(), "mutable/stream.bin", "application/octet-stream", stream, int64(len(payload))); !errors.Is(err, errUnpinnedProductionWrite) {
		t.Fatalf("PutStream error = %v, want unpinned-write refusal", err)
	}
	if stream.Len() != len(payload) {
		t.Fatalf("PutStream consumed %d bytes before refusing production write", len(payload)-stream.Len())
	}
}

func TestValidateObjectLockEnabled(t *testing.T) {
	if err := validateObjectLockEnabled("Enabled"); err != nil {
		t.Fatalf("enabled Object Lock rejected: %v", err)
	}
	for _, value := range []string{"", "Disabled", "enabled"} {
		if err := validateObjectLockEnabled(value); err == nil {
			t.Fatalf("Object Lock state %q should fail closed", value)
		}
	}
}

func TestEvidencePutOptsUsesComplianceModeForSevenCalendarYears(t *testing.T) {
	now := time.Date(2024, time.February, 29, 12, 30, 0, 987654321, time.FixedZone("test", 2*60*60))
	retainUntil := EvidenceRetentionDeadline(now, 7)
	c := &Client{writeServerSideEncryption: encrypt.NewSSE()}
	opts := c.evidencePutOpts("application/pdf", retainUntil)
	if opts.Mode != minio.Compliance {
		t.Fatalf("retention mode = %q, want COMPLIANCE", opts.Mode)
	}
	want := time.Date(2031, time.March, 1, 10, 30, 1, 0, time.UTC)
	if !opts.RetainUntilDate.Equal(want) {
		t.Fatalf("retain until = %s, want %s", opts.RetainUntilDate, want)
	}
	if opts.ContentType != "application/pdf" || opts.ServerSideEncryption == nil {
		t.Fatal("evidence write must preserve content type and SSE-S3 encryption")
	}
}

func TestStorageOptionsCarrySSECOnEveryDataPath(t *testing.T) {
	testKey := sha256.Sum256([]byte("public unit-test SSE-C key material"))
	sse, err := encrypt.NewSSEC(testKey[:])
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		writeServerSideEncryption: sse,
		readServerSideEncryption:  sse,
		sseMode:                   s3policy.SSEModeC,
	}

	if got := c.putOpts("application/pdf").ServerSideEncryption; got == nil || got.Type() != encrypt.SSEC {
		t.Fatal("put options did not carry SSE-C")
	}
	if got := c.evidencePutOpts("application/pdf", time.Now().UTC()).ServerSideEncryption; got == nil || got.Type() != encrypt.SSEC {
		t.Fatal("evidence put options did not carry SSE-C")
	}
	if got := c.getOpts("version-1"); got.ServerSideEncryption == nil || got.ServerSideEncryption.Type() != encrypt.SSEC || got.VersionID != "version-1" {
		t.Fatal("get options did not preserve version-bound SSE-C")
	}
	if got := c.statOpts("version-2"); got.ServerSideEncryption == nil || got.ServerSideEncryption.Type() != encrypt.SSEC || got.VersionID != "version-2" {
		t.Fatal("stat options did not preserve version-bound SSE-C")
	}
}

func TestStorageOptionsDoNotSendSSES3OnReads(t *testing.T) {
	c := &Client{writeServerSideEncryption: encrypt.NewSSE()}
	if got := c.putOpts("application/pdf").ServerSideEncryption; got == nil || got.Type() != encrypt.S3 {
		t.Fatal("SSE-S3 write options were lost")
	}
	if c.getOpts("version-1").ServerSideEncryption != nil {
		t.Fatal("SSE-S3 must not set encryption headers on GET")
	}
	if c.statOpts("version-1").ServerSideEncryption != nil {
		t.Fatal("SSE-S3 must not set encryption headers on HEAD/Stat")
	}
}

func TestPresignGetFailsClosedForSSEC(t *testing.T) {
	c := &Client{sseMode: s3policy.SSEModeC}
	if _, err := c.PresignGet(context.Background(), "legal/evidence.pdf", time.Minute); err == nil || !strings.Contains(err.Error(), "unavailable with SSE-C") {
		t.Fatalf("SSE-C browser presign did not fail closed: %v", err)
	}
}

func TestRetentionConformanceIAMScopeIsExplicitlyDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../DEPLOY.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, required := range []string{
		"`s3:DeleteObjectVersion`",
		"`_hash/bootstrap-estate/v1`",
		"unrelated IAM denial",
		"creates no per-deploy retained canary and never touches customer evidence",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("retention conformance IAM contract is missing %q", required)
		}
	}
}

func TestEvidenceRetentionDeadlineIsCanonicalAndLeapSafe(t *testing.T) {
	anchor := time.Date(2024, time.February, 29, 12, 30, 0, 987654321, time.FixedZone("test", 2*60*60))
	want := time.Date(2031, time.March, 1, 10, 30, 1, 0, time.UTC)
	if got := EvidenceRetentionDeadline(anchor, 7); !got.Equal(want) || got.Location() != time.UTC || got.Nanosecond() != 0 {
		t.Fatalf("deadline = %s, want canonical %s", got, want)
	}
	if got := EvidenceRetentionDeadline(anchor, 7); got.Before(anchor.UTC().AddDate(7, 0, 0)) {
		t.Fatalf("deadline %s is shorter than seven calendar years from %s", got, anchor)
	}
	exactAnchor := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	exactWant := time.Date(2032, time.January, 2, 3, 4, 5, 0, time.UTC)
	if got := EvidenceRetentionDeadline(exactAnchor, 7); !got.Equal(exactWant) {
		t.Fatalf("whole-second deadline = %s, want no gratuitous extension beyond %s", got, exactWant)
	}
	if _, err := canonicalEvidenceRetainUntil(time.Time{}); err == nil {
		t.Fatal("zero retain-until must fail closed")
	}
	if _, err := canonicalEvidenceRetainUntil(want.Add(time.Nanosecond)); err == nil {
		t.Fatal("sub-second retain-until must fail closed")
	}
}

type bucketExistsResult struct {
	exists bool
	err    error
}

type fakeBucketInitializer struct {
	existsResults []bucketExistsResult
	makeErr       error
	existsCalls   int
	makeCalls     int
	makeOptions   minio.MakeBucketOptions
}

type concurrentBucketInitializer struct {
	mu                sync.Mutex
	bothChecked       chan struct{}
	initialCheckCount int
	existsCallCount   int
	makeCallCount     int
	created           bool
}

func (f *concurrentBucketInitializer) BucketExists(context.Context, string) (bool, error) {
	f.mu.Lock()
	f.existsCallCount++
	if f.initialCheckCount < 2 {
		f.initialCheckCount++
		if f.initialCheckCount == 2 {
			close(f.bothChecked)
		}
		f.mu.Unlock()
		<-f.bothChecked
		return false, nil
	}
	exists := f.created
	f.mu.Unlock()
	return exists, nil
}

func (f *concurrentBucketInitializer) MakeBucket(context.Context, string, minio.MakeBucketOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.makeCallCount++
	if !f.created {
		f.created = true
		return nil
	}
	return minio.ErrorResponse{Code: "BucketAlreadyOwnedByYou"}
}

func (f *fakeBucketInitializer) BucketExists(context.Context, string) (bool, error) {
	f.existsCalls++
	if len(f.existsResults) == 0 {
		return false, errors.New("unexpected BucketExists call")
	}
	result := f.existsResults[0]
	f.existsResults = f.existsResults[1:]
	return result.exists, result.err
}

func (f *fakeBucketInitializer) MakeBucket(_ context.Context, _ string, options minio.MakeBucketOptions) error {
	f.makeCalls++
	f.makeOptions = options
	return f.makeErr
}

func TestEnsureBucketExisting(t *testing.T) {
	fake := &fakeBucketInitializer{
		existsResults: []bucketExistsResult{{exists: true}},
	}

	if err := ensureBucket(context.Background(), fake, "hash", "eu-north-1"); err != nil {
		t.Fatalf("ensureBucket() error = %v", err)
	}
	if fake.existsCalls != 1 || fake.makeCalls != 0 {
		t.Fatalf("calls = exists %d, make %d; want 1, 0", fake.existsCalls, fake.makeCalls)
	}
}

func TestVerifyExistingBucketNeverCreates(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  bucketExistsResult
		wantErr bool
	}{
		{name: "exists", result: bucketExistsResult{exists: true}},
		{name: "missing", result: bucketExistsResult{exists: false}, wantErr: true},
		{name: "check error", result: bucketExistsResult{err: errors.New("provider unavailable")}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeBucketInitializer{existsResults: []bucketExistsResult{test.result}}
			err := verifyExistingBucket(context.Background(), fake, "hash")
			if (err != nil) != test.wantErr {
				t.Fatalf("verifyExistingBucket() error = %v, wantErr %t", err, test.wantErr)
			}
			if fake.existsCalls != 1 || fake.makeCalls != 0 {
				t.Fatalf("calls = exists %d, make %d; want 1, 0", fake.existsCalls, fake.makeCalls)
			}
		})
	}
}

func TestValidatePingBucketExistsFailsWhenProviderReportsMissing(t *testing.T) {
	if err := validatePingBucketExists("hash", true, nil); err != nil {
		t.Fatalf("existing bucket rejected: %v", err)
	}
	if err := validatePingBucketExists("hash", false, nil); err == nil {
		t.Fatal("missing bucket left runtime readiness healthy")
	}
	providerErr := errors.New("provider unavailable")
	if err := validatePingBucketExists("hash", false, providerErr); !errors.Is(err, providerErr) {
		t.Fatalf("provider error was not preserved: %v", err)
	}
}

func TestEnsureBucketCreatesMissingBucket(t *testing.T) {
	fake := &fakeBucketInitializer{
		existsResults: []bucketExistsResult{{exists: false}},
	}

	if err := ensureBucket(context.Background(), fake, "hash", "eu-north-1"); err != nil {
		t.Fatalf("ensureBucket() error = %v", err)
	}
	if fake.existsCalls != 1 || fake.makeCalls != 1 {
		t.Fatalf("calls = exists %d, make %d; want 1, 1", fake.existsCalls, fake.makeCalls)
	}
	if fake.makeOptions.Region != "eu-north-1" {
		t.Fatalf("MakeBucket region = %q, want eu-north-1", fake.makeOptions.Region)
	}
}

func TestEnsureBucketEnablesObjectLockAtCreationWhenRequired(t *testing.T) {
	fake := &fakeBucketInitializer{
		existsResults: []bucketExistsResult{{exists: false}},
	}

	if err := ensureBucket(context.Background(), fake, "hash-evidence", "eu-north-1", true); err != nil {
		t.Fatalf("ensureBucket() error = %v", err)
	}
	if !fake.makeOptions.ObjectLocking {
		t.Fatal("production evidence bucket was created without Object Lock enabled")
	}
}

func TestEnsureBucketAcceptsVerifiedConcurrentCreate(t *testing.T) {
	tests := []struct {
		name      string
		createErr error
	}{
		{
			name:      "value response",
			createErr: fmt.Errorf("make bucket: %w", minio.ErrorResponse{Code: "BucketAlreadyOwnedByYou"}),
		},
		{
			name:      "pointer response",
			createErr: fmt.Errorf("make bucket: %w", &minio.ErrorResponse{Code: "BucketAlreadyOwnedByYou"}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeBucketInitializer{
				existsResults: []bucketExistsResult{{exists: false}, {exists: true}},
				makeErr:       test.createErr,
			}

			if err := ensureBucket(context.Background(), fake, "hash", ""); err != nil {
				t.Fatalf("ensureBucket() error = %v", err)
			}
			if fake.existsCalls != 2 || fake.makeCalls != 1 {
				t.Fatalf("calls = exists %d, make %d; want 2, 1", fake.existsCalls, fake.makeCalls)
			}
		})
	}
}

func TestEnsureBucketConcurrentCallers(t *testing.T) {
	fake := &concurrentBucketInitializer{bothChecked: make(chan struct{})}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			errs <- ensureBucket(context.Background(), fake, "hash", "eu-north-1")
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("ensureBucket() concurrent error = %v", err)
		}
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.created || fake.makeCallCount != 2 || fake.existsCallCount != 3 {
		t.Fatalf(
			"state = created %t, exists calls %d, make calls %d; want true, 3, 2",
			fake.created,
			fake.existsCallCount,
			fake.makeCallCount,
		)
	}
}

func TestEnsureBucketPreservesRealCreateError(t *testing.T) {
	for _, createErr := range []minio.ErrorResponse{
		{Code: "AccessDenied", Message: "not authorised"},
		{Code: "BucketAlreadyExists"},
	} {
		t.Run(createErr.Code, func(t *testing.T) {
			fake := &fakeBucketInitializer{
				existsResults: []bucketExistsResult{{exists: false}},
				makeErr:       createErr,
			}

			err := ensureBucket(context.Background(), fake, "hash", "")
			if !errors.Is(err, createErr) {
				t.Fatalf("ensureBucket() error = %v; want wrapped create error", err)
			}
			if fake.existsCalls != 1 || fake.makeCalls != 1 {
				t.Fatalf("calls = exists %d, make %d; want 1, 1", fake.existsCalls, fake.makeCalls)
			}
		})
	}
}

func TestEnsureBucketRejectsUnverifiedConcurrentCreate(t *testing.T) {
	createErr := minio.ErrorResponse{Code: "BucketAlreadyOwnedByYou"}
	t.Run("still missing", func(t *testing.T) {
		fake := &fakeBucketInitializer{
			existsResults: []bucketExistsResult{{exists: false}, {exists: false}},
			makeErr:       createErr,
		}

		err := ensureBucket(context.Background(), fake, "hash", "")
		if !errors.Is(err, createErr) {
			t.Fatalf("ensureBucket() error = %v; want wrapped create error", err)
		}
	})

	t.Run("verification error", func(t *testing.T) {
		checkErr := errors.New("head bucket failed")
		fake := &fakeBucketInitializer{
			existsResults: []bucketExistsResult{{exists: false}, {err: checkErr}},
			makeErr:       createErr,
		}

		err := ensureBucket(context.Background(), fake, "hash", "")
		if !errors.Is(err, createErr) || !errors.Is(err, checkErr) {
			t.Fatalf("ensureBucket() error = %v; want create and verification errors", err)
		}
	})
}

func TestEnsureBucketPreservesInitialCheckError(t *testing.T) {
	checkErr := errors.New("head bucket timed out")
	fake := &fakeBucketInitializer{
		existsResults: []bucketExistsResult{{err: checkErr}},
	}

	err := ensureBucket(context.Background(), fake, "hash", "")
	if !errors.Is(err, checkErr) {
		t.Fatalf("ensureBucket() error = %v; want wrapped check error", err)
	}
	if fake.makeCalls != 0 {
		t.Fatalf("MakeBucket calls = %d, want 0", fake.makeCalls)
	}
}
