// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/storage"
)

// TestEvidenceObjectLockE2E proves the production retention path against the
// same real S3-compatible service used by the signing E2E suite. The bucket is
// deliberately ephemeral with the MinIO container: COMPLIANCE retention
// cannot be shortened or cleaned up early, which is exactly the property this
// test is intended to exercise.
func TestEvidenceObjectLockE2E(t *testing.T) {
	endpoint := os.Getenv("HASH_E2E_S3_ENDPOINT")
	accessKey := os.Getenv("HASH_E2E_S3_ACCESS_KEY")
	secretKey := os.Getenv("HASH_E2E_S3_SECRET_KEY")
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("set HASH_E2E_S3_ENDPOINT and credentials to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	raw, err := minio.New(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	must(t, err, "create raw MinIO client")
	bucket := "hash-lock-e2e-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	must(t, raw.MakeBucket(ctx, bucket, minio.MakeBucketOptions{
		Region: "eu-central-1", ObjectLocking: true,
	}), "create Object-Lock bucket")

	store, err := storage.New(ctx, storage.Config{
		Endpoint: endpoint, Region: "eu-central-1", Bucket: bucket,
		AccessKey: accessKey, SecretKey: secretKey, RequireObjectLock: true,
	})
	must(t, err, "open production-mode storage")

	started := time.Now().UTC()
	retainUntil := storage.EvidenceRetentionDeadline(started, article13.RetentionYearsV1)
	key := "org/test/documents/test/final.pdf"
	authentic := []byte("immutable evidence")
	expected := sha256.Sum256(authentic)
	stored, err := store.PutEvidenceVersioned(ctx, key, "application/pdf", authentic, retainUntil)
	must(t, err, "put immutable evidence")
	if stored.VersionID == "" || stored.VersionID == storage.DevelopmentVersionID || stored.SHA256 != expected {
		t.Fatalf("stored identity = %#v, want exact production VersionId and digest", stored)
	}
	mode, firstUntil, err := raw.GetObjectRetention(ctx, bucket, key, stored.VersionID)
	must(t, err, "read initial evidence retention")
	if mode == nil || *mode != minio.Compliance || firstUntil == nil || !firstUntil.Equal(retainUntil) {
		t.Fatalf("initial retention = mode %v until %v, want COMPLIANCE through exact durable %s", mode, firstUntil, retainUntil)
	}
	retried, err := store.PutEvidenceVersioned(ctx, key, "application/pdf", authentic, retainUntil)
	must(t, err, "retry immutable evidence write")
	if retried.VersionID != stored.VersionID {
		t.Fatalf("same-digest retry created VersionId %q, want reuse %q", retried.VersionID, stored.VersionID)
	}
	mode, retryUntil, err := raw.GetObjectRetention(ctx, bucket, key, stored.VersionID)
	must(t, err, "read retried evidence retention")
	if mode == nil || *mode != minio.Compliance || retryUntil == nil || !retryUntil.Equal(*firstUntil) {
		t.Fatalf("retry retention = mode %v until %v, want unchanged %s", mode, retryUntil, firstUntil)
	}

	// A pre-fix retry may already have over-extended the provider deadline.
	// COMPLIANCE retention cannot be shortened; a retry using the durable target
	// must recognize the later provider state as sufficient and leave it intact.
	laterUntil := retainUntil.AddDate(1, 0, 0)
	compliance := minio.Compliance
	must(t, raw.PutObjectRetention(ctx, bucket, key, minio.PutObjectRetentionOptions{
		Mode: &compliance, RetainUntilDate: &laterUntil, VersionID: stored.VersionID,
	}), "seed a legacy over-extended provider deadline")
	must(t, store.RetainEvidenceVersion(ctx, key, stored.VersionID, expected[:], retainUntil), "retry durable target below provider deadline")
	_, preservedUntil, err := raw.GetObjectRetention(ctx, bucket, key, stored.VersionID)
	must(t, err, "read preserved over-extended retention")
	if preservedUntil == nil || !preservedUntil.Equal(laterUntil) {
		t.Fatalf("provider deadline after durable retry = %v, want preserved later deadline %s", preservedUntil, laterUntil)
	}

	// Object Lock preserves the authentic version but does not prevent a writer
	// from adding newer shadow versions at the same logical key. More than the
	// bounded legacy-search window must not affect an exact persisted VersionId.
	for i := 0; i < 101; i++ {
		shadow := []byte(fmt.Sprintf("newer malicious shadow %03d", i))
		_, err = raw.PutObject(ctx, bucket, key, bytes.NewReader(shadow), int64(len(shadow)), minio.PutObjectOptions{})
		must(t, err, "put shadow version")
	}
	got, err := store.GetVerifiedVersion(ctx, key, stored.VersionID, expected[:])
	must(t, err, "read exact pinned evidence behind more than 100 shadows")
	if !bytes.Equal(got, authentic) {
		t.Fatalf("verified bytes = %q, want authentic committed version", got)
	}
	must(t, store.RetainEvidenceVersion(ctx, key, stored.VersionID, expected[:], retainUntil), "retain exact pinned version")
	if _, err := store.GetVerified(ctx, key, expected[:]); err == nil || !strings.Contains(err.Error(), "more than 100") {
		t.Fatalf("legacy bounded lookup after shadow flood = %v, want bounded failure", err)
	}

	// A crash before the SQL intent can leave a locked orphan. A hostile latest
	// shadow does not force a history scan: the deterministic retry writes and
	// returns one new atomically retained exact version that can be persisted.
	recovered, err := store.PutEvidenceVersioned(ctx, key, "application/pdf", authentic, retainUntil)
	must(t, err, "recover deterministic write after shadow flood")
	if recovered.VersionID == "" || recovered.VersionID == storage.DevelopmentVersionID || recovered.SHA256 != expected {
		t.Fatalf("recovered identity = %#v, want exact production VersionId", recovered)
	}
	mode, recoveredUntil, err := raw.GetObjectRetention(ctx, bucket, key, recovered.VersionID)
	must(t, err, "read recovered evidence retention")
	if mode == nil || *mode != minio.Compliance || recoveredUntil == nil || !recoveredUntil.Equal(retainUntil) {
		t.Fatalf("recovered retention = mode %v until %v, want exact durable %s", mode, recoveredUntil, retainUntil)
	}
}
