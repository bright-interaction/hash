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
	"github.com/bright-interaction/hash/internal/s3policy"
	"github.com/bright-interaction/hash/internal/storage"
)

// TestEvidenceObjectLockE2E proves the production retention path against the
// same real S3-compatible service used by the signing E2E suite. Local MinIO
// runs use an ephemeral bucket. Provider conformance uses a pre-created bucket,
// writes only a unique prefix, and leaves bucket lifecycle configuration alone;
// its COMPLIANCE-retained objects cannot be cleaned up early by design.
func TestEvidenceObjectLockE2E(t *testing.T) {
	endpoint := os.Getenv("HASH_E2E_S3_ENDPOINT")
	accessKey := os.Getenv("HASH_E2E_S3_ACCESS_KEY")
	secretKey := os.Getenv("HASH_E2E_S3_SECRET_KEY")
	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("set HASH_E2E_S3_ENDPOINT and credentials to run")
	}
	storageCfg := e2eStorageConfig(t, os.Getenv("HASH_E2E_S3_BUCKET"))
	policy, err := s3policy.Load(
		storageCfg.SSEMode,
		storageCfg.SSECKeyFile,
		storageCfg.SSECKeySHA256,
		storageCfg.BucketLookup,
		storageCfg.UseSSL,
	)
	must(t, err, "validate live S3 policy")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	raw, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       storageCfg.UseSSL,
		Region:       storageCfg.Region,
		BucketLookup: policy.BucketLookupType,
	})
	must(t, err, "create raw MinIO client")
	runID := strings.ReplaceAll(uuid.NewString(), "-", "")
	bucket := storageCfg.Bucket
	precreatedBucket := bucket != ""
	if bucket == "" {
		if os.Getenv("HASH_E2E_S3_EPHEMERAL_BUCKET") != "true" {
			t.Fatal("creating an Object-Lock bucket requires HASH_E2E_S3_EPHEMERAL_BUCKET=true; otherwise provide a pre-created HASH_E2E_S3_BUCKET")
		}
		if policy.SSEMode == s3policy.SSEModeC {
			t.Fatal("SSE-C conformance requires a pre-created Object-Lock bucket in HASH_E2E_S3_BUCKET")
		}
		bucket = "hash-lock-e2e-" + runID
		must(t, raw.MakeBucket(ctx, bucket, minio.MakeBucketOptions{
			Region: storageCfg.Region, ObjectLocking: true,
		}), "create Object-Lock bucket")
	} else if os.Getenv("HASH_E2E_S3_LIVE_CONFORMANCE") != "true" {
		t.Fatal("a pre-created provider bucket requires HASH_E2E_S3_LIVE_CONFORMANCE=true because this test writes seven-year COMPLIANCE objects")
	}

	storageCfg.Bucket = bucket
	storageCfg.SSEMode = policy.SSEMode
	storageCfg.BucketLookup = policy.BucketLookup
	storageCfg.RequireObjectLock = true
	// A conformance run may write only its unique object prefix. It must not
	// overwrite lifecycle configuration on an operator-managed bucket.
	storageCfg.SkipTransientLifecycle = precreatedBucket
	store, err := storage.New(ctx, storageCfg)
	must(t, err, "open production-mode storage")

	started := time.Now().UTC()
	retainUntil := storage.EvidenceRetentionDeadline(started, article13.RetentionYearsV1)
	mutableKey := "conformance/" + runID + "/org/test/documents/draft-source.pdf"
	mutable := []byte("mutable draft source")
	mutableDigest := sha256.Sum256(mutable)
	mutableStored, err := store.PutVersioned(ctx, mutableKey, "application/pdf", mutable)
	must(t, err, "put mutable exact-version draft source")
	if mutableStored.VersionID == "" || mutableStored.VersionID == storage.DevelopmentVersionID || mutableStored.SHA256 != mutableDigest {
		t.Fatalf("mutable stored identity = %#v, want exact production VersionId and digest", mutableStored)
	}
	must(t, store.DeleteVersion(ctx, mutableKey, mutableStored.VersionID, mutableDigest[:]), "physically delete exact mutable draft version")
	for item := range raw.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: mutableKey, Recursive: true, WithVersions: true}) {
		if item.Err != nil {
			t.Fatalf("list mutable draft history after exact deletion: %v", item.Err)
		}
		if item.Key == mutableKey {
			t.Fatalf("exact deletion left version/delete-marker state: VersionId=%q delete_marker=%t", item.VersionID, item.IsDeleteMarker)
		}
	}

	key := "conformance/" + runID + "/org/test/documents/test/final.pdf"
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
	if err := raw.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{VersionID: stored.VersionID}); err == nil {
		t.Fatal("provider allowed permanent deletion of a COMPLIANCE-retained exact version")
	}
	gotAfterDelete, err := store.GetVerifiedVersion(ctx, key, stored.VersionID, expected[:])
	must(t, err, "read exact retained version after denied permanent delete")
	if !bytes.Equal(gotAfterDelete, authentic) {
		t.Fatal("denied permanent delete changed retained evidence bytes")
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
	if precreatedBucket && os.Getenv("HASH_E2E_S3_LIVE_STRESS_CONFORMANCE") != "true" {
		t.Log("basic provider conformance passed; set HASH_E2E_S3_LIVE_STRESS_CONFORMANCE=true only on a disposable dedicated bucket to run the retained shadow/version stress proof")
		return
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
		_, err = raw.PutObject(ctx, bucket, key, bytes.NewReader(shadow), int64(len(shadow)), minio.PutObjectOptions{
			ServerSideEncryption: policy.WriteEncryption,
		})
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
