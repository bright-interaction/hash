// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package storage wraps MinIO/S3 access. The Bright Interaction MinIO at
// s3.example.com is the default backend.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/lifecycle"

	"github.com/bright-interaction/hash/internal/s3policy"
)

type Client struct {
	mc                        *minio.Client
	bucket                    string
	requireEvidenceLock       bool
	writeServerSideEncryption encrypt.ServerSide
	readServerSideEncryption  encrypt.ServerSide
	sseMode                   string
}

type Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
	// SSEMode is "sse-s3" (the default) or "sse-c". SSE-C reads its
	// customer key only from SSECKeyFile and is rejected without TLS.
	SSEMode     string
	SSECKeyFile string
	// BucketLookup controls S3 addressing: auto (default), path, or dns.
	BucketLookup string
	// RequireObjectLock turns the bucket and per-object immutability checks on.
	// Production sets this unconditionally; development leaves it false because
	// its disposable MinIO bucket is recreated for every test run.
	RequireObjectLock bool
	// SkipTransientLifecycle prevents New from reconciling Hash's optional
	// transient-object expiry rule. It exists for a live-provider conformance
	// test against an operator-owned bucket; normal runtimes must leave it false.
	SkipTransientLifecycle bool
}

// DevelopmentVersionID is persisted only by disposable, non-versioned local
// storage. It makes the database contract explicit without pretending that a
// local latest-object read is an immutable S3 version. Production clients
// reject this sentinel on every exact-version read and retention operation.
const DevelopmentVersionID = "hash:unversioned-development"

// StoredObject is the complete commitment returned by a write. Legal evidence
// is identified by all three values at once: logical key (held by the caller),
// SHA-256, and the exact S3 VersionId returned by PutObject.
type StoredObject struct {
	SHA256    [sha256.Size]byte
	VersionID string
}

// A content-addressed key should normally have exactly one object version. A
// compromised writer can nevertheless place a newer version at the same key
// because Object Lock protects versions, not logical names. Bound recovery of
// the digest-committed version so reads remain available without permitting an
// attacker to turn an unbounded version history into request amplification.
const maxCommittedVersionCandidates = 100
const maxPersistedVersionIDBytes = 1024

var errStoredVersionNotFound = errors.New("no object version matches the committed SHA-256")

// Uploaded sources are capped at 50 MiB. Allow headroom for stamped pages and
// certificates, but never let a corrupted/hostile object-store response drive
// an unbounded allocation in a request or worker.
const maxStoredObjectBytes = 128 << 20

type bucketInitializer interface {
	BucketExists(context.Context, string) (bool, error)
	MakeBucket(context.Context, string, minio.MakeBucketOptions) error
}

func New(ctx context.Context, cfg Config) (*Client, error) {
	policy, err := s3policy.Load(cfg.SSEMode, cfg.SSECKeyFile, cfg.BucketLookup, cfg.UseSSL)
	if err != nil {
		return nil, fmt.Errorf("invalid object storage policy: %w", err)
	}
	mc, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       cfg.UseSSL,
		Region:       cfg.Region,
		BucketLookup: policy.BucketLookupType,
	})
	if err != nil {
		return nil, fmt.Errorf("init minio client: %w", err)
	}

	if err := ensureBucket(ctx, mc, cfg.Bucket, cfg.Region, cfg.RequireObjectLock); err != nil {
		return nil, err
	}
	if cfg.RequireObjectLock {
		enabled, _, _, _, err := mc.GetObjectLockConfig(ctx, cfg.Bucket)
		if err != nil {
			return nil, fmt.Errorf("verify bucket object lock: %w", err)
		}
		if err := validateObjectLockEnabled(enabled); err != nil {
			return nil, fmt.Errorf("bucket %q: %w", cfg.Bucket, err)
		}
	}

	// Apply housekeeping only to explicitly transient objects. Legal evidence
	// retention is NOT a lifecycle expiry rule: production writes and verifies
	// COMPLIANCE-mode Object Lock per evidence object below. Failure to install
	// this optional cleanup policy remains non-fatal.
	if !cfg.SkipTransientLifecycle {
		if err := applyLifecycle(ctx, mc, cfg.Bucket); err != nil {
			slog.Warn("storage: bucket lifecycle apply failed (set s3:PutBucketLifecycle?)",
				"bucket", cfg.Bucket, "err", err)
		}
	}

	return &Client{
		mc:                        mc,
		bucket:                    cfg.Bucket,
		requireEvidenceLock:       cfg.RequireObjectLock,
		writeServerSideEncryption: policy.WriteEncryption,
		readServerSideEncryption:  policy.ReadEncryption,
		sseMode:                   policy.SSEMode,
	}, nil
}

func validateObjectLockEnabled(enabled string) error {
	if enabled != "Enabled" {
		return errors.New("S3 Object Lock must be enabled for production evidence retention")
	}
	return nil
}

// ensureBucket is safe when the server and worker start concurrently. Both can
// observe a missing bucket before either MakeBucket request completes. S3 then
// reports the losing request as already-owned even though the desired
// postcondition has been reached.
//
// Do not ignore BucketAlreadyExists: in S3's global namespace that code means
// another account owns the name. Even BucketAlreadyOwnedByYou requires a second
// authenticated existence check before it is accepted. Every other create/check
// failure remains fatal and is returned to the caller.
func ensureBucket(ctx context.Context, client bucketInitializer, bucket, region string, requireObjectLock ...bool) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("bucket exists check: %w", err)
	}
	if exists {
		return nil
	}

	objectLocking := len(requireObjectLock) > 0 && requireObjectLock[0]
	err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{
		Region:        region,
		ObjectLocking: objectLocking,
	})
	if err == nil {
		return nil
	}
	if !isConcurrentBucketCreate(err) {
		return fmt.Errorf("create bucket: %w", err)
	}

	exists, checkErr := client.BucketExists(ctx, bucket)
	if checkErr != nil {
		return fmt.Errorf("verify bucket after concurrent create: %w", errors.Join(err, checkErr))
	}
	if !exists {
		return fmt.Errorf("create bucket: %w", err)
	}
	return nil
}

func isConcurrentBucketCreate(err error) bool {
	var response minio.ErrorResponse
	if errors.As(err, &response) {
		return response.Code == "BucketAlreadyOwnedByYou"
	}

	// MinIO currently returns ErrorResponse by value, but tolerate compatible
	// wrappers that expose a pointer to the same public error type.
	var responsePointer *minio.ErrorResponse
	if errors.As(err, &responsePointer) && responsePointer != nil {
		return responsePointer.Code == "BucketAlreadyOwnedByYou"
	}
	return false
}

// applyLifecycle installs the cleanup policy for explicitly transient objects.
// It deliberately does not claim to enforce legal retention: S3 lifecycle
// expiration deletes objects after a deadline but cannot prevent early
// deletion. That protection comes from COMPLIANCE-mode Object Lock.
func applyLifecycle(ctx context.Context, mc *minio.Client, bucket string) error {
	cfg := lifecycle.NewConfiguration()
	cfg.Rules = []lifecycle.Rule{
		{
			ID:     "hash-transient-90d",
			Status: "Enabled",
			RuleFilter: lifecycle.Filter{
				Prefix: "transient/",
			},
			Expiration: lifecycle.Expiration{Days: 90},
		},
	}
	return mc.SetBucketLifecycle(ctx, bucket, cfg)
}

// Ping issues a HEAD against the bucket so /health can confirm MinIO
// is reachable + the bucket still exists. Returns the underlying error
// unwrapped so caller-side timeouts surface cleanly.
func (c *Client) Ping(ctx context.Context) error {
	if _, err := c.mc.BucketExists(ctx, c.bucket); err != nil {
		return fmt.Errorf("bucket %q: %w", c.bucket, err)
	}
	return nil
}

// putOpts returns the canonical PutObjectOptions Hash uses for every upload.
// SSE-S3 remains the default; an explicitly configured SSE-C policy supplies
// the same customer-key headers to every write path.
func (c *Client) putOpts(contentType string) minio.PutObjectOptions {
	return minio.PutObjectOptions{
		ContentType:          contentType,
		ServerSideEncryption: c.writeServerSideEncryption,
	}
}

func (c *Client) getOpts(versionID string) minio.GetObjectOptions {
	return minio.GetObjectOptions{
		VersionID:            versionID,
		ServerSideEncryption: c.readServerSideEncryption,
	}
}

func (c *Client) statOpts(versionID string) minio.StatObjectOptions {
	return minio.StatObjectOptions{
		VersionID:            versionID,
		ServerSideEncryption: c.readServerSideEncryption,
	}
}

// EvidenceRetentionDeadline derives the canonical provider timestamp for a
// persisted lifecycle anchor. S3 Object Lock is second-precision; callers must
// persist this exact value before their first irreversible storage mutation and
// reuse it for every retry.
func EvidenceRetentionDeadline(anchor time.Time, years int) time.Time {
	target := anchor.UTC().AddDate(years, 0, 0)
	wholeSecond := target.Truncate(time.Second)
	if target.Equal(wholeSecond) {
		return wholeSecond
	}
	return wholeSecond.Add(time.Second)
}

func canonicalEvidenceRetainUntil(retainUntil time.Time) (time.Time, error) {
	if retainUntil.IsZero() {
		return time.Time{}, errors.New("immutable evidence retain-until is required")
	}
	retainUntil = retainUntil.UTC()
	if retainUntil.Nanosecond() != 0 {
		return time.Time{}, errors.New("immutable evidence retain-until must use whole-second precision")
	}
	return retainUntil, nil
}

func (c *Client) evidencePutOpts(contentType string, retainUntil time.Time) minio.PutObjectOptions {
	opts := c.putOpts(contentType)
	opts.Mode = minio.Compliance
	opts.RetainUntilDate = retainUntil
	return opts
}

// Put uploads bytes and returns the SHA-256 of the contents. It preserves the
// ordinary overwrite semantics used by mutable assets. Legal-artifact callers
// must use PutVersioned so the exact S3 VersionId can be persisted.
func (c *Client) Put(ctx context.Context, key, contentType string, data []byte) (sha [32]byte, err error) {
	sha = sha256.Sum256(data)
	_, err = c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), c.putOpts(contentType))
	if err != nil {
		return sha, fmt.Errorf("put %q: %w", key, err)
	}
	return sha, nil
}

// PutVersioned uploads bytes and returns the exact object identity. Production
// requires the provider to return a non-empty VersionId. Disposable local
// buckets may be unversioned and receive DevelopmentVersionID instead.
func (c *Client) PutVersioned(ctx context.Context, key, contentType string, data []byte) (StoredObject, error) {
	stored := StoredObject{SHA256: sha256.Sum256(data)}
	if existing, err := c.resolveLatestMatchingVersion(ctx, key, stored.SHA256[:]); err == nil {
		return existing, nil
	} else if !errors.Is(err, errStoredVersionNotFound) {
		return stored, fmt.Errorf("reuse versioned object %q: %w", key, err)
	}
	info, err := c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), c.putOpts(contentType))
	if err != nil {
		return stored, fmt.Errorf("put %q: %w", key, err)
	}
	stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
	if err != nil {
		return stored, err
	}
	return stored, nil
}

// PutEvidence uploads a legal-evidence object with the caller's durable,
// whole-second COMPLIANCE deadline, then reads the retention state back. In
// production, a missing permission, unsupported backend, downgraded mode, or
// shortened date is a hard error. Development uses the ordinary encrypted Put
// path so disposable local buckets do not need Object Lock.
func (c *Client) PutEvidence(ctx context.Context, key, contentType string, data []byte, retainUntil time.Time) (sha [32]byte, err error) {
	stored, err := c.PutEvidenceVersioned(ctx, key, contentType, data, retainUntil)
	return stored.SHA256, err
}

// PutEvidenceVersioned is PutEvidence's pin-preserving form. The returned
// VersionID must be committed alongside the digest before any later legal read.
func (c *Client) PutEvidenceVersioned(ctx context.Context, key, contentType string, data []byte, retainUntil time.Time) (StoredObject, error) {
	stored := StoredObject{SHA256: sha256.Sum256(data)}
	retainUntil, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return stored, err
	}
	if existing, err := c.resolveLatestMatchingVersion(ctx, key, stored.SHA256[:]); err == nil {
		if err := c.RetainEvidenceVersion(ctx, key, existing.VersionID, existing.SHA256[:], retainUntil); err != nil {
			return existing, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
		}
		return existing, nil
	} else if !errors.Is(err, errStoredVersionNotFound) {
		return stored, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
	}
	if !c.requireEvidenceLock {
		// The preflight above established that no matching local object exists.
		info, err := c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), c.putOpts(contentType))
		if err != nil {
			return stored, fmt.Errorf("put immutable evidence %q: %w", key, err)
		}
		stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
		return stored, err
	}
	opts := c.evidencePutOpts(contentType, retainUntil)
	info, err := c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		return stored, fmt.Errorf("put immutable evidence %q: %w", key, err)
	}
	stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
	if err != nil {
		return stored, err
	}
	if err := c.verifyEvidenceRetention(ctx, key, stored.VersionID, opts.RetainUntilDate); err != nil {
		return stored, err
	}
	if _, err := c.GetVerifiedVersion(ctx, key, stored.VersionID, stored.SHA256[:]); err != nil {
		return stored, fmt.Errorf("put immutable evidence %q: exact-version readback: %w", key, err)
	}
	return stored, nil
}

func (c *Client) persistableVersionID(key, versionID string) (string, error) {
	trimmed := strings.TrimSpace(versionID)
	if trimmed != "" {
		if len(versionID) > maxPersistedVersionIDBytes {
			return "", fmt.Errorf("put %q: object store returned an oversized version id", key)
		}
		if trimmed == DevelopmentVersionID {
			return "", fmt.Errorf("put %q: object store returned reserved version id", key)
		}
		// VersionId is an opaque provider identity. Never normalize it: even a
		// benign-looking trim would persist a different version than PutObject
		// returned and turn the later exact read into a latest-object fallback.
		return versionID, nil
	}
	if c.requireEvidenceLock {
		return "", fmt.Errorf("put immutable evidence %q: object store returned no version id", key)
	}
	return DevelopmentVersionID, nil
}

// RetainEvidence applies the same immutable retention to an existing source
// object at the moment it becomes part of a sent ceremony.
func (c *Client) RetainEvidence(ctx context.Context, key string, retainUntil time.Time) error {
	if _, err := canonicalEvidenceRetainUntil(retainUntil); err != nil {
		return err
	}
	if !c.requireEvidenceLock || key == "" {
		return nil
	}
	return errors.New("retain immutable evidence: a committed SHA-256 is required")
}

// RetainEvidenceVerified resolves the exact object version whose bytes match
// the database commitment, applies COMPLIANCE retention to that VersionId, and
// reads both the bytes and retention state back by the same VersionId. This is
// deliberately not implemented as "retain latest": a newer shadow version at
// a content-addressed logical key must never strand or replace legal evidence.
func (c *Client) RetainEvidenceVerified(ctx context.Context, key string, expectedSHA256 []byte, retainUntil time.Time) error {
	if _, err := canonicalEvidenceRetainUntil(retainUntil); err != nil {
		return err
	}
	if key == "" {
		return nil
	}
	if len(expectedSHA256) != sha256.Size {
		return errors.New("retain immutable evidence: expected SHA-256 must be 32 bytes")
	}
	if !c.requireEvidenceLock {
		_, err := c.GetVerified(ctx, key, expectedSHA256)
		return err
	}
	_, stored, err := c.ResolveVerifiedLegacy(ctx, key, expectedSHA256)
	if err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	return c.RetainEvidenceVersion(ctx, key, stored.VersionID, expectedSHA256, retainUntil)
}

// RetainEvidenceVersion applies and verifies COMPLIANCE retention on exactly
// one persisted VersionId. It never consults latest state or lists history.
func (c *Client) RetainEvidenceVersion(ctx context.Context, key, versionID string, expectedSHA256 []byte, retainUntil time.Time) error {
	if key == "" {
		return nil
	}
	if len(expectedSHA256) != sha256.Size {
		return errors.New("retain immutable evidence: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(versionID); err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	retainUntil, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if !c.requireEvidenceLock {
		_, err := c.GetVerifiedVersion(ctx, key, versionID, expectedSHA256)
		return err
	}
	// COMPLIANCE retention cannot be shortened. A prior attempt (or legacy
	// buggy retry) may already have installed an equal or later deadline, so
	// read first and avoid an illegal shortening request when the durable target
	// is already satisfied.
	if err := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); err == nil {
		_, err := c.GetVerifiedVersion(ctx, key, versionID, expectedSHA256)
		return err
	}
	mode := minio.Compliance
	if err := c.mc.PutObjectRetention(ctx, c.bucket, key, minio.PutObjectRetentionOptions{
		Mode: &mode, RetainUntilDate: &retainUntil, VersionID: versionID,
	}); err != nil {
		// Another writer may have lengthened the same version between our read and
		// write. Accept the provider error only when a fresh read proves the exact
		// durable minimum is nevertheless satisfied.
		if verifyErr := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); verifyErr == nil {
			_, readErr := c.GetVerifiedVersion(ctx, key, versionID, expectedSHA256)
			return readErr
		}
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if err := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); err != nil {
		return err
	}
	_, err = c.GetVerifiedVersion(ctx, key, versionID, expectedSHA256)
	return err
}

func (c *Client) verifyEvidenceRetention(ctx context.Context, key, versionID string, minimum time.Time) error {
	if c.requireEvidenceLock && versionID == "" {
		return fmt.Errorf("verify immutable evidence %q: object version id is required", key)
	}
	mode, until, err := c.mc.GetObjectRetention(ctx, c.bucket, key, versionID)
	if err != nil {
		return fmt.Errorf("verify immutable evidence %q: %w", key, err)
	}
	if mode == nil || *mode != minio.Compliance || until == nil || until.Before(minimum) {
		return fmt.Errorf("verify immutable evidence %q: expected COMPLIANCE retention through at least %s", key, minimum.UTC().Format(time.RFC3339))
	}
	return nil
}

// PutStream uploads from an io.Reader of known length.
func (c *Client) PutStream(ctx context.Context, key, contentType string, r io.Reader, size int64) error {
	_, err := c.mc.PutObject(ctx, c.bucket, key, r, size, c.putOpts(contentType))
	if err != nil {
		return fmt.Errorf("put stream %q: %w", key, err)
	}
	return nil
}

// Get returns the full object bytes. Caller must keep payloads small (<50MB
// hard cap on uploads).
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := c.mc.GetObject(ctx, c.bucket, key, c.getOpts(""))
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	defer obj.Close()
	body, err := readBounded(obj, maxStoredObjectBytes)
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	return body, nil
}

// GetVerified reads an object and proves that its bytes still match the
// SHA-256 committed by the database or content-addressed key. Legal-artifact
// callers must use this instead of trusting the object store's latest version:
// S3 Object Lock protects old versions from deletion, but an attacker with
// PutObject permission could otherwise place a newer version at the same key.
func (c *Client) GetVerified(ctx context.Context, key string, expectedSHA256 []byte) ([]byte, error) {
	if len(expectedSHA256) != sha256.Size {
		return nil, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	body, _, err := c.ResolveVerifiedLegacy(ctx, key, expectedSHA256)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// GetVerifiedVersion reads and hashes exactly the persisted VersionId. Unlike
// GetVerified it never scans version history, so attacker-created shadow
// versions cannot create an availability dependency on list order or count.
func (c *Client) GetVerifiedVersion(ctx context.Context, key, versionID string, expectedSHA256 []byte) ([]byte, error) {
	if len(expectedSHA256) != sha256.Size {
		return nil, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(versionID); err != nil {
		return nil, fmt.Errorf("verify stored object %q: %w", key, err)
	}
	return c.getVersionVerified(ctx, key, versionID, expectedSHA256)
}

func (c *Client) validatePinnedVersionID(versionID string) error {
	trimmed := strings.TrimSpace(versionID)
	if trimmed == "" {
		return errors.New("persisted object version id is required")
	}
	if len(versionID) > maxPersistedVersionIDBytes {
		return fmt.Errorf("persisted object version id exceeds %d bytes", maxPersistedVersionIDBytes)
	}
	if trimmed == DevelopmentVersionID {
		if versionID != DevelopmentVersionID {
			return errors.New("persisted object version id aliases the reserved development sentinel")
		}
		if c.requireEvidenceLock {
			return errors.New("development object version sentinel is forbidden in production")
		}
		return nil
	}
	return nil
}

// ResolveVerifiedLegacy is the only API allowed to search bounded object
// history by digest. Callers use it solely to migrate records created before
// VersionId pinning, then persist StoredObject.VersionID before continuing.
func (c *Client) ResolveVerifiedLegacy(ctx context.Context, key string, expectedSHA256 []byte) ([]byte, StoredObject, error) {
	body, versionID, err := c.resolveCommittedVersion(ctx, key, expectedSHA256)
	stored := StoredObject{VersionID: versionID}
	if len(expectedSHA256) == sha256.Size {
		copy(stored.SHA256[:], expectedSHA256)
	}
	if err != nil {
		return nil, stored, err
	}
	return body, stored, nil
}

// resolveLatestMatchingVersion is the idempotency check for deterministic
// legal writes. It deliberately inspects only the exact current version: a
// same-digest retry reuses its VersionId, while different bytes create a new
// intentional version. History search remains exclusive to explicitly legacy
// database rows, so a writer cannot make a new write depend on an unbounded
// number of attacker-created shadow versions.
func (c *Client) resolveLatestMatchingVersion(ctx context.Context, key string, expectedSHA256 []byte) (StoredObject, error) {
	stored := StoredObject{}
	if len(expectedSHA256) != sha256.Size {
		return stored, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	copy(stored.SHA256[:], expectedSHA256)
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(""))
	if err != nil {
		if isObjectNotFound(err) {
			return stored, errStoredVersionNotFound
		}
		return stored, fmt.Errorf("stat latest object: %w", err)
	}
	stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
	if err != nil {
		return stored, err
	}
	body, err := c.getObjectVersion(ctx, key, stored.VersionID)
	if err != nil {
		return stored, fmt.Errorf("read latest object version: %w", err)
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], expectedSHA256) != 1 {
		return stored, errStoredVersionNotFound
	}
	return stored, nil
}

// resolveCommittedVersion first pins the current object to the VersionId
// returned by StatObject and reads that exact immutable version. If its digest
// disagrees, it searches a bounded exact-key version history for the authentic
// committed bytes. Production Object Lock requires versioning, so an empty
// VersionId is itself a hard failure there.
func (c *Client) resolveCommittedVersion(ctx context.Context, key string, expectedSHA256 []byte) ([]byte, string, error) {
	if len(expectedSHA256) != sha256.Size {
		return nil, "", errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	var latestVersionID string
	var latestErr error
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(""))
	if err != nil {
		if !isObjectNotFound(err) {
			return nil, "", fmt.Errorf("verify stored object %q: stat latest: %w", key, err)
		}
		latestErr = err
	} else {
		latestVersionID, err = c.persistableVersionID(key, info.VersionID)
		if err != nil {
			return nil, "", fmt.Errorf("verify stored object %q: latest version identity: %w", key, err)
		}
		body, readErr := c.getObjectVersion(ctx, key, latestVersionID)
		if readErr == nil {
			actual := sha256.Sum256(body)
			if subtle.ConstantTimeCompare(actual[:], expectedSHA256) == 1 {
				return body, latestVersionID, nil
			}
			latestErr = errors.New("latest object version has a different SHA-256")
		} else {
			return nil, "", fmt.Errorf("verify stored object %q latest version %q: %w", key, latestVersionID, readErr)
		}
	}

	// Disposable development buckets need not enable versioning. There is no
	// older immutable version to recover in that mode.
	if !c.requireEvidenceLock {
		return nil, "", fmt.Errorf("verify stored object %q: %w: %v", key, errStoredVersionNotFound, latestErr)
	}

	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	versions := c.mc.ListObjects(searchCtx, c.bucket, minio.ListObjectsOptions{
		Prefix: key, Recursive: true, WithVersions: true, MaxKeys: maxCommittedVersionCandidates + 1,
	})
	candidates := 0
	for version := range versions {
		if version.Err != nil {
			return nil, "", fmt.Errorf("verify stored object %q: list versions: %w", key, version.Err)
		}
		if version.Key != key {
			continue
		}
		candidates++
		if candidates > maxCommittedVersionCandidates {
			return nil, "", fmt.Errorf("verify stored object %q: more than %d candidate versions", key, maxCommittedVersionCandidates)
		}
		if version.IsDeleteMarker || version.VersionID == latestVersionID {
			continue
		}
		candidateVersionID, versionErr := c.persistableVersionID(key, version.VersionID)
		if versionErr != nil {
			return nil, "", fmt.Errorf("verify stored object %q: listed version identity: %w", key, versionErr)
		}
		body, readErr := c.getObjectVersion(searchCtx, key, candidateVersionID)
		if readErr != nil {
			return nil, "", fmt.Errorf("verify stored object %q version %q: %w", key, candidateVersionID, readErr)
		}
		actual := sha256.Sum256(body)
		if subtle.ConstantTimeCompare(actual[:], expectedSHA256) == 1 {
			cancel()
			return body, candidateVersionID, nil
		}
	}
	return nil, "", fmt.Errorf("verify stored object %q: %w: %v", key, errStoredVersionNotFound, latestErr)
}

func isObjectNotFound(err error) bool {
	var response minio.ErrorResponse
	if errors.As(err, &response) {
		switch response.Code {
		case "NoSuchKey", "NoSuchObject", "NotFound":
			return true
		}
	}
	var responsePointer *minio.ErrorResponse
	if errors.As(err, &responsePointer) && responsePointer != nil {
		switch responsePointer.Code {
		case "NoSuchKey", "NoSuchObject", "NotFound":
			return true
		}
	}
	return false
}

func (c *Client) getVersionVerified(ctx context.Context, key, versionID string, expectedSHA256 []byte) ([]byte, error) {
	body, err := c.getObjectVersion(ctx, key, versionID)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], expectedSHA256) != 1 {
		return nil, fmt.Errorf("verify stored object %q version %q: SHA-256 mismatch", key, versionID)
	}
	return body, nil
}

func (c *Client) getObjectVersion(ctx context.Context, key, versionID string) ([]byte, error) {
	if versionID == DevelopmentVersionID {
		if c.requireEvidenceLock {
			return nil, fmt.Errorf("get %q: development object version sentinel is forbidden in production", key)
		}
		versionID = ""
	}
	opts := c.getOpts(versionID)
	obj, err := c.mc.GetObject(ctx, c.bucket, key, opts)
	if err != nil {
		return nil, fmt.Errorf("get %q version %q: %w", key, versionID, err)
	}
	defer obj.Close()
	if versionID != "" {
		info, statErr := obj.Stat()
		if statErr != nil {
			return nil, fmt.Errorf("stat %q version %q: %w", key, versionID, statErr)
		}
		if info.VersionID != versionID {
			return nil, fmt.Errorf("get %q version %q: provider returned version %q", key, versionID, info.VersionID)
		}
	}
	body, err := readBounded(obj, maxStoredObjectBytes)
	if err != nil {
		return nil, fmt.Errorf("get %q version %q: %w", key, versionID, err)
	}
	return body, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("invalid negative object-size limit")
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("object exceeds %d-byte safety limit", limit)
	}
	return body, nil
}

// Delete removes an object. Idempotent.
func (c *Client) Delete(ctx context.Context, key string) error {
	if err := c.mc.RemoveObject(ctx, c.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete %q: %w", key, err)
	}
	return nil
}

// PresignGet returns a time-limited URL for a signer or browser to fetch the
// object directly from MinIO without going through the app.
func (c *Client) PresignGet(ctx context.Context, key string, ttl time.Duration) (*url.URL, error) {
	if ttl <= 0 {
		return nil, errors.New("presign ttl must be positive")
	}
	if c.sseMode == s3policy.SSEModeC {
		return nil, errors.New("presigned browser downloads are unavailable with SSE-C; proxy the authenticated download through Hash")
	}
	return c.mc.PresignedGetObject(ctx, c.bucket, key, ttl, nil)
}
