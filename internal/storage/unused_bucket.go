// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

const (
	// BootstrapEstateMarkerKey is outside every application-owned org/ prefix
	// and outside the transient lifecycle namespace. It is deliberately fixed:
	// bootstrap inventory never accepts an arbitrary-prefix allowlist.
	BootstrapEstateMarkerKey            = "_hash/bootstrap-estate/v1"
	BootstrapEstateIntentSchemaVersion  = 1
	BootstrapEstateReceiptSchemaVersion = 1
	bootstrapEstateNonceBytes           = 32
	bootstrapEstateRetentionYears       = 7
)

var bootstrapEstatePayloadPrefix = []byte("hash-bootstrap-storage-estate-v1\n")

// BootstrapEstateIntent is written create-only on the host before any remote
// mutation. Candidate and Storage are non-secret binding objects interpreted
// strictly by CI; Hash preserves them in this shared wire format while
// validating the cryptographic marker fields it consumes.
type BootstrapEstateIntent struct {
	SchemaVersion     int             `json:"schema_version"`
	Candidate         json.RawMessage `json:"candidate"`
	Storage           json.RawMessage `json:"storage"`
	MarkerKey         string          `json:"marker_key"`
	MarkerNonceHex    string          `json:"marker_nonce_hex"`
	MarkerSHA256      string          `json:"marker_sha256"`
	CreatedAt         string          `json:"created_at"`
	RetentionYears    int             `json:"retention_years"`
	MarkerRetainUntil string          `json:"marker_retain_until"`
}

// BootstrapEstateReceipt is the credential-free identity of the sole object
// version allowed in a newly claimed Hash bucket. VersionID is opaque provider
// state; SHA256 commits to the random intent body without exposing credentials
// or SSE-C key material.
type BootstrapEstateReceipt struct {
	SchemaVersion     int    `json:"schema_version"`
	MarkerKey         string `json:"marker_key"`
	MarkerVersionID   string `json:"marker_version_id"`
	MarkerSHA256      string `json:"marker_sha256"`
	MarkerRetainUntil string `json:"marker_retain_until"`
}

// BootstrapEstateReference is one canonical database-to-provider identity used
// only for candidate-cutover crash recovery. Empty VersionID/SHA256 are allowed
// solely for existence-only mutable assets; the exhaustive provider inventory
// still requires exactly one ordinary version for that key.
type BootstrapEstateReference struct {
	Key           string
	VersionID     string
	SHA256        []byte
	LegalEvidence bool
	RetainUntil   time.Time
}

func validateCanonicalSHA256(value, field string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return result, fmt.Errorf("%s must be an exact lowercase SHA-256", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		clear(decoded)
		return result, fmt.Errorf("%s must be an exact lowercase SHA-256", field)
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func parseBootstrapEstateRetainUntil(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("bootstrap estate marker retention must be canonical whole-second UTC RFC3339")
	}
	return parsed, nil
}

func validateBindingObject(raw json.RawMessage, name string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !json.Valid(trimmed) {
		return fmt.Errorf("bootstrap estate intent %s binding must be a JSON object", name)
	}
	return nil
}

func (i BootstrapEstateIntent) Validate() error {
	if i.SchemaVersion != BootstrapEstateIntentSchemaVersion {
		return errors.New("unsupported bootstrap estate intent schema")
	}
	if err := validateBindingObject(i.Candidate, "candidate"); err != nil {
		return err
	}
	if err := validateBindingObject(i.Storage, "storage"); err != nil {
		return err
	}
	if i.MarkerKey != BootstrapEstateMarkerKey {
		return errors.New("bootstrap estate intent has a non-canonical marker key")
	}
	if len(i.MarkerNonceHex) != bootstrapEstateNonceBytes*2 || i.MarkerNonceHex != strings.ToLower(i.MarkerNonceHex) {
		return errors.New("bootstrap estate intent nonce must be exactly 32 lowercase hexadecimal bytes")
	}
	nonce, err := hex.DecodeString(i.MarkerNonceHex)
	if err != nil || len(nonce) != bootstrapEstateNonceBytes {
		clear(nonce)
		return errors.New("bootstrap estate intent nonce must be exactly 32 lowercase hexadecimal bytes")
	}
	defer clear(nonce)
	expected, err := validateCanonicalSHA256(i.MarkerSHA256, "bootstrap estate intent marker_sha256")
	if err != nil {
		return err
	}
	payload := make([]byte, len(bootstrapEstatePayloadPrefix)+len(nonce))
	copy(payload, bootstrapEstatePayloadPrefix)
	copy(payload[len(bootstrapEstatePayloadPrefix):], nonce)
	actual := sha256.Sum256(payload)
	clear(payload)
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		return errors.New("bootstrap estate intent marker SHA-256 does not match its canonical payload")
	}
	createdAt, err := parseBootstrapEstateRetainUntil(i.CreatedAt)
	if err != nil {
		return errors.New("bootstrap estate intent creation time must be canonical whole-second UTC RFC3339")
	}
	if i.RetentionYears != bootstrapEstateRetentionYears {
		return errors.New("bootstrap estate intent retention horizon does not match Hash evidence policy")
	}
	retainUntil, err := parseBootstrapEstateRetainUntil(i.MarkerRetainUntil)
	if err != nil {
		return err
	}
	if !retainUntil.Equal(EvidenceRetentionDeadline(createdAt, i.RetentionYears)) {
		return errors.New("bootstrap estate marker retention deadline does not match the canonical evidence horizon")
	}
	return nil
}

func (i BootstrapEstateIntent) payload() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(i.MarkerNonceHex)
	if err != nil {
		return nil, errors.New("decode bootstrap estate marker nonce")
	}
	defer clear(nonce)
	payload := make([]byte, len(bootstrapEstatePayloadPrefix)+len(nonce))
	copy(payload, bootstrapEstatePayloadPrefix)
	copy(payload[len(bootstrapEstatePayloadPrefix):], nonce)
	return payload, nil
}

func (r BootstrapEstateReceipt) Validate() error {
	if r.SchemaVersion != BootstrapEstateReceiptSchemaVersion {
		return errors.New("unsupported bootstrap estate receipt schema")
	}
	if r.MarkerKey != BootstrapEstateMarkerKey {
		return errors.New("bootstrap estate receipt has a non-canonical marker key")
	}
	if r.MarkerVersionID == "" || r.MarkerVersionID != strings.TrimSpace(r.MarkerVersionID) ||
		len(r.MarkerVersionID) > maxPersistedVersionIDBytes ||
		strings.ContainsAny(r.MarkerVersionID, "\x00\r\n") || r.MarkerVersionID == DevelopmentVersionID {
		return errors.New("bootstrap estate receipt has an invalid provider VersionId")
	}
	if _, err := validateCanonicalSHA256(r.MarkerSHA256, "bootstrap estate receipt marker_sha256"); err != nil {
		return err
	}
	if _, err := parseBootstrapEstateRetainUntil(r.MarkerRetainUntil); err != nil {
		return err
	}
	return nil
}

func (r BootstrapEstateReceipt) matchesIntent(intent BootstrapEstateIntent) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if r.MarkerKey != intent.MarkerKey || r.MarkerSHA256 != intent.MarkerSHA256 ||
		r.MarkerRetainUntil != intent.MarkerRetainUntil {
		return errors.New("bootstrap estate receipt does not match its durable pre-PUT intent")
	}
	return nil
}

func (r BootstrapEstateReceipt) digest() ([sha256.Size]byte, error) {
	if err := r.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	return validateCanonicalSHA256(r.MarkerSHA256, "bootstrap estate receipt marker_sha256")
}

type unusedBucketLister interface {
	ListObjects(context.Context, string, minio.ListObjectsOptions) <-chan minio.ObjectInfo
	ListIncompleteUploads(context.Context, string, string, bool) <-chan minio.ObjectMultipartInfo
}

type bootstrapEstateInventory struct {
	versionCount int
	firstVersion minio.ObjectInfo
	hasUpload    bool
	providerErr  bool
}

// scanBootstrapEstateInventory drains both provider-paginated inventories even
// after seeing debris. A first-install decision is never made from one page or
// from the first conveniently matching key.
func scanBootstrapEstateInventory(ctx context.Context, lister unusedBucketLister, bucket string) (bootstrapEstateInventory, error) {
	var result bootstrapEstateInventory
	if err := ctx.Err(); err != nil {
		return result, errors.New("bootstrap estate inventory context is not usable")
	}
	if lister == nil || bucket == "" {
		return result, errors.New("bootstrap estate inventory requires an initialized provider and bucket")
	}
	inventoryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for item := range lister.ListObjects(inventoryCtx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		if item.Err != nil {
			result.providerErr = true
			continue
		}
		result.versionCount++
		if result.versionCount == 1 {
			result.firstVersion = item
		}
	}
	if err := inventoryCtx.Err(); err != nil {
		return result, errors.New("list all bootstrap estate object versions and delete markers did not complete")
	}
	for item := range lister.ListIncompleteUploads(inventoryCtx, bucket, "", true) {
		if item.Err != nil {
			result.providerErr = true
			continue
		}
		result.hasUpload = true
	}
	if err := inventoryCtx.Err(); err != nil {
		return result, errors.New("list all bootstrap estate incomplete multipart uploads did not complete")
	}
	if result.providerErr {
		return result, errors.New("bootstrap estate provider inventory returned an error")
	}
	if result.hasUpload {
		return result, errors.New("bootstrap estate contains an incomplete multipart upload")
	}
	return result, nil
}

func checkBootstrapEstateInventory(ctx context.Context, lister unusedBucketLister, bucket string, expected *BootstrapEstateReceipt) error {
	if expected != nil {
		if err := expected.Validate(); err != nil {
			return err
		}
	}
	inventory, err := scanBootstrapEstateInventory(ctx, lister, bucket)
	if err != nil {
		return err
	}
	if expected == nil {
		if inventory.versionCount != 0 {
			return errors.New("unclaimed bucket contains an object version or delete marker")
		}
		return nil
	}
	item := inventory.firstVersion
	if inventory.versionCount != 1 || item.IsDeleteMarker || item.Key != expected.MarkerKey ||
		item.VersionID != expected.MarkerVersionID {
		return errors.New("claimed bucket contains missing, changed, or additional durable object state")
	}
	return nil
}

func pendingBootstrapEstateVersion(ctx context.Context, lister unusedBucketLister, bucket string, intent BootstrapEstateIntent) (string, bool, error) {
	if err := intent.Validate(); err != nil {
		return "", false, err
	}
	inventory, err := scanBootstrapEstateInventory(ctx, lister, bucket)
	if err != nil {
		return "", false, err
	}
	if inventory.versionCount == 0 {
		return "", false, nil
	}
	item := inventory.firstVersion
	if inventory.versionCount != 1 || item.IsDeleteMarker || item.Key != intent.MarkerKey ||
		item.VersionID == "" || item.VersionID != strings.TrimSpace(item.VersionID) ||
		len(item.VersionID) > maxPersistedVersionIDBytes || strings.ContainsAny(item.VersionID, "\x00\r\n") ||
		item.VersionID == DevelopmentVersionID {
		return "", false, errors.New("pending bootstrap estate contains changed or additional durable object state")
	}
	return item.VersionID, true, nil
}

type bootstrapEstateOperations interface {
	PendingInventory(context.Context, BootstrapEstateIntent) (string, bool, error)
	ExactInventory(context.Context, BootstrapEstateReceipt) error
	PutMarker(context.Context, BootstrapEstateIntent, []byte) (string, error)
	VerifyExactMarker(context.Context, BootstrapEstateReceipt) error
	ProtectExactMarker(context.Context, BootstrapEstateReceipt) error
	VerifyExactMarkerProtection(context.Context, BootstrapEstateReceipt) error
}

type clientBootstrapEstateOperations struct{ client *Client }

func (o clientBootstrapEstateOperations) PendingInventory(ctx context.Context, intent BootstrapEstateIntent) (string, bool, error) {
	return pendingBootstrapEstateVersion(ctx, o.client.mc, o.client.bucket, intent)
}

func (o clientBootstrapEstateOperations) ExactInventory(ctx context.Context, receipt BootstrapEstateReceipt) error {
	return checkBootstrapEstateInventory(ctx, o.client.mc, o.client.bucket, &receipt)
}

func (o clientBootstrapEstateOperations) PutMarker(ctx context.Context, intent BootstrapEstateIntent, payload []byte) (string, error) {
	retainUntil, err := parseBootstrapEstateRetainUntil(intent.MarkerRetainUntil)
	if err != nil {
		return "", err
	}
	info, err := o.client.mc.PutObject(ctx, o.client.bucket, intent.MarkerKey, bytes.NewReader(payload), int64(len(payload)), o.client.evidencePutOpts("application/octet-stream", retainUntil))
	if err != nil {
		return "", fmt.Errorf("write COMPLIANCE-protected bootstrap estate marker: %w", err)
	}
	versionID := info.VersionID
	probe := BootstrapEstateReceipt{
		SchemaVersion:     BootstrapEstateReceiptSchemaVersion,
		MarkerKey:         intent.MarkerKey,
		MarkerVersionID:   versionID,
		MarkerSHA256:      intent.MarkerSHA256,
		MarkerRetainUntil: intent.MarkerRetainUntil,
	}
	if err := probe.Validate(); err != nil {
		return "", fmt.Errorf("write bootstrap estate marker identity: %w", err)
	}
	return versionID, nil
}

func (o clientBootstrapEstateOperations) VerifyExactMarker(ctx context.Context, receipt BootstrapEstateReceipt) error {
	digest, err := receipt.digest()
	if err != nil {
		return err
	}
	body, err := o.client.GetVerifiedVersion(ctx, receipt.MarkerKey, receipt.MarkerVersionID, digest[:])
	if err != nil {
		return fmt.Errorf("exact-version read bootstrap estate marker: %w", err)
	}
	if len(body) != len(bootstrapEstatePayloadPrefix)+bootstrapEstateNonceBytes || !bytes.HasPrefix(body, bootstrapEstatePayloadPrefix) {
		return errors.New("exact-version bootstrap estate marker has an invalid canonical body")
	}
	stat, err := o.client.mc.StatObject(ctx, o.client.bucket, receipt.MarkerKey, o.client.statOpts(receipt.MarkerVersionID))
	if err != nil {
		return fmt.Errorf("exact-version HEAD bootstrap estate marker: %w", err)
	}
	if stat.VersionID != receipt.MarkerVersionID || stat.Size != int64(len(body)) {
		return errors.New("exact-version HEAD bootstrap estate marker returned changed identity or size")
	}
	if err := o.client.verifyDataPlaneEncryption(ctx, receipt.MarkerKey, receipt.MarkerVersionID, stat); err != nil {
		return fmt.Errorf("bootstrap estate marker encryption proof: %w", err)
	}
	return nil
}

func (o clientBootstrapEstateOperations) ProtectExactMarker(ctx context.Context, receipt BootstrapEstateReceipt) error {
	digest, err := receipt.digest()
	if err != nil {
		return err
	}
	retainUntil, err := parseBootstrapEstateRetainUntil(receipt.MarkerRetainUntil)
	if err != nil {
		return err
	}
	return o.client.RetainEvidenceVersion(ctx, receipt.MarkerKey, receipt.MarkerVersionID, digest[:], retainUntil)
}

func (o clientBootstrapEstateOperations) VerifyExactMarkerProtection(ctx context.Context, receipt BootstrapEstateReceipt) error {
	retainUntil, err := parseBootstrapEstateRetainUntil(receipt.MarkerRetainUntil)
	if err != nil {
		return err
	}
	digest, err := receipt.digest()
	if err != nil {
		return err
	}
	return o.client.VerifyRetentionConformance(ctx, receipt.MarkerKey, receipt.MarkerVersionID, digest[:], retainUntil)
}

func bootstrapEstateReceiptFor(intent BootstrapEstateIntent, versionID string) BootstrapEstateReceipt {
	return BootstrapEstateReceipt{
		SchemaVersion:     BootstrapEstateReceiptSchemaVersion,
		MarkerKey:         intent.MarkerKey,
		MarkerVersionID:   versionID,
		MarkerSHA256:      intent.MarkerSHA256,
		MarkerRetainUntil: intent.MarkerRetainUntil,
	}
}

// ReconcileBootstrapEstate claims or safely resumes a pre-intent-bound
// first-install bucket. Empty means PUT the exact intended bytes; one exact
// marker means a prior process may have died after provider commit. Every other
// state fails. The exact version is read/HEADed with runtime encryption and
// COMPLIANCE-protected before the final receipt is created, then inventoried
// again to catch the unavoidable LIST/PUT race.
func (c *Client) ReconcileBootstrapEstate(ctx context.Context, intent BootstrapEstateIntent, persist func(BootstrapEstateReceipt) error) (BootstrapEstateReceipt, error) {
	if c == nil || c.mc == nil || c.bucket == "" || !c.requireEvidenceLock {
		return BootstrapEstateReceipt{}, errors.New("bootstrap estate claim requires initialized production Object-Lock storage")
	}
	if persist == nil {
		return BootstrapEstateReceipt{}, errors.New("bootstrap estate claim requires durable receipt persistence")
	}
	return reconcileBootstrapEstate(ctx, clientBootstrapEstateOperations{client: c}, intent, persist)
}

func reconcileBootstrapEstate(ctx context.Context, operations bootstrapEstateOperations, intent BootstrapEstateIntent, persist func(BootstrapEstateReceipt) error) (BootstrapEstateReceipt, error) {
	if operations == nil || persist == nil {
		return BootstrapEstateReceipt{}, errors.New("bootstrap estate claim requires provider operations and durable receipt persistence")
	}
	if err := intent.Validate(); err != nil {
		return BootstrapEstateReceipt{}, err
	}
	versionID, present, err := operations.PendingInventory(ctx, intent)
	if err != nil {
		return BootstrapEstateReceipt{}, fmt.Errorf("inventory pre-receipt bootstrap estate: %w", err)
	}
	if !present {
		payload, err := intent.payload()
		if err != nil {
			return BootstrapEstateReceipt{}, err
		}
		versionID, err = operations.PutMarker(ctx, intent, payload)
		clear(payload)
		if err != nil {
			return BootstrapEstateReceipt{}, err
		}
	}
	receipt := bootstrapEstateReceiptFor(intent, versionID)
	if err := receipt.matchesIntent(intent); err != nil {
		return receipt, err
	}
	if err := operations.VerifyExactMarker(ctx, receipt); err != nil {
		return receipt, err
	}
	if err := operations.ProtectExactMarker(ctx, receipt); err != nil {
		return receipt, fmt.Errorf("protect exact bootstrap estate marker: %w", err)
	}
	if err := persist(receipt); err != nil {
		return receipt, fmt.Errorf("persist final bootstrap estate receipt: %w", err)
	}
	if err := operations.ExactInventory(ctx, receipt); err != nil {
		return receipt, fmt.Errorf("prove exclusive bucket state after estate claim: %w", err)
	}
	if err := operations.VerifyExactMarkerProtection(ctx, receipt); err != nil {
		return receipt, fmt.Errorf("verify exact bootstrap estate marker protection: %w", err)
	}
	return receipt, nil
}

// VerifyBootstrapEstate is the final-receipt retry and last-pre-writer gate.
// It exhaustively inventories first, then exact-reads/HEADs with current runtime
// encryption and independently reads back the exact COMPLIANCE protection.
func (c *Client) VerifyBootstrapEstate(ctx context.Context, intent BootstrapEstateIntent, receipt BootstrapEstateReceipt) error {
	if c == nil || c.mc == nil || c.bucket == "" || !c.requireEvidenceLock {
		return errors.New("bootstrap estate verification requires initialized production Object-Lock storage")
	}
	return verifyBootstrapEstate(ctx, clientBootstrapEstateOperations{client: c}, intent, receipt)
}

// VerifyBootstrapEstateMarker verifies only the exact receipt-bound control
// version. It is intentionally narrower than VerifyBootstrapEstate and is
// permitted only after the deployment has durably entered candidate-cutover:
// at that point legitimate, database-referenced application objects may exist,
// so a whole-bucket exact-one assertion would reject a safe crash recovery.
// Callers must pair this with the canonical database/audit/object inventory.
func (c *Client) VerifyBootstrapEstateMarker(ctx context.Context, intent BootstrapEstateIntent, receipt BootstrapEstateReceipt) error {
	if c == nil || c.mc == nil || c.bucket == "" || !c.requireEvidenceLock {
		return errors.New("bootstrap estate marker verification requires initialized production Object-Lock storage")
	}
	return verifyBootstrapEstateMarker(ctx, clientBootstrapEstateOperations{client: c}, intent, receipt)
}

type bootstrapEstateReferencedVersion struct {
	versionID    string
	lastModified time.Time
}

func validateBootstrapEstateReference(reference BootstrapEstateReference) error {
	if reference.Key == "" || reference.Key != strings.TrimSpace(reference.Key) ||
		strings.ContainsAny(reference.Key, "\x00\r\n\t") || reference.Key == BootstrapEstateMarkerKey {
		return errors.New("candidate-cutover storage inventory contains an invalid application key")
	}
	if reference.VersionID != "" && (reference.VersionID != strings.TrimSpace(reference.VersionID) ||
		len(reference.VersionID) > maxPersistedVersionIDBytes || strings.ContainsAny(reference.VersionID, "\x00\r\n") ||
		reference.VersionID == DevelopmentVersionID) {
		return errors.New("candidate-cutover storage inventory contains an invalid provider VersionId")
	}
	if len(reference.SHA256) != 0 && len(reference.SHA256) != sha256.Size {
		return errors.New("candidate-cutover storage inventory contains an invalid SHA-256")
	}
	if reference.LegalEvidence {
		if reference.VersionID == "" {
			return errors.New("candidate-cutover legal evidence lacks an exact provider VersionId")
		}
		if _, err := canonicalEvidenceRetainUntil(reference.RetainUntil); err != nil {
			return errors.New("candidate-cutover legal evidence lacks its exact database retention deadline")
		}
	} else if !reference.RetainUntil.IsZero() {
		return errors.New("candidate-cutover mutable object unexpectedly carries a retention deadline")
	}
	return nil
}

func checkBootstrapEstateReferencedInventory(ctx context.Context, lister unusedBucketLister, bucket string, receipt BootstrapEstateReceipt, references []BootstrapEstateReference) (map[string]bootstrapEstateReferencedVersion, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	expected := make(map[string]BootstrapEstateReference, len(references))
	for _, reference := range references {
		if err := validateBootstrapEstateReference(reference); err != nil {
			return nil, err
		}
		if _, duplicate := expected[reference.Key]; duplicate {
			return nil, errors.New("candidate-cutover storage inventory contains a duplicate application key")
		}
		reference.SHA256 = append([]byte(nil), reference.SHA256...)
		expected[reference.Key] = reference
	}
	if err := ctx.Err(); err != nil || lister == nil || bucket == "" {
		return nil, errors.New("candidate-cutover provider inventory context is not usable")
	}

	resolved := make(map[string]bootstrapEstateReferencedVersion, len(expected))
	markerCount := 0
	unsafeState := false
	providerErr := false
	for item := range lister.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		if item.Err != nil {
			providerErr = true
			continue
		}
		if item.Key == receipt.MarkerKey {
			markerCount++
			if item.IsDeleteMarker || item.VersionID != receipt.MarkerVersionID {
				unsafeState = true
			}
			continue
		}
		reference, ok := expected[item.Key]
		if !ok || item.IsDeleteMarker || item.VersionID == "" || item.VersionID != strings.TrimSpace(item.VersionID) ||
			len(item.VersionID) > maxPersistedVersionIDBytes || strings.ContainsAny(item.VersionID, "\x00\r\n") ||
			item.VersionID == DevelopmentVersionID {
			unsafeState = true
			continue
		}
		if reference.VersionID != "" && reference.VersionID != item.VersionID {
			unsafeState = true
			continue
		}
		if _, duplicate := resolved[item.Key]; duplicate {
			unsafeState = true
			continue
		}
		resolved[item.Key] = bootstrapEstateReferencedVersion{versionID: item.VersionID, lastModified: item.LastModified}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("candidate-cutover object-version inventory did not complete")
	}
	for upload := range lister.ListIncompleteUploads(ctx, bucket, "", true) {
		if upload.Err != nil {
			providerErr = true
			continue
		}
		unsafeState = true
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("candidate-cutover multipart inventory did not complete")
	}
	if providerErr {
		return nil, errors.New("candidate-cutover provider inventory returned an error")
	}
	if unsafeState || markerCount != 1 || len(resolved) != len(expected) {
		return nil, errors.New("candidate-cutover bucket contains missing, changed, additional, deleted, or incomplete durable state")
	}
	return resolved, nil
}

// VerifyBootstrapEstateWithReferences is the phase-aware recovery gate after a
// candidate was previously permitted to write. It does not demand an empty
// bucket. Instead, it permits exactly the retained marker plus exactly one
// provider version per canonical database reference, and rejects every orphan
// version, delete marker, transient key, multipart upload, or provider error.
func (c *Client) VerifyBootstrapEstateWithReferences(ctx context.Context, intent BootstrapEstateIntent, receipt BootstrapEstateReceipt, references []BootstrapEstateReference) error {
	if c == nil || c.mc == nil || c.bucket == "" || !c.requireEvidenceLock {
		return errors.New("candidate-cutover estate verification requires initialized production Object-Lock storage")
	}
	if err := receipt.matchesIntent(intent); err != nil {
		return err
	}
	resolved, err := checkBootstrapEstateReferencedInventory(ctx, c.mc, c.bucket, receipt, references)
	if err != nil {
		return err
	}
	if err := verifyBootstrapEstateMarker(ctx, clientBootstrapEstateOperations{client: c}, intent, receipt); err != nil {
		return err
	}
	for _, reference := range references {
		provider := resolved[reference.Key]
		var body []byte
		if len(reference.SHA256) == sha256.Size {
			body, err = c.GetVerifiedVersion(ctx, reference.Key, provider.versionID, reference.SHA256)
		} else {
			body, err = c.getObjectVersion(ctx, reference.Key, provider.versionID)
		}
		clear(body)
		if err != nil {
			return errors.New("candidate-cutover exact-version application object readback failed")
		}
		stat, err := c.mc.StatObject(ctx, c.bucket, reference.Key, c.statOpts(provider.versionID))
		if err != nil || stat.VersionID != provider.versionID {
			return errors.New("candidate-cutover exact-version application object HEAD failed")
		}
		if reference.LegalEvidence {
			if err := c.verifyEvidenceRetention(ctx, reference.Key, provider.versionID, reference.RetainUntil); err != nil {
				return errors.New("candidate-cutover legal evidence retention proof failed")
			}
		}
		if err := c.verifyDataPlaneEncryption(ctx, reference.Key, provider.versionID, stat); err != nil {
			return errors.New("candidate-cutover exact-version application object encryption proof failed")
		}
	}
	after, err := checkBootstrapEstateReferencedInventory(ctx, c.mc, c.bucket, receipt, references)
	if err != nil || len(after) != len(resolved) {
		return errors.New("candidate-cutover provider inventory changed during exact-version verification")
	}
	for key, before := range resolved {
		if current, ok := after[key]; !ok || current.versionID != before.versionID {
			return errors.New("candidate-cutover provider inventory changed during exact-version verification")
		}
	}
	return nil
}

func verifyBootstrapEstate(ctx context.Context, operations bootstrapEstateOperations, intent BootstrapEstateIntent, receipt BootstrapEstateReceipt) error {
	if operations == nil {
		return errors.New("bootstrap estate verification requires provider operations")
	}
	if err := receipt.matchesIntent(intent); err != nil {
		return err
	}
	if err := operations.ExactInventory(ctx, receipt); err != nil {
		return fmt.Errorf("inventory receipt-bound bootstrap estate: %w", err)
	}
	return verifyBootstrapEstateMarker(ctx, operations, intent, receipt)
}

func verifyBootstrapEstateMarker(ctx context.Context, operations bootstrapEstateOperations, intent BootstrapEstateIntent, receipt BootstrapEstateReceipt) error {
	if operations == nil {
		return errors.New("bootstrap estate marker verification requires provider operations")
	}
	if err := receipt.matchesIntent(intent); err != nil {
		return err
	}
	if err := operations.VerifyExactMarker(ctx, receipt); err != nil {
		return err
	}
	if err := operations.VerifyExactMarkerProtection(ctx, receipt); err != nil {
		return fmt.Errorf("verify exact bootstrap estate marker protection: %w", err)
	}
	return nil
}
