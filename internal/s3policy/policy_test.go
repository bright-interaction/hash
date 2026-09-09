// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package s3policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

func TestLoadDefaultsPreserveMinIOPolicy(t *testing.T) {
	policy, err := Load("", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if policy.SSEMode != SSEModeS3 || policy.WriteEncryption == nil ||
		policy.WriteEncryption.Type() != encrypt.S3 {
		t.Fatal("default encryption policy is not SSE-S3")
	}
	if policy.ReadEncryption != nil {
		t.Fatal("SSE-S3 GET/HEAD policy must be nil")
	}
	if policy.BucketLookup != BucketLookupAuto || policy.BucketLookupType != minio.BucketLookupAuto {
		t.Fatalf("default bucket lookup = %q/%v, want auto", policy.BucketLookup, policy.BucketLookupType)
	}
}

func TestLoadMapsBucketLookupModes(t *testing.T) {
	for _, test := range []struct {
		value string
		want  minio.BucketLookupType
	}{
		{BucketLookupAuto, minio.BucketLookupAuto},
		{BucketLookupPath, minio.BucketLookupPath},
		{BucketLookupDNS, minio.BucketLookupDNS},
	} {
		policy, err := Load(SSEModeS3, "", "", test.value, true)
		if err != nil {
			t.Fatalf("Load(%q): %v", test.value, err)
		}
		if policy.BucketLookupType != test.want {
			t.Fatalf("Load(%q) bucket lookup = %v, want %v", test.value, policy.BucketLookupType, test.want)
		}
	}
	if _, err := Load(SSEModeS3, "", "", "virtual", true); err == nil {
		t.Fatal("unknown bucket lookup mode was accepted")
	}
}

func TestLoadSSECRequiresTLSAndExactRawKeyFile(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "key")
	validKey := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(validPath, validKey, 0o600); err != nil {
		t.Fatal(err)
	}
	validSum := sha256.Sum256(validKey)
	validDigest := hex.EncodeToString(validSum[:])

	policy, err := Load(SSEModeC, validPath, validDigest, BucketLookupPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if policy.WriteEncryption == nil || policy.WriteEncryption.Type() != encrypt.SSEC ||
		policy.ReadEncryption == nil || policy.ReadEncryption.Type() != encrypt.SSEC {
		t.Fatal("SSE-C policy did not produce SSEC write and read encryption")
	}
	if _, err := Load(SSEModeC, validPath, validDigest, BucketLookupPath, false); err == nil || !strings.Contains(err.Error(), "requires HASH_S3_USE_SSL=true") {
		t.Fatalf("plaintext SSE-C endpoint accepted: %v", err)
	}
	if _, err := Load(SSEModeC, "", validDigest, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("missing SSE-C key path accepted: %v", err)
	}
	if _, err := Load(SSEModeC, "relative/key", validDigest, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "absolute in-container path") {
		t.Fatalf("relative SSE-C key path accepted: %v", err)
	}
	if _, err := Load(SSEModeS3, validPath, "", BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("unused SSE-C key path accepted under SSE-S3: %v", err)
	}
	if _, err := Load(SSEModeS3, "", validDigest, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "HASH_S3_SSE_C_KEY_SHA256 must be empty") {
		t.Fatalf("unused SSE-C key digest accepted under SSE-S3: %v", err)
	}
	for _, digest := range []string{"", strings.Repeat("0", 63), strings.ToUpper(validDigest), strings.Repeat("z", 64)} {
		if _, err := Load(SSEModeC, validPath, digest, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "exact lowercase 64-character SHA-256") {
			t.Fatalf("invalid SSE-C key digest %q accepted: %v", digest, err)
		}
	}
	wrongDigest := strings.Repeat("0", 64)
	if _, err := Load(SSEModeC, validPath, wrongDigest, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("SSE-C key replacement was accepted against pinned digest: %v", err)
	}

	for _, test := range []struct {
		name     string
		contents []byte
		want     string
	}{
		{name: "short", contents: []byte("0123456789abcdef0123456789abc"), want: "exactly 32 raw bytes"},
		{name: "newline", contents: []byte("0123456789abcdef0123456789abcdef\n"), want: "exactly 32 raw bytes"},
		{name: "hex-encoded", contents: []byte(strings.Repeat("00", 32)), want: "exactly 32 raw bytes"},
		{name: "all-zero", contents: make([]byte, 32), want: "all-identical-byte values are rejected"},
		{name: "all-identical", contents: []byte(strings.Repeat("x", 32)), want: "all-identical-byte values are rejected"},
	} {
		path := filepath.Join(dir, test.name)
		if err := os.WriteFile(path, test.contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(SSEModeC, path, validDigest, BucketLookupAuto, true); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("weak or malformed key file accepted: %v", err)
		} else if strings.Contains(err.Error(), string(test.contents)) {
			t.Fatal("SSE-C key contents leaked through validation error")
		}
	}
}

func TestLoadNeverIncludesSSECContentsInErrors(t *testing.T) {
	secret := "do-not-render-this-secret-value"
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(SSEModeC, path, strings.Repeat("0", 64), BucketLookupAuto, true)
	if err == nil {
		t.Fatal("wrong-length key unexpectedly accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("SSE-C key contents leaked through validation error")
	}
}

func TestLoadTreatsSSECKeyValueAsOpaquePathInErrors(t *testing.T) {
	// This simulates the dangerous operator mistake of assigning key material
	// itself to *_KEY_FILE. os.PathError normally echoes its filename.
	mistakenValue := strings.Repeat("sensitive-customer-key-value", 8)
	mistakenPath := filepath.Join(string(os.PathSeparator), mistakenValue)
	_, err := Load(SSEModeC, mistakenPath, strings.Repeat("0", 64), BucketLookupAuto, true)
	if err == nil {
		t.Fatal("nonexistent key path unexpectedly accepted")
	}
	if strings.Contains(err.Error(), mistakenValue) || strings.Contains(err.Error(), mistakenPath) {
		t.Fatal("misplaced SSE-C key material leaked through path error")
	}
}
