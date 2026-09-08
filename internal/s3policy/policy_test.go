// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package s3policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

func TestLoadDefaultsPreserveMinIOPolicy(t *testing.T) {
	policy, err := Load("", "", "", false)
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
		policy, err := Load(SSEModeS3, "", test.value, true)
		if err != nil {
			t.Fatalf("Load(%q): %v", test.value, err)
		}
		if policy.BucketLookupType != test.want {
			t.Fatalf("Load(%q) bucket lookup = %v, want %v", test.value, policy.BucketLookupType, test.want)
		}
	}
	if _, err := Load(SSEModeS3, "", "virtual", true); err == nil {
		t.Fatal("unknown bucket lookup mode was accepted")
	}
}

func TestLoadSSECRequiresTLSAndExactRawKeyFile(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "key")
	if err := os.WriteFile(validPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	policy, err := Load(SSEModeC, validPath, BucketLookupPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if policy.WriteEncryption == nil || policy.WriteEncryption.Type() != encrypt.SSEC ||
		policy.ReadEncryption == nil || policy.ReadEncryption.Type() != encrypt.SSEC {
		t.Fatal("SSE-C policy did not produce SSEC write and read encryption")
	}
	if _, err := Load(SSEModeC, validPath, BucketLookupPath, false); err == nil || !strings.Contains(err.Error(), "requires HASH_S3_USE_SSL=true") {
		t.Fatalf("plaintext SSE-C endpoint accepted: %v", err)
	}
	if _, err := Load(SSEModeC, "", BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("missing SSE-C key path accepted: %v", err)
	}
	if _, err := Load(SSEModeC, "relative/key", BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "absolute in-container path") {
		t.Fatalf("relative SSE-C key path accepted: %v", err)
	}
	if _, err := Load(SSEModeS3, validPath, BucketLookupPath, true); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("unused SSE-C key path accepted under SSE-S3: %v", err)
	}

	for _, test := range []struct {
		name     string
		contents []byte
	}{
		{name: "short", contents: []byte("0123456789abcdef0123456789abc")},
		{name: "newline", contents: []byte("0123456789abcdef0123456789abcdef\n")},
		{name: "hex-encoded", contents: []byte(strings.Repeat("00", 32))},
	} {
		path := filepath.Join(dir, test.name)
		if err := os.WriteFile(path, test.contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(SSEModeC, path, BucketLookupAuto, true); err == nil || !strings.Contains(err.Error(), "exactly 32 raw bytes") {
			t.Fatalf("%d-byte/non-raw key file accepted: %v", len(test.contents), err)
		}
	}
}

func TestLoadNeverIncludesSSECContentsInErrors(t *testing.T) {
	secret := "do-not-render-this-secret-value"
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(SSEModeC, path, BucketLookupAuto, true)
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
	_, err := Load(SSEModeC, mistakenPath, BucketLookupAuto, true)
	if err == nil {
		t.Fatal("nonexistent key path unexpectedly accepted")
	}
	if strings.Contains(err.Error(), mistakenValue) || strings.Contains(err.Error(), mistakenPath) {
		t.Fatal("misplaced SSE-C key material leaked through path error")
	}
}
