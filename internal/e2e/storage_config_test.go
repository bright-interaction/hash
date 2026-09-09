// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e || demo

package e2e

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/storage"
)

// e2eStorageConfig keeps local MinIO behavior as the default while allowing
// the full signing/demo suites to exercise the same TLS, bucket-addressing,
// and SSE-C policy as the Object Lock provider conformance test.
func e2eStorageConfig(t *testing.T, bucket string) storage.Config {
	t.Helper()
	useSSL := false
	if raw := os.Getenv("HASH_E2E_S3_USE_SSL"); raw != "" {
		var err error
		useSSL, err = strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("parse HASH_E2E_S3_USE_SSL: %v", err)
		}
	}
	region := os.Getenv("HASH_E2E_S3_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	configuredBucket := os.Getenv("HASH_E2E_S3_BUCKET")
	if configuredBucket != "" {
		bucket = configuredBucket
	}
	liveConformance := os.Getenv("HASH_E2E_S3_LIVE_CONFORMANCE") == "true"
	endpoint := os.Getenv("HASH_E2E_S3_ENDPOINT")
	providerOverride := e2eRequiresLiveAcknowledgement(endpoint, configuredBucket,
		os.Getenv("HASH_E2E_S3_REGION"), os.Getenv("HASH_E2E_S3_USE_SSL"),
		os.Getenv("HASH_E2E_S3_SSE_MODE"), os.Getenv("HASH_E2E_S3_SSE_C_KEY_FILE"),
		os.Getenv("HASH_E2E_S3_SSE_C_KEY_SHA256"), os.Getenv("HASH_E2E_S3_BUCKET_LOOKUP"))
	if providerOverride && !liveConformance {
		t.Fatal("explicit nonlocal endpoint, bucket, or provider policy requires HASH_E2E_S3_LIVE_CONFORMANCE=true")
	}
	return storage.Config{
		Endpoint:      endpoint,
		Region:        region,
		Bucket:        bucket,
		AccessKey:     os.Getenv("HASH_E2E_S3_ACCESS_KEY"),
		SecretKey:     os.Getenv("HASH_E2E_S3_SECRET_KEY"),
		UseSSL:        useSSL,
		SSEMode:       os.Getenv("HASH_E2E_S3_SSE_MODE"),
		SSECKeyFile:   os.Getenv("HASH_E2E_S3_SSE_C_KEY_FILE"),
		SSECKeySHA256: os.Getenv("HASH_E2E_S3_SSE_C_KEY_SHA256"),
		BucketLookup:  os.Getenv("HASH_E2E_S3_BUCKET_LOOKUP"),
		// Live conformance is allowed to mutate only unique object keys. Never
		// create or replace lifecycle configuration on its operator-owned bucket,
		// but do exercise the same versioning/Object-Lock contract as production.
		RequireObjectLock:                liveConformance,
		RequireExistingBucket:            liveConformance,
		SkipTransientLifecycle:           liveConformance,
		AllowInsecureDevelopmentEndpoint: !useSSL && e2eKnownEphemeralEndpoint(endpoint),
	}
}

func e2eRequiresLiveAcknowledgement(endpoint, configuredBucket string, providerOverrides ...string) bool {
	if !e2eKnownEphemeralEndpoint(endpoint) || configuredBucket != "" {
		return true
	}
	for _, value := range providerOverrides {
		if value != "" {
			return true
		}
	}
	return false
}

func e2eKnownEphemeralEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || port != "9000" {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "hash-e2e-minio":
		return true
	default:
		return false
	}
}

func TestE2EStorageConfigDefaultsAndProviderOverrides(t *testing.T) {
	for _, name := range []string{
		"HASH_E2E_S3_ENDPOINT", "HASH_E2E_S3_REGION", "HASH_E2E_S3_BUCKET",
		"HASH_E2E_S3_ACCESS_KEY", "HASH_E2E_S3_SECRET_KEY", "HASH_E2E_S3_USE_SSL",
		"HASH_E2E_S3_SSE_MODE", "HASH_E2E_S3_SSE_C_KEY_FILE",
		"HASH_E2E_S3_SSE_C_KEY_SHA256",
		"HASH_E2E_S3_BUCKET_LOOKUP", "HASH_E2E_S3_LIVE_CONFORMANCE",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("HASH_E2E_S3_ENDPOINT", "localhost:9000")
	local := e2eStorageConfig(t, "hash-e2e")
	if local.Region != "eu-central-1" || local.Bucket != "hash-e2e" || local.UseSSL ||
		local.SSEMode != "" || local.SSECKeyFile != "" || local.BucketLookup != "" ||
		local.RequireObjectLock || local.RequireExistingBucket || local.SkipTransientLifecycle {
		t.Fatal("local storage defaults changed")
	}

	t.Setenv("HASH_E2E_S3_ENDPOINT", "fsn1.your-objectstorage.com")
	t.Setenv("HASH_E2E_S3_REGION", "fsn1")
	t.Setenv("HASH_E2E_S3_BUCKET", "hash-provider-test")
	t.Setenv("HASH_E2E_S3_USE_SSL", "true")
	t.Setenv("HASH_E2E_S3_SSE_MODE", "sse-c")
	t.Setenv("HASH_E2E_S3_SSE_C_KEY_FILE", "/run/secrets/hash-s3-sse-c")
	t.Setenv("HASH_E2E_S3_SSE_C_KEY_SHA256", strings.Repeat("a", 64))
	t.Setenv("HASH_E2E_S3_BUCKET_LOOKUP", "path")
	t.Setenv("HASH_E2E_S3_LIVE_CONFORMANCE", "true")
	provider := e2eStorageConfig(t, "ignored-fallback")
	if provider.Endpoint != "fsn1.your-objectstorage.com" || provider.Region != "fsn1" ||
		provider.Bucket != "hash-provider-test" || !provider.UseSSL || provider.SSEMode != "sse-c" ||
		provider.SSECKeyFile != "/run/secrets/hash-s3-sse-c" || provider.SSECKeySHA256 != strings.Repeat("a", 64) || provider.BucketLookup != "path" ||
		!provider.RequireObjectLock || !provider.RequireExistingBucket || !provider.SkipTransientLifecycle {
		t.Fatal("provider storage overrides not preserved")
	}
}

func TestE2EKnownEphemeralEndpointIsExact(t *testing.T) {
	for _, endpoint := range []string{"localhost:9000", "127.0.0.1:9000", "[::1]:9000", "hash-e2e-minio:9000"} {
		if !e2eKnownEphemeralEndpoint(endpoint) {
			t.Errorf("known local harness %q rejected", endpoint)
		}
	}
	for _, endpoint := range []string{"", "minio:9000", "localhost:443", "localhost:9000.evil", "fsn1.your-objectstorage.com:443"} {
		if e2eKnownEphemeralEndpoint(endpoint) {
			t.Errorf("non-ephemeral endpoint %q accepted", endpoint)
		}
	}
}

func TestE2ECustomProviderInputsRequireLiveAcknowledgement(t *testing.T) {
	if e2eRequiresLiveAcknowledgement("localhost:9000", "") {
		t.Fatal("known ephemeral harness required live acknowledgement")
	}
	for _, tc := range []struct {
		endpoint string
		bucket   string
		extra    []string
	}{
		{"objects.example.com:443", "", nil},
		{"localhost:9000", "operator-bucket", nil},
		{"localhost:9000", "", []string{"eu-west-1"}},
		{"hash-e2e-minio:9000", "", []string{"", "true"}},
	} {
		if !e2eRequiresLiveAcknowledgement(tc.endpoint, tc.bucket, tc.extra...) {
			t.Errorf("custom provider input was treated as ephemeral: %+v", tc)
		}
	}
}
