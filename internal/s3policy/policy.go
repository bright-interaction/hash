// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package s3policy turns Hash's object-storage settings into the exact MinIO
// SDK policy used by the server, worker, release verifier, and provider tests.
// Keeping this in one package prevents a read-only verification path from
// silently omitting the customer-provided encryption headers.
package s3policy

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

const (
	SSEModeS3 = "sse-s3"
	SSEModeC  = "sse-c"

	BucketLookupAuto = "auto"
	BucketLookupPath = "path"
	BucketLookupDNS  = "dns"
)

// Policy contains no plaintext configuration string for an SSE-C key. The
// MinIO encryption value owns a private copy of the 32-byte key and must never
// be logged or formatted.
type Policy struct {
	SSEMode          string
	WriteEncryption  encrypt.ServerSide
	ReadEncryption   encrypt.ServerSide
	BucketLookup     string
	BucketLookupType minio.BucketLookupType
}

// Load validates and materializes Hash's S3 policy. Empty values preserve the
// historic behavior for direct storage.Config callers: SSE-S3 and automatic
// bucket addressing. SSE-C deliberately accepts only a file, never key bytes
// in an environment variable or command-line argument.
func Load(sseMode, sseCKeyFile, bucketLookup string, useSSL bool) (Policy, error) {
	policy := Policy{}
	if sseMode == "" {
		sseMode = SSEModeS3
	}
	if bucketLookup == "" {
		bucketLookup = BucketLookupAuto
	}

	switch bucketLookup {
	case BucketLookupAuto:
		policy.BucketLookupType = minio.BucketLookupAuto
	case BucketLookupPath:
		policy.BucketLookupType = minio.BucketLookupPath
	case BucketLookupDNS:
		policy.BucketLookupType = minio.BucketLookupDNS
	default:
		return Policy{}, errors.New("HASH_S3_BUCKET_LOOKUP must be exactly auto, path, or dns")
	}

	switch sseMode {
	case SSEModeS3:
		if sseCKeyFile != "" {
			return policy, errors.New("HASH_S3_SSE_C_KEY_FILE must be empty when HASH_S3_SSE_MODE is sse-s3")
		}
		// SSE-S3 is a write instruction. S3 explicitly rejects its generic
		// x-amz-server-side-encryption header on GET/HEAD, so reads stay nil.
		policy.WriteEncryption = encrypt.NewSSE()
	case SSEModeC:
		if !useSSL {
			return policy, errors.New("HASH_S3_SSE_MODE=sse-c requires HASH_S3_USE_SSL=true")
		}
		key, err := readSSECKeyFile(sseCKeyFile)
		if err != nil {
			return policy, err
		}
		sse, err := encrypt.NewSSEC(key)
		clear(key)
		if err != nil {
			return policy, errors.New("initialize SSE-C encryption")
		}
		// SSE-C requires the customer-key headers on both write and read/HEAD.
		policy.WriteEncryption = sse
		policy.ReadEncryption = sse
	default:
		return policy, errors.New("HASH_S3_SSE_MODE must be exactly sse-s3 or sse-c")
	}

	policy.SSEMode = sseMode
	policy.BucketLookup = bucketLookup
	return policy, nil
}

func readSSECKeyFile(filename string) ([]byte, error) {
	if filename == "" {
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE is required when HASH_S3_SSE_MODE is sse-c")
	}
	if !filepath.IsAbs(filename) {
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE must be an absolute in-container path")
	}
	f, err := os.Open(filename)
	if err != nil {
		// Do not wrap os.PathError: an operator who accidentally pasted key
		// material into the *_FILE variable must not have it echoed to logs.
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE cannot be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE must be a regular file containing exactly 32 raw bytes")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, errors.New("read HASH_S3_SSE_C_KEY_FILE")
	}
	if len(key) != 32 {
		clear(key)
		return nil, errors.New("HASH_S3_SSE_C_KEY_FILE must contain exactly 32 raw bytes (not hex, base64, or newline-terminated text)")
	}
	return key, nil
}
