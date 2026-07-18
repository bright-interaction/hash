// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package storage wraps MinIO/S3 access. The Bright Interaction MinIO at
// s3.example.com is the default backend.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

type Client struct {
	mc     *minio.Client
	bucket string
}

type Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

func New(ctx context.Context, cfg Config) (*Client, error) {
	mc, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("init minio client: %w", err)
	}

	exists, err := mc.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("bucket exists check: %w", err)
	}
	if !exists {
		if err := mc.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("create bucket: %w", err)
		}
	}

	// Apply the canonical lifecycle: signed PDFs + audit certs retain
	// 7 years (statutory evidentiary minimum + buffer); transient
	// preview / logo / template uploads expire after 90 days. Failure
	// to apply the policy is logged but non-fatal so a read-only
	// instance still boots; production MinIO needs s3:PutBucketLifecycle
	// to make this stick.
	if err := applyLifecycle(ctx, mc, cfg.Bucket); err != nil {
		slog.Warn("storage: bucket lifecycle apply failed (set s3:PutBucketLifecycle?)",
			"bucket", cfg.Bucket, "err", err)
	}

	return &Client{mc: mc, bucket: cfg.Bucket}, nil
}

// applyLifecycle installs the Hash retention policy on the bucket.
// Two prefixes survive 7 years (signed PDFs + audit certs); one prefix
// expires after 90 days (telemetry overflow + preview renders);
// everything else is left alone.
func applyLifecycle(ctx context.Context, mc *minio.Client, bucket string) error {
	cfg := lifecycle.NewConfiguration()
	cfg.Rules = []lifecycle.Rule{
		{
			ID:     "hash-signed-7y",
			Status: "Enabled",
			RuleFilter: lifecycle.Filter{
				Prefix: "signed/",
			},
			Expiration: lifecycle.Expiration{Days: 7 * 365},
		},
		{
			ID:     "hash-audit-7y",
			Status: "Enabled",
			RuleFilter: lifecycle.Filter{
				Prefix: "audit/",
			},
			Expiration: lifecycle.Expiration{Days: 7 * 365},
		},
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

// putOpts returns the canonical PutObjectOptions Hash uses for every
// upload. SSE-S3 (server-side AES-256, MinIO-managed key) is on by
// default so the privacy-policy "encrypted at rest" claim is backed by
// code, not vibes. A bucket-default encryption policy is the belt; this
// is the suspenders so a misconfigured bucket still encrypts.
func putOpts(contentType string) minio.PutObjectOptions {
	return minio.PutObjectOptions{
		ContentType:          contentType,
		ServerSideEncryption: encrypt.NewSSE(),
	}
}

// Put uploads bytes and returns the storage key plus SHA-256 of the contents.
func (c *Client) Put(ctx context.Context, key, contentType string, data []byte) (sha [32]byte, err error) {
	sha = sha256.Sum256(data)
	_, err = c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), putOpts(contentType))
	if err != nil {
		return sha, fmt.Errorf("put %q: %w", key, err)
	}
	return sha, nil
}

// PutStream uploads from an io.Reader of known length.
func (c *Client) PutStream(ctx context.Context, key, contentType string, r io.Reader, size int64) error {
	_, err := c.mc.PutObject(ctx, c.bucket, key, r, size, putOpts(contentType))
	if err != nil {
		return fmt.Errorf("put stream %q: %w", key, err)
	}
	return nil
}

// Get returns the full object bytes. Caller must keep payloads small (<50MB
// hard cap on uploads).
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := c.mc.GetObject(ctx, c.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	defer obj.Close()
	return io.ReadAll(obj)
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
	return c.mc.PresignedGetObject(ctx, c.bucket, key, ttl, nil)
}
