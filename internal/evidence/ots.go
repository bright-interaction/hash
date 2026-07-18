// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPOTSAnchor talks to a public OpenTimestamps calendar to anchor a
// SHA-256 digest in Bitcoin (free, decentralized, EU-court accepted).
//
// Default endpoint is `https://a.pool.opentimestamps.org/digest` which
// accepts a 32-byte digest body via POST and returns a `.ots` proof.
// The returned proof file is what readers later upgrade by querying
// the same calendar until the Bitcoin attestation lands (typically
// within an hour).
//
// Network failure is non-fatal: Builder.Build catches the err and
// drops the OpenTimestamps field from the manifest so the rest of the
// bundle still produces.
type HTTPOTSAnchor struct {
	Endpoint string
	Client   *http.Client
}

// NewHTTPOTSAnchor builds an anchor with sensible defaults.
func NewHTTPOTSAnchor(endpoint string) *HTTPOTSAnchor {
	if endpoint == "" {
		endpoint = "https://a.pool.opentimestamps.org/digest"
	}
	return &HTTPOTSAnchor{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *HTTPOTSAnchor) Stamp(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("ots: digest must be 32 bytes, got %d", len(digest))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.Endpoint, bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ots: %d", resp.StatusCode)
	}
	// Cap at 1 MiB. OTS proofs are typically <2KB so this is generous.
	return io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
}

// NoopOTSAnchor returns nil bytes + nil error so Builder.Build skips
// the anchor field silently. Used in tests + when the operator opts
// out of OTS anchoring.
type NoopOTSAnchor struct{}

func (NoopOTSAnchor) Stamp(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}
