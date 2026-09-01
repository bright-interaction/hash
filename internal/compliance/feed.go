// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/nethard"
)

// FeedItem mirrors compliance_feed_items + the wire shape of the
// EDPB / EUR-Lex feeds we consume.
type FeedItem struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Topic       string    `json:"topic"`
	PublishedAt time.Time `json:"published_at"`
}

// Feed is the abstraction every parser implements. Production wiring
// points at the EDPB JSON endpoint; tests inject a fake.
type Feed interface {
	Fetch(ctx context.Context, since time.Time) ([]FeedItem, error)
}

// HTTPFeed fetches a JSON feed from a configurable endpoint. The
// expected wire shape is `{items: [{id, title, summary, topic,
// published_at}, ...]}`; we own the upstream proxy so we can keep the
// shape stable even if EDPB's HTML format wobbles.
type HTTPFeed struct {
	Endpoint string
	Client   *http.Client
}

const (
	maxComplianceFeedBytes = 4 << 20
	maxComplianceFeedItems = 1000
)

func NewHTTPFeed(endpoint string, allowPrivate ...bool) *HTTPFeed {
	privateAllowed := len(allowPrivate) > 0 && allowPrivate[0]
	return &HTTPFeed{
		Endpoint: endpoint,
		Client:   nethard.Client(10*time.Second, func() bool { return privateAllowed }),
	}
}

func (f *HTTPFeed) Fetch(ctx context.Context, since time.Time) ([]FeedItem, error) {
	if f.Endpoint == "" {
		return nil, ErrFeedNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, "GET", f.Endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("feed %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return nil, errors.New("feed response must use an application/json content type")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxComplianceFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxComplianceFeedBytes {
		return nil, fmt.Errorf("feed response exceeds %d bytes", maxComplianceFeedBytes)
	}
	if !utf8.Valid(body) {
		return nil, errors.New("feed response must be valid UTF-8")
	}
	var wire struct {
		Items []FeedItem `json:"items"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("feed decode: %w", err)
	}
	if len(wire.Items) > maxComplianceFeedItems {
		return nil, fmt.Errorf("feed contains more than %d items", maxComplianceFeedItems)
	}
	out := wire.Items[:0]
	for _, item := range wire.Items {
		if err := validateFeedItem(item); err != nil {
			return nil, err
		}
		if item.PublishedAt.Before(since) {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func validateFeedItem(item FeedItem) error {
	if strings.TrimSpace(item.ID) == "" || item.ID != strings.TrimSpace(item.ID) || len(item.ID) > 512 {
		return errors.New("feed item id must be non-empty, trimmed, and at most 512 bytes")
	}
	if strings.TrimSpace(item.Title) == "" || len(item.Title) > 2048 {
		return fmt.Errorf("feed item %q title must be non-empty and at most 2048 bytes", item.ID)
	}
	if len(item.Summary) > 64*1024 {
		return fmt.Errorf("feed item %q summary exceeds 65536 bytes", item.ID)
	}
	if strings.TrimSpace(item.Topic) == "" || item.Topic != strings.TrimSpace(item.Topic) || len(item.Topic) > 128 {
		return fmt.Errorf("feed item %q topic must be non-empty, trimmed, and at most 128 bytes", item.ID)
	}
	if item.PublishedAt.IsZero() {
		return fmt.Errorf("feed item %q published_at is required", item.ID)
	}
	return nil
}

// ErrFeedNotConfigured is returned when no endpoint is set + the worker
// is asked to run the rollup anyway. The worker handles this softly:
// logs at info, skips the run, retries on the next tick.
var ErrFeedNotConfigured = errors.New("compliance: feed endpoint not configured")

// NoopFeed always returns no items. Used in tests + when an org opts
// out of the EDPB rollup.
type NoopFeed struct{}

func (NoopFeed) Fetch(_ context.Context, _ time.Time) ([]FeedItem, error) {
	return nil, nil
}

// SyntheticFeed serves a fixed slice of items. Used by the unit tests
// + by the seed-defaults endpoint, which can pre-populate one or two
// "known interesting" advisories so the dashboard isn't empty on day
// one.
type SyntheticFeed struct {
	Items []FeedItem
}

func (s *SyntheticFeed) Fetch(_ context.Context, since time.Time) ([]FeedItem, error) {
	out := []FeedItem{}
	for _, it := range s.Items {
		if it.PublishedAt.Before(since) {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// DevelopmentSampleFeedItems returns fictional fixtures for local demos and
// unit tests. They are not authoritative legal guidance and production wiring
// must never ingest them or surface flags derived from them.
func DevelopmentSampleFeedItems() []FeedItem {
	return []FeedItem{
		{
			ID:          "edpb/2025/schrems-iii-supplementary-measures",
			Title:       "EDPB note: supplementary measures for cross-border transfers post-Schrems II",
			Summary:     "EDPB clarifies expectations for transfer impact assessments + supplementary measures when transferring personal data to third countries. Review DPAs that reference SCC + transfers.",
			Topic:       "transfer_to_third_country",
			PublishedAt: time.Date(2025, 11, 14, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:          "edpb/2026/retention-default-windows",
			Title:       "EDPB guidance on default retention windows for B2B prospecting",
			Summary:     "Default retention for B2B contacts should not exceed 36 months without renewed legitimate-interest justification. Review records of processing.",
			Topic:       "data_retention",
			PublishedAt: time.Date(2026, 2, 7, 9, 0, 0, 0, time.UTC),
		},
	}
}
