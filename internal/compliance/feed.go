package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
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

func NewHTTPFeed(endpoint string) *HTTPFeed {
	return &HTTPFeed{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 10 * time.Second},
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
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("feed %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	var wire struct {
		Items []FeedItem `json:"items"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("feed decode: %w", err)
	}
	out := wire.Items[:0]
	for _, item := range wire.Items {
		if item.PublishedAt.Before(since) {
			continue
		}
		out = append(out, item)
	}
	return out, nil
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

// SampleFeedItems returns a small starter set so a fresh deploy can
// show the /compliance dashboard with one or two known advisories.
// Replace by real EDPB fetches once we wire the upstream URL.
func SampleFeedItems() []FeedItem {
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
