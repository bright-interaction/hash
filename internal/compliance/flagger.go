// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package compliance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Flagger walks the EDPB feed cache + raises compliance_flags against
// affected documents. The walker is heuristic-first: each FeedItem
// carries a Topic, and the flagger checks every org's compliance
// baseline for documents whose body mentions topic keywords. Phase
// 12.2.1 will plug in the AI runtime for semantic matching (the
// keyword pass already catches the obvious cases + keeps the AI cost
// proportional to actual matches).
type Flagger struct {
	Q *generated.Queries
}

func NewFlagger(q *generated.Queries) *Flagger { return &Flagger{Q: q} }

// FlagRun ingests new feed items + raises flags for affected
// documents. Idempotent: feed items are upserted by ID; flags are
// inserted only when no open flag for the same (doc, update_ref)
// already exists.
func (f *Flagger) FlagRun(ctx context.Context, items []FeedItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	for _, it := range items {
		if err := f.Q.UpsertFeedItem(ctx, generated.UpsertFeedItemParams{
			ID:          it.ID,
			Title:       it.Title,
			Summary:     it.Summary,
			Topic:       it.Topic,
			PublishedAt: pgtype.Timestamptz{Time: it.PublishedAt, Valid: true},
		}); err != nil {
			return 0, fmt.Errorf("upsert feed item: %w", err)
		}
	}
	// Pull baselines for every org so the walker scopes the scan to the
	// docs the customer is actually relying on.
	orgIDs, err := f.Q.ListAllOrgsForCompliance(ctx, 10000)
	if err != nil {
		return 0, fmt.Errorf("list orgs: %w", err)
	}
	raised := 0
	for _, orgID := range orgIDs {
		baseline, err := f.Q.GetComplianceBaseline(ctx, orgID)
		if err != nil {
			continue
		}
		for _, item := range items {
			n, _ := f.flagForOrg(ctx, orgID, baseline, item)
			raised += n
		}
	}
	return raised, nil
}

func (f *Flagger) flagForOrg(ctx context.Context, orgID uuid.UUID, baseline *generated.ComplianceBaseline, item FeedItem) (int, error) {
	keywords := keywordsForTopic(item.Topic)
	raised := 0
	type target struct {
		docID      pgtype.UUID
		templateID pgtype.UUID
		title      string
		body       []byte
	}
	targets := []target{}
	if baseline.RecordsDocID.Valid {
		if doc, err := f.Q.GetDocument(ctx, generated.GetDocumentParams{
			ID: uuid.UUID(baseline.RecordsDocID.Bytes), OrgID: orgID,
		}); err == nil {
			targets = append(targets, target{
				docID: baseline.RecordsDocID, title: doc.Name, body: doc.BlocksJson,
			})
		}
	}
	if baseline.PrivacyNoticeID.Valid {
		if doc, err := f.Q.GetDocument(ctx, generated.GetDocumentParams{
			ID: uuid.UUID(baseline.PrivacyNoticeID.Bytes), OrgID: orgID,
		}); err == nil {
			targets = append(targets, target{
				docID: baseline.PrivacyNoticeID, title: doc.Name, body: doc.BlocksJson,
			})
		}
	}
	if baseline.DpaTemplateID.Valid {
		if tpl, err := f.Q.GetTemplate(ctx, generated.GetTemplateParams{
			ID: uuid.UUID(baseline.DpaTemplateID.Bytes), OrgID: orgID,
		}); err == nil {
			targets = append(targets, target{
				templateID: baseline.DpaTemplateID, title: tpl.Name, body: tpl.BlocksJson,
			})
		}
	}
	for _, t := range targets {
		if !bodyMentions(t.body, keywords) {
			continue
		}
		_, err := f.Q.InsertComplianceFlag(ctx, generated.InsertComplianceFlagParams{
			OrgID:           orgID,
			DocumentID:      t.docID,
			TemplateID:      t.templateID,
			UpdateRef:       item.ID,
			UpdateTitle:     item.Title,
			AffectedTopic:   item.Topic,
			BlockID:         "",
			Severity:        severityForTopic(item.Topic),
			SuggestedAction: suggestionForTopic(item.Topic),
		})
		if err != nil {
			continue
		}
		raised++
	}
	return raised, nil
}

func keywordsForTopic(topic string) []string {
	switch topic {
	case "data_retention":
		return []string{"retention", "retain", "kept", "deletion", "delete after"}
	case "transfer_to_third_country":
		return []string{"international transfer", "third country", "SCC", "Schrems", "transfer impact"}
	case "lawful_basis":
		return []string{"legitimate interest", "consent", "Article 6", "lawful basis"}
	case "data_subject_rights":
		return []string{"right of access", "right to be forgotten", "data portability", "Article 15", "Article 17", "Article 20"}
	case "breach_notification":
		return []string{"breach", "incident", "Article 33", "Article 34"}
	default:
		return []string{topic}
	}
}

func severityForTopic(topic string) string {
	switch topic {
	case "transfer_to_third_country", "breach_notification":
		return "urgent"
	default:
		return "review"
	}
}

func suggestionForTopic(topic string) string {
	switch topic {
	case "data_retention":
		return "Verify retention windows match the new guidance; tighten or document a renewed legitimate-interest basis."
	case "transfer_to_third_country":
		return "Re-run the transfer impact assessment; confirm SCC + supplementary measures are still adequate."
	case "lawful_basis":
		return "Re-confirm the lawful basis stated in the document still maps to current EDPB guidance."
	case "data_subject_rights":
		return "Ensure the rights table reflects current Article 15-22 timing + format expectations."
	case "breach_notification":
		return "Update the breach-notification clause to match current 72-hour reporting + content requirements."
	default:
		return "Review the flagged passage against the linked guidance."
	}
}

func bodyMentions(blocksJSON []byte, keywords []string) bool {
	if len(blocksJSON) == 0 || len(keywords) == 0 {
		return false
	}
	lower := strings.ToLower(string(blocksJSON))
	for _, k := range keywords {
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// FlagOnce is a small worker entry that fetches new items + runs the
// flagger. Designed so the worker tick can call it without knowing the
// feed details.
func FlagOnce(ctx context.Context, feed Feed, flagger *Flagger, since time.Time) (int, error) {
	items, err := feed.Fetch(ctx, since)
	if err != nil {
		return 0, err
	}
	return flagger.FlagRun(ctx, items)
}
