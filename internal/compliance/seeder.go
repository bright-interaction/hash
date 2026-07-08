package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/eidas"
)

// Seeder is the entry point for org-onboarding compliance baselines.
// Hold one process-wide.
type Seeder struct {
	Q     *generated.Queries
	EIDAS *eidas.Engine
}

func New(q *generated.Queries, e *eidas.Engine) *Seeder {
	return &Seeder{Q: q, EIDAS: e}
}

// SeedInput captures what the onboarding wizard collects + what the
// system needs to attribute the seeded artifacts.
type SeedInput struct {
	OrgID        uuid.UUID
	UserID       uuid.UUID // attributed as the creator of the seeded docs + template
	BusinessType BusinessType
	Jurisdiction string // ISO country code; defaults to SE
}

// SeedResult names what landed so the caller (the onboarding wizard +
// the audit log) can show "we set up X, Y, Z".
type SeedResult struct {
	BaselineID       uuid.UUID `json:"baseline_id"`
	DPATemplateID    uuid.UUID `json:"dpa_template_id"`
	RecordsDocID     uuid.UUID `json:"records_doc_id"`
	PrivacyNoticeID  uuid.UUID `json:"privacy_notice_id"`
	EIDASRulesSeeded int       `json:"eidas_rules_seeded"`
}

// Seed installs the full baseline kit for an org. Idempotent: re-seeds
// only insert missing artifacts; existing artifacts are preserved + the
// baseline row updated. The eIDAS Swedish defaults are seeded
// unconditionally via the Phase 9.2 engine (which is itself idempotent).
func (s *Seeder) Seed(ctx context.Context, in SeedInput) (*SeedResult, error) {
	if in.OrgID == uuid.Nil {
		return nil, errors.New("compliance: org_id required")
	}
	if !in.BusinessType.Valid() {
		return nil, fmt.Errorf("compliance: invalid business_type %q", in.BusinessType)
	}
	juris := in.Jurisdiction
	if juris == "" {
		juris = "SE"
	}
	templates := TemplatesFor(in.BusinessType, juris)

	existing, _ := s.Q.GetComplianceBaseline(ctx, in.OrgID)

	out := &SeedResult{}

	// DPA template (blocks-source so senders can edit + reuse).
	dpaTemplateID := pgtype.UUID{}
	if existing != nil && existing.DpaTemplateID.Valid {
		dpaTemplateID = existing.DpaTemplateID
		out.DPATemplateID = uuid.UUID(existing.DpaTemplateID.Bytes)
	} else {
		tpl, err := s.Q.CreateBlocksTemplate(ctx, generated.CreateBlocksTemplateParams{
			OrgID:         in.OrgID,
			Name:          templates.DPATitle,
			BlocksJson:    bodyToBlocksJSON(templates.DPABody),
			VariablesJson: []byte("{}"),
			CreatedBy:     in.UserID,
		})
		if err != nil {
			return nil, fmt.Errorf("compliance: create DPA template: %w", err)
		}
		dpaTemplateID = pgtype.UUID{Bytes: tpl.ID, Valid: true}
		out.DPATemplateID = tpl.ID
	}

	// Records of processing (a regular document, kept as draft for editing).
	recordsDocID := pgtype.UUID{}
	if existing != nil && existing.RecordsDocID.Valid {
		recordsDocID = existing.RecordsDocID
		out.RecordsDocID = uuid.UUID(existing.RecordsDocID.Bytes)
	} else {
		doc, err := s.Q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID:         in.OrgID,
			Name:          templates.RecordsTitle,
			BlocksJson:    bodyToBlocksJSON(templates.RecordsBody),
			VariablesJson: []byte("{}"),
			SenderID:      in.UserID,
		})
		if err != nil {
			return nil, fmt.Errorf("compliance: create records doc: %w", err)
		}
		recordsDocID = pgtype.UUID{Bytes: doc.ID, Valid: true}
		out.RecordsDocID = doc.ID
	}

	// Privacy notice (Article 13).
	privacyDocID := pgtype.UUID{}
	if existing != nil && existing.PrivacyNoticeID.Valid {
		privacyDocID = existing.PrivacyNoticeID
		out.PrivacyNoticeID = uuid.UUID(existing.PrivacyNoticeID.Bytes)
	} else {
		doc, err := s.Q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID:         in.OrgID,
			Name:          templates.PrivacyNoticeTitle,
			BlocksJson:    bodyToBlocksJSON(templates.PrivacyNoticeBody),
			VariablesJson: []byte("{}"),
			SenderID:      in.UserID,
		})
		if err != nil {
			return nil, fmt.Errorf("compliance: create privacy notice: %w", err)
		}
		privacyDocID = pgtype.UUID{Bytes: doc.ID, Valid: true}
		out.PrivacyNoticeID = doc.ID
	}

	// eIDAS rules. Seed Swedish defaults first; future versions may
	// fork by jurisdiction.
	if s.EIDAS != nil {
		if err := s.EIDAS.SeedSwedishDefaults(ctx, in.OrgID); err != nil {
			return nil, fmt.Errorf("compliance: seed eIDAS: %w", err)
		}
		rules, _ := s.Q.ListEIDASRules(ctx, in.OrgID)
		out.EIDASRulesSeeded = len(rules)
	}

	row, err := s.Q.UpsertComplianceBaseline(ctx, generated.UpsertComplianceBaselineParams{
		OrgID:           in.OrgID,
		BusinessType:    string(in.BusinessType),
		Jurisdiction:    juris,
		DpaTemplateID:   dpaTemplateID,
		RecordsDocID:    recordsDocID,
		PrivacyNoticeID: privacyDocID,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: upsert baseline: %w", err)
	}
	out.BaselineID = row.OrgID // baseline is keyed by org_id, no separate id
	return out, nil
}

// bodyToBlocksJSON wraps a long markdown-ish body into a canonical
// block tree: one paragraph block per non-empty line, headings detected
// by leading `#`. The editor can refine; we just need something the
// renderer accepts.
func bodyToBlocksJSON(body string) json.RawMessage {
	type block struct {
		ID    string         `json:"id"`
		Type  blocks.Type    `json:"type"`
		Text  string         `json:"text,omitempty"`
		Attrs map[string]any `json:"attrs,omitempty"`
	}
	type tree struct {
		Version int     `json:"version"`
		Blocks  []block `json:"blocks"`
	}
	out := tree{Version: 1}
	idx := 0
	emit := func(kind blocks.Type, text string, attrs map[string]any) {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", kind, idx, text)))
		idx++
		out.Blocks = append(out.Blocks, block{
			ID:    "cb_" + hex.EncodeToString(h[:6]),
			Type:  kind,
			Text:  text,
			Attrs: attrs,
		})
	}
	for _, raw := range splitLines(body) {
		line := trimRight(raw, " \t")
		if line == "" {
			continue
		}
		switch {
		case startsWith(line, "# "):
			emit(blocks.TypeHeading, line[2:], map[string]any{"level": 1})
		case startsWith(line, "## "):
			emit(blocks.TypeHeading, line[3:], map[string]any{"level": 2})
		case startsWith(line, "### "):
			emit(blocks.TypeHeading, line[4:], map[string]any{"level": 3})
		case startsWith(line, "> "):
			emit(blocks.TypeCallout, line[2:], nil)
		case startsWith(line, "- "):
			emit(blocks.TypeListItem, line[2:], nil)
		default:
			emit(blocks.TypeParagraph, line, nil)
		}
	}
	raw, _ := json.Marshal(out)
	return raw
}

// Tiny strings helpers kept here so the compliance package doesn't
// import "strings" in this hot path (one micro-import). They cover the
// exact case we need (ASCII prefix matching).

func splitLines(s string) []string {
	out := []string{}
	cur := ""
	for _, ch := range s {
		if ch == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func startsWith(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func trimRight(s, cutset string) string {
	for len(s) > 0 {
		last := s[len(s)-1]
		match := false
		for _, c := range cutset {
			if byte(c) == last {
				match = true
				break
			}
		}
		if !match {
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}
