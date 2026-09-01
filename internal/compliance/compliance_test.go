// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package compliance

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBusinessType_Valid(t *testing.T) {
	for _, ok := range []BusinessType{BTLawFirm, BTSaaS, BTConsulting, BTHealthcare, BTFintech, BTOther} {
		if !ok.Valid() {
			t.Errorf("%s should be valid", ok)
		}
	}
	if BusinessType("bogus").Valid() {
		t.Fatal("bogus should be invalid")
	}
}

func TestTemplatesFor_HealthcareHasAddenda(t *testing.T) {
	tpl := TemplatesFor(BTHealthcare, "SE")
	if !strings.Contains(tpl.DPABody, "Patientdatalagen") {
		t.Errorf("healthcare DPA should mention Patientdatalagen, got: %s", tpl.DPABody[:200])
	}
	if len(tpl.ExtraEIDASHints) == 0 {
		t.Error("healthcare should propose eIDAS hints")
	}
}

func TestTemplatesFor_FintechHasAMLLanguage(t *testing.T) {
	tpl := TemplatesFor(BTFintech, "SE")
	if !strings.Contains(tpl.DPABody, "AML") || !strings.Contains(tpl.DPABody, "PSD2") {
		t.Errorf("fintech DPA should mention AML + PSD2, got first 200 chars: %s", tpl.DPABody[:200])
	}
}

func TestTemplatesFor_DefaultsBoilerplate(t *testing.T) {
	tpl := TemplatesFor(BTSaaS, "SE")
	if !strings.Contains(tpl.DPABody, "Schrems II") {
		t.Errorf("SE jurisdiction should mention Schrems II in DPA body")
	}
	if !strings.Contains(tpl.PrivacyNoticeBody, "IMY") {
		t.Errorf("SE jurisdiction privacy notice should mention IMY")
	}
}

func TestBodyToBlocksJSON_HeadingsAndCallouts(t *testing.T) {
	raw := bodyToBlocksJSON("# Heading\n\n## Sub\n\n> Banner\n\n- item one\n- item two\n\nA paragraph.")
	var tree struct {
		Version int `json:"version"`
		Blocks  []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text"`
			Attrs map[string]any `json:"attrs"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tree.Blocks) == 0 {
		t.Fatal("expected blocks")
	}
	first := tree.Blocks[0]
	if first.Type != "heading" || first.Text != "Heading" {
		t.Errorf("first block should be heading: %+v", first)
	}
	if first.Attrs["level"] != float64(1) {
		t.Errorf("first heading should be level 1, got %v", first.Attrs["level"])
	}
	// Find the callout
	gotCallout := false
	for _, b := range tree.Blocks {
		if b.Type == "callout" && b.Text == "Banner" {
			gotCallout = true
		}
	}
	if !gotCallout {
		t.Error("expected a callout for the > Banner line")
	}
}

func TestKeywordsForTopic(t *testing.T) {
	got := keywordsForTopic("transfer_to_third_country")
	if len(got) == 0 || !contains(got, "SCC") {
		t.Errorf("transfer keywords should include SCC, got %v", got)
	}
	if !contains(keywordsForTopic("breach_notification"), "Article 33") {
		t.Error("breach keywords should include Article 33")
	}
	if len(keywordsForTopic("unknown_topic")) != 1 {
		t.Error("unknown topics fall back to the topic itself")
	}
}

func TestSeverityAndSuggestion(t *testing.T) {
	if severityForTopic("transfer_to_third_country") != "urgent" {
		t.Error("transfer topic should be urgent")
	}
	if severityForTopic("data_retention") != "review" {
		t.Error("retention should default to review")
	}
	if !strings.Contains(suggestionForTopic("data_retention"), "retention") {
		t.Error("retention suggestion should mention retention")
	}
}

func TestSyntheticFeed_FiltersBySince(t *testing.T) {
	f := &SyntheticFeed{Items: DevelopmentSampleFeedItems()}
	all, err := f.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("fetch all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sample items, got %d", len(all))
	}
	recent, _ := f.Fetch(context.Background(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(recent) != 1 {
		t.Fatalf("expected 1 item after 2026-01-01, got %d", len(recent))
	}
}

func TestBodyMentions(t *testing.T) {
	body := []byte(`{"blocks":[{"text":"We retain data for 24 months"}]}`)
	if !bodyMentions(body, []string{"retain", "retention"}) {
		t.Error("should match retain")
	}
	if bodyMentions(body, []string{"unrelated"}) {
		t.Error("should not match unrelated")
	}
	if bodyMentions(nil, []string{"retain"}) {
		t.Error("nil body should not match")
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
