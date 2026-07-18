// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package eidas

import (
	"encoding/json"
	"testing"
)

func TestTier_CmpAndValid(t *testing.T) {
	if TierSES.Cmp(TierAES) >= 0 {
		t.Fatal("SES < AES")
	}
	if TierAES.Cmp(TierQES) >= 0 {
		t.Fatal("AES < QES")
	}
	if TierSES.Cmp(TierQES) >= 0 {
		t.Fatal("SES < QES")
	}
	if TierAES.Cmp(TierAES) != 0 {
		t.Fatal("AES == AES")
	}
	if !TierSES.Valid() || !TierAES.Valid() || !TierQES.Valid() {
		t.Fatal("standard tiers should be valid")
	}
	if Tier("Invalid").Valid() {
		t.Fatal("garbage tier should not be valid")
	}
}

func TestMatchPredicate_AmountGTE(t *testing.T) {
	in := EvaluateInput{Amount: 150000}
	cases := []struct {
		pred string
		want bool
	}{
		{`{"field":"amount","op":">=","value":100000}`, true},
		{`{"field":"amount","op":">=","value":200000}`, false},
		{`{"field":"amount","op":">","value":150000}`, false},
		{`{"field":"amount","op":">=","value":150000}`, true},
		{`{"field":"amount","op":"<","value":200000}`, true},
	}
	for _, c := range cases {
		got, err := matchPredicate(json.RawMessage(c.pred), in)
		if err != nil {
			t.Fatalf("pred %s: %v", c.pred, err)
		}
		if got != c.want {
			t.Errorf("pred %s: got %v want %v", c.pred, got, c.want)
		}
	}
}

func TestMatchPredicate_CountryIn(t *testing.T) {
	in := EvaluateInput{Country: "SE"}
	got, err := matchPredicate(json.RawMessage(`{"field":"country","op":"in","value":["SE","NO","DK"]}`), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got {
		t.Fatal("SE should match [SE,NO,DK]")
	}
	got, _ = matchPredicate(json.RawMessage(`{"field":"country","op":"in","value":["NO","DK"]}`), in)
	if got {
		t.Fatal("SE should NOT match [NO,DK]")
	}
}

func TestMatchPredicate_VariableField(t *testing.T) {
	in := EvaluateInput{
		Variables: map[string]string{"deal_amount": "50000", "tier": "premium"},
	}
	got, err := matchPredicate(json.RawMessage(`{"field":"variables.deal_amount","op":">=","value":40000}`), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got {
		t.Fatal("variables.deal_amount should be 50000 >= 40000")
	}
	got, _ = matchPredicate(json.RawMessage(`{"field":"variables.tier","op":"==","value":"premium"}`), in)
	if !got {
		t.Fatal("variables.tier == premium")
	}
}

func TestMatchPredicate_MissingFieldDoesNotMatch(t *testing.T) {
	in := EvaluateInput{Variables: map[string]string{}}
	got, err := matchPredicate(json.RawMessage(`{"field":"variables.missing","op":"==","value":"x"}`), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got {
		t.Fatal("missing variable should never match (silently)")
	}
}

func TestMatchPredicate_AllComposite(t *testing.T) {
	in := EvaluateInput{Amount: 200000, Country: "SE"}
	all := `{"all":[
		{"field":"amount","op":">=","value":100000},
		{"field":"country","op":"==","value":"SE"}
	]}`
	got, err := matchPredicate(json.RawMessage(all), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got {
		t.Fatal("both child predicates should match")
	}
	// flip country -> all should fail
	in.Country = "NO"
	got, _ = matchPredicate(json.RawMessage(all), in)
	if got {
		t.Fatal("changing country should break the all")
	}
}

func TestMatchPredicate_AnyComposite(t *testing.T) {
	in := EvaluateInput{Amount: 50000, Country: "NO"}
	any := `{"any":[
		{"field":"amount","op":">=","value":100000},
		{"field":"country","op":"==","value":"NO"}
	]}`
	got, err := matchPredicate(json.RawMessage(any), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got {
		t.Fatal("country match should satisfy any")
	}
}

func TestMatchPredicate_UnknownOp(t *testing.T) {
	in := EvaluateInput{Amount: 1}
	_, err := matchPredicate(json.RawMessage(`{"field":"amount","op":"~","value":1}`), in)
	if err == nil {
		t.Fatal("unknown op should error")
	}
}

func TestGuardError_Message(t *testing.T) {
	err := &GuardError{
		Decision: Decision{
			RequiredTier: TierAES,
			MatchedRules: []MatchedRule{
				{Name: "Sweden 100k AES", RequiredTier: TierAES},
			},
		},
		CurrentTier: TierSES,
	}
	msg := err.Error()
	for _, want := range []string{"AES", "SES", "Sweden 100k AES"} {
		if !contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
