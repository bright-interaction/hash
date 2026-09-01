// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
)

func TestBuildEIDASEvaluateInputAmountFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want float64
	}{
		{"machine number", `{"deal_amount":"1000000"}`, 1_000_000},
		{"Swedish spaces", `{"deal_amount":"1 000 000"}`, 1_000_000},
		{"non-breaking spaces", "{\"deal_amount\":\"1\u00a0000\u00a0000\"}", 1_000_000},
		{"decimal comma", `{"deal_amount":"1250,50"}`, 1250.50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildEIDASEvaluateInput(&generated.Document{VariablesJson: json.RawMessage(tc.raw)})
			if err != nil {
				t.Fatal(err)
			}
			if got.Amount != tc.want {
				t.Fatalf("amount = %v, want %v", got.Amount, tc.want)
			}
			if want := strconv.FormatFloat(tc.want, 'f', -1, 64); got.Variables["deal_amount"] != want {
				t.Fatalf("normalized variable = %q, want %q", got.Variables["deal_amount"], want)
			}
		})
	}
}

func TestBuildEIDASEvaluateInputRejectsInvalidPresentAmount(t *testing.T) {
	for _, amount := range []string{"NaN", "+Inf", "1.000.000", "", "not money"} {
		raw, err := json.Marshal(map[string]string{"deal_amount": amount})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := BuildEIDASEvaluateInput(&generated.Document{VariablesJson: raw}); err == nil {
			t.Errorf("amount %q should fail closed", amount)
		}
	}
}

func TestGuardEnvelopeEIDASSendUsesHighestChildRequirement(t *testing.T) {
	orgID := uuid.New()
	family := []*generated.Document{
		{ID: uuid.New(), VariablesJson: json.RawMessage(`{}`)},
		{ID: uuid.New(), VariablesJson: json.RawMessage(`{"deal_amount":"200000"}`)},
		{ID: uuid.New(), VariablesJson: json.RawMessage(`{"deal_amount":"2000000"}`)},
	}
	evaluator := &amountTierEvaluator{}

	decision, err := guardEnvelopeEIDASSend(context.Background(), evaluator, orgID, eidas.TierAES, family)
	if !errors.Is(err, ErrSignatureTierUnavailable) {
		t.Fatalf("error = %v, want ErrSignatureTierUnavailable", err)
	}
	if decision.RequiredTier != eidas.TierQES {
		t.Fatalf("required tier = %s, want QES", decision.RequiredTier)
	}
	if len(evaluator.inputs) != len(family) {
		t.Fatalf("evaluated documents = %d, want %d", len(evaluator.inputs), len(family))
	}
	if evaluator.inputs[1].Amount != 200_000 || evaluator.inputs[2].Amount != 2_000_000 {
		t.Fatalf("child amounts = %v and %v, want 200000 and 2000000", evaluator.inputs[1].Amount, evaluator.inputs[2].Amount)
	}

	if _, err := guardEnvelopeEIDASSend(context.Background(), &amountTierEvaluator{}, orgID, eidas.TierQES, family); !errors.Is(err, ErrSignatureTierUnavailable) {
		t.Fatalf("direct QES envelope error = %v, want unavailable proof-path rejection", err)
	}
}

func TestRequireSupportedSignatureTierRejectsDirectAESAndQESSends(t *testing.T) {
	for _, tier := range []eidas.Tier{eidas.TierAES, eidas.TierQES} {
		if err := requireSupportedSignatureTier(tier, eidas.TierSES); !errors.Is(err, ErrSignatureTierUnavailable) {
			t.Errorf("selected %s error = %v, want ErrSignatureTierUnavailable", tier, err)
		}
		if err := requireSupportedSignatureTier(eidas.TierSES, tier); !errors.Is(err, ErrSignatureTierUnavailable) {
			t.Errorf("required %s error = %v, want ErrSignatureTierUnavailable", tier, err)
		}
	}
	if err := requireSupportedSignatureTier(eidas.TierSES, eidas.TierSES); err != nil {
		t.Fatalf("SES send rejected: %v", err)
	}
}

func TestGuardEnvelopeEIDASSendFailsClosedOnInvalidChildVariables(t *testing.T) {
	family := []*generated.Document{
		{ID: uuid.New(), VariablesJson: json.RawMessage(`{}`)},
		{ID: uuid.New(), VariablesJson: json.RawMessage(`{"deal_amount":"not-money"}`)},
	}
	if _, err := guardEnvelopeEIDASSend(context.Background(), &amountTierEvaluator{}, uuid.New(), eidas.TierQES, family); err == nil {
		t.Fatal("invalid child variables should fail envelope eIDAS evaluation")
	}
}

type amountTierEvaluator struct {
	inputs []eidas.EvaluateInput
}

func (e *amountTierEvaluator) Evaluate(_ context.Context, _ uuid.UUID, input eidas.EvaluateInput) (eidas.Decision, error) {
	e.inputs = append(e.inputs, input)
	decision := eidas.Decision{RequiredTier: eidas.TierSES, EvaluatedCount: 2}
	switch {
	case input.Amount >= 1_000_000:
		decision.RequiredTier = eidas.TierQES
		decision.MatchedRules = []eidas.MatchedRule{{ID: "qes", Name: "High value", RequiredTier: eidas.TierQES}}
	case input.Amount >= 100_000:
		decision.RequiredTier = eidas.TierAES
		decision.MatchedRules = []eidas.MatchedRule{{ID: "aes", Name: "Elevated value", RequiredTier: eidas.TierAES}}
	}
	return decision, nil
}
