// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package eidas implements Phase 9.2 (#4): smart eIDAS tier escalation.
//
// Each org configures rules (predicate + required_tier). On send, the
// engine evaluates every active rule against the document's metadata +
// resolved variables. The highest required tier across matched rules
// becomes the gating tier; if the document's selected routing_tier is
// below that, send is refused with a clear message naming the rule.
//
// Tier ladder (low to high):
//
//	SES (Simple Electronic Signature):    default. Magic link + typed
//	                                      name + ed25519 audit cert.
//	AES (Advanced Electronic Signature):  identity-bound. Requires the
//	                                      signer to authenticate via
//	                                      OIDC OR provide a verified
//	                                      email proof challenge.
//	QES (Qualified Electronic Signature): QTSP-backed (Idura/Signicat/
//	                                      Scrive). Wired via the
//	                                      resolver path in Phase 11+;
//	                                      here we just gate on
//	                                      routing_tier=QES.
//
// Predicate shape (predicate_json):
//
//	{
//	  "field": "amount" | "variables.<key>" | "country" | "document_type",
//	  "op":    ">=" | ">" | "<=" | "<" | "==" | "!=" | "in",
//	  "value": 100000 | "SE" | ["SE","NO"]
//	}
//
// Rules can also combine via "any" / "all" wrappers:
//
//	{ "all": [predicate, predicate, ...] }
//	{ "any": [predicate, predicate, ...] }
package eidas

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Tier is the eIDAS ladder. The Cmp method makes "higher = stricter"
// readable at every guard site.
type Tier string

const (
	TierSES Tier = "SES"
	TierAES Tier = "AES"
	TierQES Tier = "QES"
)

var ErrHigherTierUnavailable = errors.New("active AES/QES routing rules are unavailable until those signing tiers are production-capable")

// ValidateRuleActivation prevents API clients from creating or reactivating
// a rule that makes matching documents unsendable in this SES-only release.
// Inactive higher-tier rules may remain visible for migration or deletion.
func ValidateRuleActivation(t Tier, active bool) error {
	if !t.Valid() {
		return errors.New("required tier must be SES, AES, or QES")
	}
	if active && t != TierSES {
		return ErrHigherTierUnavailable
	}
	return nil
}

// Cmp returns negative if a is lower than b, 0 if equal, positive if
// higher. Unknown values sort low.
func (a Tier) Cmp(b Tier) int {
	return rank(a) - rank(b)
}

func rank(t Tier) int {
	switch t {
	case TierSES:
		return 1
	case TierAES:
		return 2
	case TierQES:
		return 3
	}
	return 0
}

// Valid reports whether t is one of the three recognised tiers.
func (t Tier) Valid() bool {
	return rank(t) > 0
}

// Engine owns rule storage + evaluation. Hold one process-wide.
type Engine struct {
	Q *generated.Queries
}

func New(q *generated.Queries) *Engine { return &Engine{Q: q} }

// EvaluateInput describes what the engine sees when deciding the tier
// for a send. The handler builds this from the resolved variables + a
// few document-level facts; we don't take the full Document so the
// engine stays trivially unit-testable.
type EvaluateInput struct {
	Country      string
	DocumentType string
	// Amount is the canonical numeric value of the deal. Handlers
	// extract it from resolved variables (typically "deal_amount") OR
	// from the document's own metadata. 0 means "not specified".
	Amount float64
	// Variables is the full resolved variable map. Predicates can
	// reference any key via "variables.<key>".
	Variables map[string]string
}

// Decision is what Evaluate returns.
type Decision struct {
	RequiredTier   Tier          `json:"required_tier"`
	MatchedRules   []MatchedRule `json:"matched_rules"`
	EvaluatedCount int           `json:"evaluated_count"`
}

// MatchedRule names the rule that contributed to the required tier so
// the UI can show "this rule forced AES" + the rule's reason.
type MatchedRule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RequiredTier Tier   `json:"required_tier"`
	Reason       string `json:"reason"`
}

// Evaluate runs every active rule for the org against the input and
// returns the highest required tier across matches plus the list of
// rules that matched. Returns Decision{RequiredTier: TierSES} when no
// rule matches (SES is the implicit floor).
func (e *Engine) Evaluate(ctx context.Context, orgID uuid.UUID, in EvaluateInput) (Decision, error) {
	rules, err := e.Q.ListActiveEIDASRules(ctx, orgID)
	if err != nil {
		return Decision{}, fmt.Errorf("eidas: list rules: %w", err)
	}
	return evaluateActiveRules(rules, in)
}

func evaluateActiveRules(rules []*generated.EidasRoutingRule, in EvaluateInput) (Decision, error) {
	// Keep the public response shape stable when no rule matches. A nil slice
	// serializes as JSON null, which forces every API consumer to special-case
	// the ordinary "no matches" result instead of iterating an empty array.
	out := Decision{
		RequiredTier:   TierSES,
		MatchedRules:   []MatchedRule{},
		EvaluatedCount: len(rules),
	}
	for _, r := range rules {
		if r == nil {
			return Decision{}, errors.New("eidas: active rule row is nil")
		}
		t := Tier(r.RequiredTier)
		if err := ValidateRule(r.PredicateJson, t); err != nil {
			return Decision{}, fmt.Errorf("eidas: active rule %q (%s) is invalid: %w", r.Name, r.ID, err)
		}
		match, err := matchPredicate(r.PredicateJson, in)
		if err != nil {
			return Decision{}, fmt.Errorf("eidas: evaluate active rule %q (%s): %w", r.Name, r.ID, err)
		}
		if !match {
			continue
		}
		out.MatchedRules = append(out.MatchedRules, MatchedRule{
			ID:           r.ID.String(),
			Name:         r.Name,
			RequiredTier: t,
			Reason:       r.Reason,
		})
		if t.Cmp(out.RequiredTier) > 0 {
			out.RequiredTier = t
		}
	}
	// Sort matched rules by required tier descending so the UI's
	// "highest first" presentation matches the engine's choice.
	sort.SliceStable(out.MatchedRules, func(i, j int) bool {
		return rank(out.MatchedRules[i].RequiredTier) > rank(out.MatchedRules[j].RequiredTier)
	})
	return out, nil
}

// GuardSend is the single check the send handler calls. Returns nil if
// the document's current routing_tier satisfies the required tier;
// otherwise returns a *GuardError with a clear, user-facing message.
func (e *Engine) GuardSend(ctx context.Context, orgID uuid.UUID, currentTier Tier, in EvaluateInput) (Decision, error) {
	decision, err := e.Evaluate(ctx, orgID, in)
	if err != nil {
		return decision, err
	}
	if currentTier.Cmp(decision.RequiredTier) >= 0 {
		return decision, nil
	}
	return decision, &GuardError{
		Decision:    decision,
		CurrentTier: currentTier,
	}
}

// GuardError signals a send was blocked because the document's selected
// tier is below the required tier. Handlers should return a 409 with
// the embedded message so the UI can prompt the user to bump the tier.
type GuardError struct {
	Decision    Decision
	CurrentTier Tier
}

func (e *GuardError) Error() string {
	if len(e.Decision.MatchedRules) == 0 {
		return fmt.Sprintf("eidas: tier %s required, document is %s", e.Decision.RequiredTier, e.CurrentTier)
	}
	var parts []string
	for _, m := range e.Decision.MatchedRules {
		parts = append(parts, fmt.Sprintf("%q (%s)", m.Name, m.RequiredTier))
	}
	return fmt.Sprintf(
		"eidas: %s required (document is %s); matched rules: %s",
		e.Decision.RequiredTier, e.CurrentTier, strings.Join(parts, ", "),
	)
}

// SeedSwedishDefaults is retained as a fail-closed compatibility surface.
// Every historic default selected AES or QES and included legal assumptions
// the product cannot substantiate. It must not write until those ceremonies
// exist and the defaults receive transaction-specific legal review.
func (e *Engine) SeedSwedishDefaults(ctx context.Context, orgID uuid.UUID) error {
	return ErrHigherTierUnavailable
}
