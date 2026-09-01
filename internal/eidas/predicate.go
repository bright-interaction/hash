// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package eidas

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ValidateRule checks the full persisted rule shape without depending on a
// particular evaluation input. Send-time matching cannot be used as schema
// validation because a missing variable short-circuits before an invalid
// operator/value is examined. Every write surface calls this, and Evaluate
// calls it again for defense against legacy or directly inserted corrupt rows.
func ValidateRule(raw json.RawMessage, requiredTier Tier) error {
	if !requiredTier.Valid() {
		return fmt.Errorf("required_tier must be SES, AES, or QES (got %q)", requiredTier)
	}
	if err := validatePredicateShape(raw, "predicate"); err != nil {
		return err
	}
	return nil
}

func validatePredicateShape(raw json.RawMessage, path string) error {
	if len(raw) == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("%s must be a JSON object: %w", path, err)
	}
	if object == nil {
		return fmt.Errorf("%s must be a JSON object", path)
	}
	allRaw, hasAll := object["all"]
	anyRaw, hasAny := object["any"]
	if hasAll || hasAny {
		if hasAll && hasAny {
			return fmt.Errorf("%s cannot contain both all and any", path)
		}
		if len(object) != 1 {
			return fmt.Errorf("%s composite cannot mix all/any with leaf or unknown fields", path)
		}
		kind, childrenRaw := "all", allRaw
		if hasAny {
			kind, childrenRaw = "any", anyRaw
		}
		var children []json.RawMessage
		if err := json.Unmarshal(childrenRaw, &children); err != nil || len(children) == 0 {
			return fmt.Errorf("%s.%s must be a non-empty predicate array", path, kind)
		}
		for i, child := range children {
			if err := validatePredicateShape(child, fmt.Sprintf("%s.%s[%d]", path, kind, i)); err != nil {
				return err
			}
		}
		return nil
	}

	for key := range object {
		switch key {
		case "field", "op", "value":
		default:
			return fmt.Errorf("%s contains unknown field %q", path, key)
		}
	}
	if len(object) != 3 {
		return fmt.Errorf("%s leaf requires exactly field, op, and value", path)
	}
	var field, op string
	if err := json.Unmarshal(object["field"], &field); err != nil || field == "" {
		return fmt.Errorf("%s.field must be a non-empty string", path)
	}
	if err := json.Unmarshal(object["op"], &op); err != nil || op == "" {
		return fmt.Errorf("%s.op must be a non-empty string", path)
	}
	if field != "amount" && field != "country" && field != "document_type" &&
		!(strings.HasPrefix(field, "variables.") && len(strings.TrimPrefix(field, "variables.")) > 0) {
		return fmt.Errorf("%s.field %q is not supported", path, field)
	}
	value := object["value"]
	switch op {
	case "in":
		var values []json.RawMessage
		if err := json.Unmarshal(value, &values); err != nil || len(values) == 0 {
			return fmt.Errorf("%s.value must be a non-empty array for op in", path)
		}
		for i, candidate := range values {
			if err := validateComparableScalar(candidate); err != nil {
				return fmt.Errorf("%s.value[%d]: %w", path, i, err)
			}
		}
	case "==", "!=":
		if err := validateComparableScalar(value); err != nil {
			return fmt.Errorf("%s.value: %w", path, err)
		}
	case ">", ">=", "<", "<=":
		var number float64
		if err := json.Unmarshal(value, &number); err != nil {
			return fmt.Errorf("%s.value must be a number for op %s", path, op)
		}
	default:
		return fmt.Errorf("%s.op %q is not supported", path, op)
	}
	return nil
}

func validateComparableScalar(raw json.RawMessage) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("must be a string or number")
	}
	switch value.(type) {
	case string, float64:
		return nil
	default:
		return errors.New("must be a string or number")
	}
}

// matchPredicate is the dispatch root. Supports leaf predicates +
// "all"/"any" composites. Designed so a rule author can build complex
// logic in JSON without us ever evaluating arbitrary user-supplied
// expressions (no eval, no script injection).
func matchPredicate(raw json.RawMessage, in EvaluateInput) (bool, error) {
	if len(raw) == 0 {
		return false, errors.New("empty predicate")
	}
	// Composite checks first.
	var composite struct {
		All []json.RawMessage `json:"all"`
		Any []json.RawMessage `json:"any"`
	}
	if err := json.Unmarshal(raw, &composite); err == nil {
		if len(composite.All) > 0 {
			for _, child := range composite.All {
				ok, err := matchPredicate(child, in)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, nil
				}
			}
			return true, nil
		}
		if len(composite.Any) > 0 {
			for _, child := range composite.Any {
				ok, err := matchPredicate(child, in)
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
			return false, nil
		}
	}

	// Leaf predicate.
	var leaf struct {
		Field string          `json:"field"`
		Op    string          `json:"op"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &leaf); err != nil {
		return false, fmt.Errorf("predicate decode: %w", err)
	}
	if leaf.Field == "" || leaf.Op == "" {
		return false, errors.New("predicate missing field/op")
	}
	actual, err := readField(leaf.Field, in)
	if err != nil {
		return false, err
	}
	return compare(actual, leaf.Op, leaf.Value)
}

// fieldValue is either a number or a string. We coerce on read so the
// comparator can short-circuit by type.
type fieldValue struct {
	num float64
	str string
	// has a value at all (used to distinguish "missing" from "zero")
	present bool
	// numeric reading succeeded
	isNumber bool
}

func readField(field string, in EvaluateInput) (fieldValue, error) {
	switch {
	case field == "amount":
		return fieldValue{num: in.Amount, present: true, isNumber: true}, nil
	case field == "country":
		return fieldValue{str: in.Country, present: in.Country != ""}, nil
	case field == "document_type":
		return fieldValue{str: in.DocumentType, present: in.DocumentType != ""}, nil
	case strings.HasPrefix(field, "variables."):
		key := strings.TrimPrefix(field, "variables.")
		if v, ok := in.Variables[key]; ok {
			fv := fieldValue{str: v, present: true}
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				fv.num = n
				fv.isNumber = true
			}
			return fv, nil
		}
		return fieldValue{}, nil
	default:
		return fieldValue{}, fmt.Errorf("unknown predicate field %q", field)
	}
}

// compare evaluates op against the read field value + the supplied
// JSON value. Missing fields never match (no rule should silently fire
// because a variable wasn't resolved).
func compare(actual fieldValue, op string, raw json.RawMessage) (bool, error) {
	if !actual.present {
		return false, nil
	}
	switch op {
	case "in":
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return false, fmt.Errorf(`op "in" expects an array value`)
		}
		for _, candidate := range arr {
			ok, err := compare(actual, "==", candidate)
			if err == nil && ok {
				return true, nil
			}
		}
		return false, nil
	case "==", "!=":
		// Try number first, fall back to string for type-aware equality.
		var n float64
		if err := json.Unmarshal(raw, &n); err == nil && actual.isNumber {
			match := actual.num == n
			if op == "!=" {
				match = !match
			}
			return match, nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			match := actual.str == s
			if op == "!=" {
				match = !match
			}
			return match, nil
		}
		return false, fmt.Errorf(`op %q: value must be number or string`, op)
	case ">", ">=", "<", "<=":
		var n float64
		if err := json.Unmarshal(raw, &n); err != nil {
			return false, fmt.Errorf(`op %q: value must be a number`, op)
		}
		if !actual.isNumber {
			return false, nil
		}
		switch op {
		case ">":
			return actual.num > n, nil
		case ">=":
			return actual.num >= n, nil
		case "<":
			return actual.num < n, nil
		case "<=":
			return actual.num <= n, nil
		}
	}
	return false, fmt.Errorf("unknown op %q", op)
}
