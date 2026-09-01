// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// EvalCondition evaluates a tiny allowlisted expression language against the
// variable map. Supported forms (all using the var(name) syntax to read
// values; quoted strings or numbers as literals):
//
//	var(amount) > 10000
//	var(country) == "SE"
//	var(country) != "US"
//	var(governing_law) == "Sweden" && var(has_nda) == "true"
//	var(amount) > 5000 || var(escalate) == "true"
//
// The grammar is deliberately small. No function calls, no arbitrary code,
// no recursion. Comparison operators: == != > >= < <=. Combinators: && ||.
// A bare `var(name)` reads as truthy if the value is non-empty and not
// equal to "false"/"0"/"no".
//
// If the expression fails to parse we return false. Validate and
// ConditionVariableNames expose the parse error to authoring and send-time
// gates; rendering remains fail-closed for legacy callers that only need a
// boolean.
func EvalCondition(expr string, vars map[string]string) bool {
	value, err := EvalConditionStrict(expr, vars)
	return err == nil && value
}

// EvalConditionStrict evaluates an expression and reports malformed or
// mistyped comparisons. Send, recovery, and finalization use this form so a
// localized/non-numeric amount cannot silently choose a contractual branch.
func EvalConditionStrict(expr string, vars map[string]string) (bool, error) {
	value, _, err := parseCondition(expr, vars)
	return value, err
}

// ConditionVariableNames strictly parses expr and returns every referenced
// var(name), sorted and deduplicated. Callers use this before freezing a
// document so a missing condition input cannot silently remove a clause from
// the immutable artifact.
func ConditionVariableNames(expr string) ([]string, error) {
	_, names, err := parseCondition(expr, nil)
	return names, err
}

// ValidateConditionalEvaluation proves that every conditional can be
// evaluated against the exact frozen string values used for rendering. It is
// intentionally separate from EvalCondition's boolean-only compatibility API
// so immutable lifecycle gates can distinguish false from invalid.
func ValidateConditionalEvaluation(t *Tree, vars map[string]string) error {
	if t == nil {
		return nil
	}
	var validationErr error
	walkTree(t, func(b *Block) {
		if validationErr != nil || b.Type != TypeConditional {
			return
		}
		if _, err := EvalConditionStrict(b.AttrString("expression", ""), vars); err != nil {
			validationErr = fmt.Errorf("block %q condition: %w", b.ID, err)
		}
	})
	return validationErr
}

var conditionVariableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\.]*$`)

type conditionParser struct {
	input string
	pos   int
	vars  map[string]string
	names map[string]struct{}
}

type conditionAtomKind uint8

const (
	conditionAtomVariable conditionAtomKind = iota
	conditionAtomString
	conditionAtomNumber
	conditionAtomBoolean
)

type conditionAtom struct {
	value string
	kind  conditionAtomKind
}

var strictDecimalPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func parseCondition(expr string, vars map[string]string) (bool, []string, error) {
	p := &conditionParser{
		input: strings.TrimSpace(expr),
		vars:  vars,
		names: make(map[string]struct{}),
	}
	if p.input == "" {
		return false, nil, fmt.Errorf("condition expression is empty")
	}
	value, err := p.parseOr()
	if err != nil {
		return false, nil, err
	}
	p.skipSpace()
	if p.pos != len(p.input) {
		return false, nil, p.errorf("unexpected trailing input")
	}
	names := make([]string, 0, len(p.names))
	for name := range p.names {
		names = append(names, name)
	}
	sort.Strings(names)
	return value, names, nil
}

func (p *conditionParser) parseOr() (bool, error) {
	left, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for {
		p.skipSpace()
		if !p.consume("||") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		left = left || right
	}
}

func (p *conditionParser) parseAnd() (bool, error) {
	left, err := p.parseComparison()
	if err != nil {
		return false, err
	}
	for {
		p.skipSpace()
		if !p.consume("&&") {
			return left, nil
		}
		right, err := p.parseComparison()
		if err != nil {
			return false, err
		}
		left = left && right
	}
}

func (p *conditionParser) parseComparison() (bool, error) {
	left, err := p.parseAtom()
	if err != nil {
		return false, err
	}
	p.skipSpace()
	op := ""
	for _, candidate := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if p.consume(candidate) {
			op = candidate
			break
		}
	}
	if op == "" {
		return truthy(left.value), nil
	}
	right, err := p.parseAtom()
	if err != nil {
		return false, err
	}
	switch op {
	case "==":
		return left.value == right.value, nil
	case "!=":
		return left.value != right.value, nil
	}
	if left.kind == conditionAtomString || left.kind == conditionAtomBoolean ||
		right.kind == conditionAtomString || right.kind == conditionAtomBoolean {
		return false, p.errorf("relational comparisons require numeric operands")
	}
	// ConditionVariableNames parses with nil vars to validate structure before
	// values exist. Runtime callers provide a non-nil frozen map and must prove
	// that every variable participating in a relational comparison is numeric.
	if p.vars == nil {
		return false, nil
	}
	comparison, err := numericCompare(left.value, right.value)
	if err != nil {
		return false, p.errorf("relational comparisons require numeric operands")
	}
	switch op {
	case ">":
		return comparison > 0, nil
	case ">=":
		return comparison >= 0, nil
	case "<":
		return comparison < 0, nil
	case "<=":
		return comparison <= 0, nil
	default:
		return false, p.errorf("unsupported comparison operator")
	}
}

// parseAtom parses one atom at the current cursor. Supported atoms:
//   - var(name)            looks up the variable
//   - "double-quoted"      literal string
//   - 'single-quoted'      literal string
//   - 123 / 1.5            numeric literal (returned as canonical string)
//   - true / false         bool literal (as "true" / "false")
func (p *conditionParser) parseAtom() (conditionAtom, error) {
	p.skipSpace()
	if p.pos >= len(p.input) {
		return conditionAtom{}, p.errorf("expected condition value")
	}
	rest := p.input[p.pos:]
	if strings.HasPrefix(rest, "var(") {
		p.pos += len("var(")
		end := strings.IndexByte(p.input[p.pos:], ')')
		if end < 0 {
			return conditionAtom{}, p.errorf("unterminated var()")
		}
		name := strings.TrimSpace(p.input[p.pos : p.pos+end])
		p.pos += end + 1
		if !conditionVariableNamePattern.MatchString(name) {
			return conditionAtom{}, p.errorf("invalid variable name")
		}
		p.names[name] = struct{}{}
		return conditionAtom{value: p.vars[name], kind: conditionAtomVariable}, nil
	}
	if rest[0] == '"' || rest[0] == '\'' {
		quote := rest[0]
		p.pos++
		start := p.pos
		for p.pos < len(p.input) && p.input[p.pos] != quote {
			p.pos++
		}
		if p.pos >= len(p.input) {
			return conditionAtom{}, p.errorf("unterminated quoted string")
		}
		value := p.input[start:p.pos]
		p.pos++
		return conditionAtom{value: value, kind: conditionAtomString}, nil
	}
	for _, literal := range []string{"true", "false"} {
		if strings.HasPrefix(rest, literal) && p.hasAtomBoundary(p.pos+len(literal)) {
			p.pos += len(literal)
			return conditionAtom{value: literal, kind: conditionAtomBoolean}, nil
		}
	}

	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == ' ' || c == '\t' || c == '&' || c == '|' || c == '!' ||
			c == '=' || c == '<' || c == '>' {
			break
		}
		p.pos++
	}
	if start == p.pos {
		return conditionAtom{}, p.errorf("expected condition value")
	}
	literal := p.input[start:p.pos]
	if _, err := parseStrictDecimal(literal); err != nil {
		return conditionAtom{}, p.errorf("expected a number, boolean, quoted string, or var(name)")
	}
	return conditionAtom{value: literal, kind: conditionAtomNumber}, nil
}

func (p *conditionParser) skipSpace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t' || p.input[p.pos] == '\n' || p.input[p.pos] == '\r') {
		p.pos++
	}
}

func (p *conditionParser) consume(token string) bool {
	if strings.HasPrefix(p.input[p.pos:], token) {
		p.pos += len(token)
		return true
	}
	return false
}

func (p *conditionParser) hasAtomBoundary(pos int) bool {
	if pos >= len(p.input) {
		return true
	}
	switch p.input[pos] {
	case ' ', '\t', '\n', '\r', '&', '|', '!', '=', '<', '>':
		return true
	default:
		return false
	}
}

func (p *conditionParser) errorf(message string) error {
	return fmt.Errorf("%s at byte %d", message, p.pos)
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "false", "0", "no":
		return false
	}
	return true
}

func numericCompare(a, b string) (int, error) {
	an, err := parseStrictDecimal(strings.TrimSpace(a))
	if err != nil {
		return 0, err
	}
	bn, err := parseStrictDecimal(strings.TrimSpace(b))
	if err != nil {
		return 0, err
	}
	return an.Cmp(bn), nil
}

func parseStrictDecimal(value string) (*big.Rat, error) {
	if !strictDecimalPattern.MatchString(value) {
		return nil, fmt.Errorf("not a decimal number")
	}
	number, ok := new(big.Rat).SetString(value)
	if !ok {
		return nil, fmt.Errorf("not a decimal number")
	}
	return number, nil
}
