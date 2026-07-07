package blocks

import (
	"strconv"
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
// If the expression fails to parse we return false and never raise; agents
// should produce well-formed expressions and the editor's UX prevents bad
// ones at author time.
func EvalCondition(expr string, vars map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	v, _ := evalOr(expr, vars)
	return v
}

func evalOr(s string, vars map[string]string) (bool, string) {
	left, rest := evalAnd(s, vars)
	for {
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, "||") {
			return left, rest
		}
		var right bool
		right, rest = evalAnd(rest[2:], vars)
		left = left || right
	}
}

func evalAnd(s string, vars map[string]string) (bool, string) {
	left, rest := evalCmp(s, vars)
	for {
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, "&&") {
			return left, rest
		}
		var right bool
		right, rest = evalCmp(rest[2:], vars)
		left = left && right
	}
}

func evalCmp(s string, vars map[string]string) (bool, string) {
	leftVal, rest := evalAtom(s, vars)
	rest = strings.TrimSpace(rest)
	op, opLen := matchOp(rest)
	if op == "" {
		return truthy(leftVal), rest
	}
	rest = rest[opLen:]
	rightVal, rest := evalAtom(rest, vars)

	switch op {
	case "==":
		return leftVal == rightVal, rest
	case "!=":
		return leftVal != rightVal, rest
	case ">":
		return numericCompare(leftVal, rightVal) > 0, rest
	case ">=":
		return numericCompare(leftVal, rightVal) >= 0, rest
	case "<":
		return numericCompare(leftVal, rightVal) < 0, rest
	case "<=":
		return numericCompare(leftVal, rightVal) <= 0, rest
	}
	return false, rest
}

func matchOp(s string) (op string, length int) {
	switch {
	case strings.HasPrefix(s, "=="):
		return "==", 2
	case strings.HasPrefix(s, "!="):
		return "!=", 2
	case strings.HasPrefix(s, ">="):
		return ">=", 2
	case strings.HasPrefix(s, "<="):
		return "<=", 2
	case strings.HasPrefix(s, ">"):
		return ">", 1
	case strings.HasPrefix(s, "<"):
		return "<", 1
	}
	return "", 0
}

// evalAtom parses one atom from the front of s. Returns the resolved string
// value plus the remaining unparsed input. Supported atoms:
//   - var(name)            looks up the variable
//   - "double-quoted"      literal string
//   - 'single-quoted'      literal string
//   - 123 / 1.5            numeric literal (returned as canonical string)
//   - true / false         bool literal (as "true" / "false")
func evalAtom(s string, vars map[string]string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	switch {
	case strings.HasPrefix(s, "var("):
		end := strings.Index(s, ")")
		if end < 0 {
			return "", ""
		}
		name := strings.TrimSpace(s[4:end])
		return vars[name], s[end+1:]
	case strings.HasPrefix(s, `"`):
		return readQuoted(s[1:], '"')
	case strings.HasPrefix(s, `'`):
		return readQuoted(s[1:], '\'')
	case strings.HasPrefix(s, "true"):
		return "true", s[4:]
	case strings.HasPrefix(s, "false"):
		return "false", s[5:]
	}
	// Numeric literal: read until whitespace or operator.
	end := 0
	for end < len(s) {
		c := s[end]
		if c == ' ' || c == '\t' || c == '&' || c == '|' || c == '!' ||
			c == '=' || c == '<' || c == '>' || c == ')' {
			break
		}
		end++
	}
	return s[:end], s[end:]
}

func readQuoted(s string, quote byte) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == quote {
			return s[:i], s[i+1:]
		}
	}
	return s, "" // unterminated; return everything
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "false", "0", "no":
		return false
	}
	return true
}

func numericCompare(a, b string) int {
	an, aErr := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bn, bErr := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if aErr == nil && bErr == nil {
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	}
	// Lexical fallback so string comparisons still work.
	return strings.Compare(a, b)
}
