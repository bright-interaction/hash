// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"regexp"
	"sort"
	"strings"
)

// varPattern matches `{{name}}` or `{{ ns.name }}` with optional whitespace.
// Names use letters, digits, underscores, and dots. The dotted form lets us
// namespace context: `{{recipient.name}}`, `{{document.signed_date}}`,
// `{{org.legal_name}}`, plus arbitrary user-defined `{{amount}}`.
var varPattern = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*\}\}`)

// ParseVariableValues decodes the only contract-variable shape Hash accepts:
// a JSON object whose values are strings. Keeping numbers, booleans, arrays,
// and objects out of this boundary prevents JSON's float64 decoding from
// rounding contractual values (for example integers above 2^53) or changing
// their authored lexical representation.
func ParseVariableValues(raw []byte) (map[string]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return map[string]string{}, nil
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("variables must be a JSON object of string values")
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &encoded); err != nil || encoded == nil {
		return nil, fmt.Errorf("variables must be a JSON object of string values")
	}
	values := make(map[string]string, len(encoded))
	for name, rawValue := range encoded {
		if !conditionVariableNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid variable name %q", name)
		}
		valueBytes := bytes.TrimSpace(rawValue)
		if len(valueBytes) == 0 || valueBytes[0] != '"' {
			return nil, fmt.Errorf("variable %q must be a string", name)
		}
		var value string
		if err := json.Unmarshal(valueBytes, &value); err != nil {
			return nil, fmt.Errorf("variable %q must be a string", name)
		}
		values[name] = value
	}
	return values, nil
}

// Substitute replaces every `{{name}}` token in s with the value from vars.
// Tokens with no matching key render as the original token (so authors see
// missing context rather than silently produce blank docs).
func Substitute(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return varPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := varPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		key := sub[1]
		if v, ok := vars[key]; ok {
			return v
		}
		return match
	})
}

// ExtractVariableNames returns the unique variable names referenced in a
// document. Useful for the editor's "fill these in" UX and for telling
// agents what context the document expects.
func ExtractVariableNames(t *Tree) []string {
	if t == nil {
		return nil
	}
	seen := map[string]struct{}{}
	walkTree(t, func(b *Block) {
		// `dynamic_variable` blocks reference a name explicitly.
		if b.Type == TypeDynamicVar {
			if name := b.AttrString("name", ""); name != "" {
				seen[name] = struct{}{}
			}
		}
		if b.Type == TypeConditional {
			names, err := ConditionVariableNames(b.AttrString("expression", ""))
			if err == nil {
				for _, name := range names {
					seen[name] = struct{}{}
				}
			}
		}
		// Text-bearing blocks may contain {{ }} tokens.
		if b.Text != "" {
			for _, m := range varPattern.FindAllStringSubmatch(b.Text, -1) {
				seen[m[1]] = struct{}{}
			}
		}
		// Table cells.
		for _, row := range b.Rows {
			for _, cell := range row {
				for _, m := range varPattern.FindAllStringSubmatch(cell, -1) {
					seen[m[1]] = struct{}{}
				}
			}
		}
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// ValidateVariablePlaceholders verifies that every mustache-looking sequence
// uses Hash's supported {{name}} grammar and appears on a surface RenderHTML
// actually substitutes. Without this check, a value could exist in the frozen
// variable map while a token in a code block, raw HTML block, or table heading
// remained literal in the immutable PDF.
func ValidateVariablePlaceholders(t *Tree) error {
	if t == nil {
		return nil
	}
	var validationErr error
	walkTree(t, func(b *Block) {
		if validationErr != nil {
			return
		}
		if b.Type == TypeConditional {
			if _, err := ConditionVariableNames(b.AttrString("expression", "")); err != nil {
				validationErr = fmt.Errorf("block %q condition: %w", b.ID, err)
				return
			}
		}
		if b.Type == TypeRawHTML {
			// Raw HTML is intentionally never substituted. Decode character
			// references before checking so `&#123;`, hexadecimal variants, and
			// braces split across elements cannot smuggle a literal mustache token
			// into the signer/PDF surface after sanitization.
			if strings.ContainsAny(stdhtml.UnescapeString(b.Text), "{}") {
				validationErr = fmt.Errorf("block %q raw HTML: braces are not allowed on this non-substituted surface", b.ID)
				return
			}
		}

		textSupported := false
		switch b.Type {
		case TypeHeading, TypeParagraph:
			textSupported = true
		case TypeListItem, TypeQuote, TypeCallout:
			// RenderHTML ignores the parent Text when nested Content is present.
			textSupported = len(b.Content) == 0
		}
		if err := validatePlaceholderSurface(b.Text, textSupported); err != nil {
			validationErr = fmt.Errorf("block %q text: %w", b.ID, err)
			return
		}

		for rowIndex, row := range b.Rows {
			for cellIndex, cell := range row {
				if err := validatePlaceholderSurface(cell, b.Type == TypeTable); err != nil {
					validationErr = fmt.Errorf("block %q row %d cell %d: %w", b.ID, rowIndex, cellIndex, err)
					return
				}
			}
		}

		// No attribute is passed through Substitute. This deliberately includes
		// table column headings, dynamic-variable defaults, labels, and alt text.
		keys := make([]string, 0, len(b.Attrs))
		for key := range b.Attrs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if attrContainsPlaceholder(b.Attrs[key]) {
				validationErr = fmt.Errorf("block %q attribute %q: variable placeholders are not supported on this surface", b.ID, key)
				return
			}
		}
	})
	return validationErr
}

// ValidateResolvedVariableValues applies the full immutable-variable contract
// and returns the exact string map renderers must use. It is shared by send,
// sealing recovery, signer views, and finalization so older active rows cannot
// bypass a gate merely by entering the lifecycle before a newer binary.
func ValidateResolvedVariableValues(t *Tree, raw json.RawMessage) (map[string]string, error) {
	if t == nil {
		return nil, fmt.Errorf("block tree is nil")
	}
	if err := ValidateVariablePlaceholders(t); err != nil {
		return nil, err
	}
	values, err := ParseVariableValues(raw)
	if err != nil {
		return nil, err
	}
	hardReferences := make(map[string]struct{})
	unresolvedSet := make(map[string]struct{})
	walkTree(t, func(block *Block) {
		if block.Type == TypeConditional {
			names, _ := ConditionVariableNames(block.AttrString("expression", ""))
			for _, name := range names {
				hardReferences[name] = struct{}{}
			}
		}
		for _, match := range varPattern.FindAllStringSubmatch(block.Text, -1) {
			hardReferences[match[1]] = struct{}{}
		}
		for _, row := range block.Rows {
			for _, cell := range row {
				for _, match := range varPattern.FindAllStringSubmatch(cell, -1) {
					hardReferences[match[1]] = struct{}{}
				}
			}
		}
		if block.Type == TypeDynamicVar {
			name := block.AttrString("name", "")
			value, present := values[name]
			if present && validResolvedValue(value) {
				return
			}
			// A dynamic_variable's authored default applies to that exact block
			// only. It is frozen in the canonical tree and therefore safe to use,
			// but it must not satisfy a {{name}} or condition reference elsewhere.
			if !validResolvedValue(block.AttrString("default", "")) {
				unresolvedSet[name] = struct{}{}
			}
		}
	})
	for name := range hardReferences {
		value, ok := values[name]
		if !ok || !validResolvedValue(value) {
			unresolvedSet[name] = struct{}{}
		}
	}
	unresolved := make([]string, 0, len(unresolvedSet))
	for name := range unresolvedSet {
		unresolved = append(unresolved, name)
	}
	if len(unresolved) != 0 {
		sort.Strings(unresolved)
		return nil, fmt.Errorf("unresolved variables: %s", strings.Join(unresolved, ", "))
	}
	if err := ValidateConditionalEvaluation(t, values); err != nil {
		return nil, err
	}
	return values, nil
}

func validResolvedValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && !strings.Contains(trimmed, "{{") && !strings.Contains(trimmed, "}}")
}

func validatePlaceholderSurface(value string, supported bool) error {
	if !containsPlaceholderDelimiter(value) {
		return nil
	}
	if !supported {
		return fmt.Errorf("variable placeholders are not supported on this surface")
	}
	remainder := value
	for {
		open := strings.Index(remainder, "{{")
		close := strings.Index(remainder, "}}")
		if open == -1 && close == -1 {
			return nil
		}
		if open == -1 || (close >= 0 && close < open) {
			return fmt.Errorf("invalid variable placeholder syntax")
		}
		if open > 0 && remainder[open-1] == '{' {
			return fmt.Errorf("invalid variable placeholder syntax")
		}
		relativeClose := strings.Index(remainder[open+2:], "}}")
		if relativeClose < 0 {
			return fmt.Errorf("invalid variable placeholder syntax")
		}
		end := open + 2 + relativeClose + 2
		token := remainder[open:end]
		match := varPattern.FindStringIndex(token)
		if match == nil || match[0] != 0 || match[1] != len(token) {
			return fmt.Errorf("invalid variable placeholder syntax")
		}
		if end < len(remainder) && remainder[end] == '}' {
			return fmt.Errorf("invalid variable placeholder syntax")
		}
		remainder = remainder[end:]
	}
}

func containsPlaceholderDelimiter(value string) bool {
	return strings.Contains(value, "{{") || strings.Contains(value, "}}")
}

func attrContainsPlaceholder(value any) bool {
	switch typed := value.(type) {
	case string:
		return containsPlaceholderDelimiter(typed)
	case []string:
		for _, item := range typed {
			if containsPlaceholderDelimiter(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if attrContainsPlaceholder(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if attrContainsPlaceholder(item) {
				return true
			}
		}
	}
	return false
}

// walkTree calls fn on every block in t, including nested content. Pre-order.
func walkTree(t *Tree, fn func(*Block)) {
	if t == nil {
		return
	}
	walkBlocks(t.Blocks, fn)
}

func walkBlocks(blocks []Block, fn func(*Block)) {
	for i := range blocks {
		fn(&blocks[i])
		if len(blocks[i].Content) > 0 {
			walkBlocks(blocks[i].Content, fn)
		}
	}
}
