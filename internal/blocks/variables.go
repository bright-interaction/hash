package blocks

import (
	"regexp"
	"strings"
)

// varPattern matches `{{name}}` or `{{ ns.name }}` with optional whitespace.
// Names use letters, digits, underscores, and dots. The dotted form lets us
// namespace context: `{{recipient.name}}`, `{{document.signed_date}}`,
// `{{org.legal_name}}`, plus arbitrary user-defined `{{amount}}`.
var varPattern = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*\}\}`)

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
