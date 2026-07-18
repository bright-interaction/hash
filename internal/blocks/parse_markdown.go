// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"strings"
)

// ParseMarkdown converts a CommonMark-ish markdown body into a block tree.
// It is intentionally a small subset: headings (# .. ######), paragraphs,
// blockquotes, bullet/ordered lists, code fences, horizontal rules, and
// tables. More elaborate markdown is rarely needed in contracts; agents
// should reach for explicit block types when they need precision.
func ParseMarkdown(src string) *Tree {
	t := MustEmptyTree()
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Blank line: skip.
		if trimmed == "" {
			i++
			continue
		}

		// Heading.
		if lvl, rest := headingPrefix(trimmed); lvl > 0 {
			t.Blocks = append(t.Blocks, Block{
				ID:    generateBlockID(),
				Type:  TypeHeading,
				Attrs: map[string]any{"level": float64(lvl)},
				Text:  rest,
			})
			i++
			continue
		}

		// Horizontal rule.
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			t.Blocks = append(t.Blocks, Block{ID: generateBlockID(), Type: TypeDivider})
			i++
			continue
		}

		// Code fence.
		if strings.HasPrefix(trimmed, "```") {
			lang := strings.TrimPrefix(trimmed, "```")
			i++
			var body []string
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				body = append(body, lines[i])
				i++
			}
			if i < len(lines) {
				i++ // consume closing fence
			}
			t.Blocks = append(t.Blocks, Block{
				ID:    generateBlockID(),
				Type:  TypeCode,
				Attrs: map[string]any{"language": lang},
				Text:  strings.Join(body, "\n"),
			})
			continue
		}

		// Blockquote.
		if strings.HasPrefix(trimmed, ">") {
			var body []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), ">") {
				stripped := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), ">"))
				body = append(body, stripped)
				i++
			}
			t.Blocks = append(t.Blocks, Block{
				ID:   generateBlockID(),
				Type: TypeQuote,
				Text: strings.Join(body, " "),
			})
			continue
		}

		// Bullet list.
		if isBullet(trimmed) {
			items, consumed := readListItems(lines[i:], false)
			t.Blocks = append(t.Blocks, Block{
				ID:      generateBlockID(),
				Type:    TypeBulletList,
				Content: items,
			})
			i += consumed
			continue
		}

		// Ordered list.
		if isOrdered(trimmed) {
			items, consumed := readListItems(lines[i:], true)
			t.Blocks = append(t.Blocks, Block{
				ID:      generateBlockID(),
				Type:    TypeOrderedList,
				Content: items,
			})
			i += consumed
			continue
		}

		// Table (simple GFM): line containing pipes followed by a separator
		// line.
		if isTableHeader(line, lines, i) {
			tbl, consumed := readTable(lines[i:])
			if tbl != nil {
				t.Blocks = append(t.Blocks, *tbl)
				i += consumed
				continue
			}
		}

		// Default: paragraph (collect until blank line).
		var body []string
		for i < len(lines) && strings.TrimSpace(lines[i]) != "" {
			body = append(body, strings.TrimSpace(lines[i]))
			i++
		}
		t.Blocks = append(t.Blocks, Block{
			ID:   generateBlockID(),
			Type: TypeParagraph,
			Text: strings.Join(body, " "),
		})
	}
	return t
}

func headingPrefix(line string) (int, string) {
	for n := 6; n >= 1; n-- {
		prefix := strings.Repeat("#", n) + " "
		if strings.HasPrefix(line, prefix) {
			return n, strings.TrimSpace(line[len(prefix):])
		}
	}
	return 0, ""
}

func isBullet(line string) bool {
	return strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "+ ")
}

func isOrdered(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' && i > 0 && i+1 < len(line) && line[i+1] == ' ' {
			return true
		}
		return false
	}
	return false
}

func readListItems(lines []string, ordered bool) ([]Block, int) {
	var items []Block
	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		var content string
		if !ordered && isBullet(trimmed) {
			content = strings.TrimSpace(trimmed[2:])
		} else if ordered && isOrdered(trimmed) {
			dot := strings.Index(trimmed, ". ")
			content = strings.TrimSpace(trimmed[dot+2:])
		} else {
			break
		}
		items = append(items, Block{
			ID:   generateBlockID(),
			Type: TypeListItem,
			Text: content,
		})
		i++
	}
	return items, i
}

func isTableHeader(line string, lines []string, idx int) bool {
	if !strings.Contains(line, "|") {
		return false
	}
	if idx+1 >= len(lines) {
		return false
	}
	sep := strings.TrimSpace(lines[idx+1])
	if !strings.Contains(sep, "|") || !strings.Contains(sep, "-") {
		return false
	}
	return true
}

func readTable(lines []string) (*Block, int) {
	if len(lines) < 2 {
		return nil, 0
	}
	headerCells := splitTableRow(lines[0])
	if len(headerCells) == 0 {
		return nil, 0
	}
	colsAny := make([]any, len(headerCells))
	for i, c := range headerCells {
		colsAny[i] = c
	}
	tbl := &Block{
		ID:    generateBlockID(),
		Type:  TypeTable,
		Attrs: map[string]any{"columns": colsAny},
		Rows:  [][]string{},
	}
	consumed := 2 // header + separator
	for consumed < len(lines) {
		line := lines[consumed]
		if strings.TrimSpace(line) == "" || !strings.Contains(line, "|") {
			break
		}
		cells := splitTableRow(line)
		if len(cells) == len(headerCells) {
			tbl.Rows = append(tbl.Rows, cells)
		}
		consumed++
	}
	return tbl, consumed
}

func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}
