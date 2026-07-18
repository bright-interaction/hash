// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a markdown representation of the tree. Used for
// agent round-trips ("read this document, edit it, post markdown back")
// and as the export format on the sender side.
func RenderMarkdown(t *Tree, vars map[string]string) string {
	if t == nil {
		return ""
	}
	var sb strings.Builder
	r := &mdRenderer{vars: vars}
	for _, b := range t.Blocks {
		r.render(&sb, &b, 0)
		sb.WriteString("\n")
	}
	return sb.String()
}

type mdRenderer struct {
	vars map[string]string
}

func (r *mdRenderer) render(sb *strings.Builder, b *Block, indent int) {
	pad := strings.Repeat("  ", indent)
	switch b.Type {
	case TypeHeading:
		fmt.Fprintf(sb, "%s%s %s\n", pad, strings.Repeat("#", b.HeadingLevel()), r.subst(b.Text))
	case TypeParagraph:
		fmt.Fprintf(sb, "%s%s\n", pad, r.subst(b.Text))
	case TypeBulletList:
		for _, c := range b.Content {
			r.renderListItem(sb, &c, indent, "- ")
		}
	case TypeOrderedList:
		for i, c := range b.Content {
			r.renderListItem(sb, &c, indent, fmt.Sprintf("%d. ", i+1))
		}
	case TypeListItem:
		// Standalone list_item; render with default bullet.
		r.renderListItem(sb, b, indent, "- ")
	case TypeTable:
		cols := stringSlice(b.Attrs["columns"])
		if len(cols) == 0 {
			return
		}
		sb.WriteString(pad)
		sb.WriteString("| ")
		sb.WriteString(strings.Join(cols, " | "))
		sb.WriteString(" |\n")
		sb.WriteString(pad)
		sb.WriteString("|")
		for range cols {
			sb.WriteString(" --- |")
		}
		sb.WriteString("\n")
		for _, row := range b.Rows {
			sb.WriteString(pad)
			sb.WriteString("| ")
			cells := make([]string, len(row))
			for i, cell := range row {
				cells[i] = r.subst(cell)
			}
			sb.WriteString(strings.Join(cells, " | "))
			sb.WriteString(" |\n")
		}
	case TypeImage:
		alt := b.AttrString("alt", "")
		key := b.AttrString("storage_key", "")
		fmt.Fprintf(sb, "%s![%s](/api/v1/storage/%s)\n", pad, alt, key)
	case TypeDivider, TypePageBreak:
		fmt.Fprintf(sb, "%s---\n", pad)
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		role := b.AttrString("recipient_role", "")
		label := b.AttrString("label", "")
		fmt.Fprintf(sb, "%s_[%s field for %s%s]_\n", pad, b.Type, role, suffix(label))
	case TypeDynamicVar:
		name := b.AttrString("name", "")
		val := r.vars[name]
		if val == "" {
			val = "{{" + name + "}}"
		}
		sb.WriteString(val)
	case TypeConditional:
		if EvalCondition(b.AttrString("expression", ""), r.vars) {
			for _, c := range b.Content {
				r.render(sb, &c, indent)
			}
		}
	case TypeCode:
		fmt.Fprintf(sb, "%s```%s\n%s\n%s```\n", pad, b.AttrString("language", ""), b.Text, pad)
	case TypeQuote:
		if len(b.Content) == 0 {
			fmt.Fprintf(sb, "%s> %s\n", pad, r.subst(b.Text))
		} else {
			for _, c := range b.Content {
				var inner strings.Builder
				r.render(&inner, &c, 0)
				for _, line := range strings.Split(strings.TrimRight(inner.String(), "\n"), "\n") {
					fmt.Fprintf(sb, "%s> %s\n", pad, line)
				}
			}
		}
	case TypeCallout:
		tone := b.AttrString("tone", "info")
		fmt.Fprintf(sb, "%s> **%s**\n", pad, strings.ToUpper(tone))
		if len(b.Content) == 0 {
			fmt.Fprintf(sb, "%s> %s\n", pad, r.subst(b.Text))
		} else {
			for _, c := range b.Content {
				var inner strings.Builder
				r.render(&inner, &c, 0)
				for _, line := range strings.Split(strings.TrimRight(inner.String(), "\n"), "\n") {
					fmt.Fprintf(sb, "%s> %s\n", pad, line)
				}
			}
		}
	case TypeRawHTML:
		// raw_html survives the markdown round-trip because CommonMark
		// permits inline HTML.
		fmt.Fprintf(sb, "%s%s\n", pad, b.Text)
	}
}

func (r *mdRenderer) renderListItem(sb *strings.Builder, b *Block, indent int, marker string) {
	pad := strings.Repeat("  ", indent)
	if len(b.Content) == 0 {
		fmt.Fprintf(sb, "%s%s%s\n", pad, marker, r.subst(b.Text))
		return
	}
	first := true
	for _, c := range b.Content {
		if first {
			fmt.Fprintf(sb, "%s%s", pad, marker)
			r.render(sb, &c, 0)
			first = false
		} else {
			r.render(sb, &c, indent+1)
		}
	}
}

func (r *mdRenderer) subst(s string) string { return Substitute(s, r.vars) }

func suffix(label string) string {
	if label == "" {
		return ""
	}
	return " (" + label + ")"
}
