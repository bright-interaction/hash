// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"fmt"
	"html"
	"strings"
)

// RenderHTML produces a deterministic HTML document body from a block tree.
// Variables are resolved against vars; unknown variables render as the
// literal token (no substitution) so authors notice missing context.
//
// Output is intended to feed Gotenberg's Chromium pipeline, so it includes
// minimal inline styling that prints correctly. Field blocks emit a marker
// element with data-attributes the post-render pass uses to compute PDF
// coordinates.
func RenderHTML(t *Tree, vars map[string]string) string {
	if t == nil {
		return ""
	}
	var sb strings.Builder
	r := &htmlRenderer{vars: vars}
	// Group top-level blocks into <section> units, one per top-level heading
	// (h1/h2), so the print stylesheet can keep each section whole with
	// break-inside: avoid. A section that would be cut by a page boundary moves
	// to the next page intact instead of splitting mid-clause. Page-break blocks
	// stay outside any section so an explicit break still works.
	inSection := false
	closeSection := func() {
		if inSection {
			sb.WriteString(`</section>`)
			inSection = false
		}
	}
	for i := range t.Blocks {
		b := &t.Blocks[i]
		switch {
		case b.Type == TypePageBreak:
			closeSection()
			r.render(&sb, b)
			continue
		case b.Type == TypeHeading && b.HeadingLevel() <= 2:
			closeSection()
			sb.WriteString(`<section class="doc-section">`)
			inSection = true
		default:
			if !inSection {
				sb.WriteString(`<section class="doc-section">`)
				inSection = true
			}
		}
		r.render(&sb, b)
	}
	closeSection()
	return sb.String()
}

type htmlRenderer struct {
	vars map[string]string
}

func (r *htmlRenderer) render(sb *strings.Builder, b *Block) {
	switch b.Type {
	case TypeHeading:
		lvl := b.HeadingLevel()
		fmt.Fprintf(sb, `<h%d data-block-id="%s">%s</h%d>`, lvl, html.EscapeString(b.ID),
			r.text(b.Text), lvl)
	case TypeParagraph:
		fmt.Fprintf(sb, `<p data-block-id="%s">%s</p>`, html.EscapeString(b.ID), r.text(b.Text))
	case TypeBulletList:
		fmt.Fprintf(sb, `<ul data-block-id="%s">`, html.EscapeString(b.ID))
		for _, c := range b.Content {
			r.render(sb, &c)
		}
		sb.WriteString(`</ul>`)
	case TypeOrderedList:
		fmt.Fprintf(sb, `<ol data-block-id="%s">`, html.EscapeString(b.ID))
		for _, c := range b.Content {
			r.render(sb, &c)
		}
		sb.WriteString(`</ol>`)
	case TypeListItem:
		fmt.Fprintf(sb, `<li data-block-id="%s">`, html.EscapeString(b.ID))
		if len(b.Content) == 0 {
			sb.WriteString(r.text(b.Text))
		} else {
			for _, c := range b.Content {
				r.render(sb, &c)
			}
		}
		sb.WriteString(`</li>`)
	case TypeTable:
		fmt.Fprintf(sb, `<table data-block-id="%s"><thead><tr>`, html.EscapeString(b.ID))
		for _, col := range stringSlice(b.Attrs["columns"]) {
			fmt.Fprintf(sb, `<th>%s</th>`, html.EscapeString(col))
		}
		sb.WriteString(`</tr></thead><tbody>`)
		for _, row := range b.Rows {
			sb.WriteString(`<tr>`)
			for _, cell := range row {
				fmt.Fprintf(sb, `<td>%s</td>`, html.EscapeString(r.substitute(cell)))
			}
			sb.WriteString(`</tr>`)
		}
		sb.WriteString(`</tbody></table>`)
	case TypeImage:
		key := html.EscapeString(b.AttrString("storage_key", ""))
		alt := html.EscapeString(b.AttrString("alt", ""))
		// width_pct is rendered as a CSS width on the surrounding figure to
		// keep image proportions intact.
		styleAttr := ""
		if w := b.AttrString("width_pct", ""); w != "" {
			styleAttr = fmt.Sprintf(` style="width:%s%%"`, html.EscapeString(w))
		}
		fmt.Fprintf(sb, `<figure data-block-id="%s"%s><img src="/api/v1/storage/%s" alt="%s" /></figure>`,
			html.EscapeString(b.ID), styleAttr, key, alt)
	case TypeDivider:
		fmt.Fprintf(sb, `<hr data-block-id="%s" />`, html.EscapeString(b.ID))
	case TypePageBreak:
		fmt.Fprintf(sb, `<div data-block-id="%s" style="page-break-after: always;"></div>`, html.EscapeString(b.ID))
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		role := html.EscapeString(b.AttrString("recipient_role", ""))
		label := html.EscapeString(b.AttrString("label", ""))
		required := "false"
		if b.AttrBool("required", true) {
			required = "true"
		}
		fmt.Fprintf(sb,
			`<span class="hash-field" data-block-id="%s" data-field-type="%s" data-recipient-role="%s" data-required="%s">[%s%s]</span>`,
			html.EscapeString(b.ID),
			html.EscapeString(string(b.Type)),
			role,
			required,
			fieldPlaceholder(b.Type),
			placeholderSuffix(label))
	case TypeDynamicVar:
		name := b.AttrString("name", "")
		val := r.lookup(name, b.AttrString("default", ""))
		fmt.Fprintf(sb, `<span class="hash-var" data-block-id="%s" data-var="%s">%s</span>`,
			html.EscapeString(b.ID), html.EscapeString(name), html.EscapeString(val))
	case TypeConditional:
		expr := b.AttrString("expression", "")
		if EvalCondition(expr, r.vars) {
			for _, c := range b.Content {
				r.render(sb, &c)
			}
		}
	case TypeCode:
		lang := html.EscapeString(b.AttrString("language", ""))
		fmt.Fprintf(sb, `<pre data-block-id="%s" data-language="%s"><code>%s</code></pre>`,
			html.EscapeString(b.ID), lang, html.EscapeString(b.Text))
	case TypeQuote:
		fmt.Fprintf(sb, `<blockquote data-block-id="%s">`, html.EscapeString(b.ID))
		if len(b.Content) == 0 {
			sb.WriteString(r.text(b.Text))
		} else {
			for _, c := range b.Content {
				r.render(sb, &c)
			}
		}
		sb.WriteString(`</blockquote>`)
	case TypeCallout:
		tone := html.EscapeString(b.AttrString("tone", "info"))
		fmt.Fprintf(sb, `<aside class="hash-callout hash-callout-%s" data-block-id="%s">`, tone, html.EscapeString(b.ID))
		if len(b.Content) == 0 {
			sb.WriteString(r.text(b.Text))
		} else {
			for _, c := range b.Content {
				r.render(sb, &c)
			}
		}
		sb.WriteString(`</aside>`)
	case TypeRawHTML:
		// raw_html is allowlist-sanitised here at the single render chokepoint
		// (covers the signer page, the signed PDF, and pre-existing stored
		// blocks). bluemonday strips <script>, on* handlers, javascript: URIs,
		// iframes, and inline styles; the policy preserves the signature span
		// the signing flow injects through this same path.
		sb.WriteString(SanitizeRawHTML(b.Text))
	}
}

func (r *htmlRenderer) text(t string) string {
	return html.EscapeString(r.substitute(t))
}

func (r *htmlRenderer) substitute(t string) string {
	return Substitute(t, r.vars)
}

func (r *htmlRenderer) lookup(name, fallback string) string {
	if v, ok := r.vars[name]; ok {
		return v
	}
	return fallback
}

func fieldPlaceholder(t Type) string {
	switch t {
	case TypeSignatureField:
		return "signature"
	case TypeInitialField:
		return "initials"
	case TypeTextField:
		return "text"
	case TypeDateField:
		return "date"
	case TypeCheckbox:
		return "checkbox"
	}
	return "field"
}

func placeholderSuffix(label string) string {
	if label == "" {
		return ""
	}
	return ": " + label
}

// stringSlice coerces an attr value (which is unmarshalled as []any from
// JSON) into a []string. Non-string elements become their default Go format.
func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}
