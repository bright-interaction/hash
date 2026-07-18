// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// redactionItem mirrors sanitize.Report on the wire. Defined locally so
// the sign package doesn't have to import internal/sanitize (and the
// cert renderer stays a pure HTML emitter).
type redactionItem struct {
	Asset       string   `json:"asset"`
	ContentType string   `json:"content_type"`
	Method      string   `json:"method"`
	Stripped    []string `json:"stripped"`
	BytesBefore int64    `json:"bytes_before"`
	BytesAfter  int64    `json:"bytes_after"`
}

type redactionReport struct {
	SchemaVersion int             `json:"schema_version"`
	Items         []redactionItem `json:"items"`
}

// renderRedactionReportSection emits the GDPR-sanitization section that
// appears inside the audit certificate. Empty / unparseable / no-items
// reports return "" so pre-Phase-8.7 documents render unchanged.
//
// The section is embedded BEFORE the ed25519 signature is computed, so
// the signature covers it: tampering with what was reportedly stripped
// breaks cert verification.
func renderRedactionReportSection(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var rep redactionReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return ""
	}
	if len(rep.Items) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(`<section class="hash-redaction-report">`)
	sb.WriteString(`<h2>Metadata sanitization (GDPR)</h2>`)
	sb.WriteString(`<p>Every asset uploaded to this document was routed through Hash's sanitizer before storage. The categories below were stripped from each asset; the original bytes were never persisted. This section is bound by the ed25519 signature below.</p>`)
	sb.WriteString(`<table><thead><tr><th>Asset</th><th>Type</th><th>Method</th><th>Stripped</th><th>Bytes (before -> after)</th></tr></thead><tbody>`)
	for _, it := range rep.Items {
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d -> %d</td></tr>`,
			html.EscapeString(it.Asset),
			html.EscapeString(it.ContentType),
			html.EscapeString(it.Method),
			html.EscapeString(strings.Join(it.Stripped, ", ")),
			it.BytesBefore, it.BytesAfter,
		)
	}
	sb.WriteString(`</tbody></table>`)
	sb.WriteString(`</section>`)
	return sb.String()
}
