// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import "encoding/json"

func jsonMarshalLite(v any) ([]byte, error) {
	return json.Marshal(v)
}

func jsonUnmarshalLite(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}

// SyntheticTemplateReport builds a redaction report describing the
// sanitization a PDF template went through at upload time. Used by
// PDF-source document creation so the document carries an authoritative
// record of GDPR cleaning without needing to look up the template row.
//
// The fields list every category pdfcpu strips during Optimize +
// RemoveAttachments + RemoveFormFields + RemoveAnnotations passes; if
// the upload path's behaviour ever changes, update this list to match
// so the audit cert stays honest.
func SyntheticTemplateReport() ([]byte, error) {
	return MergeReports(nil, Report{
		Asset:       "template-pdf",
		ContentType: "application/pdf",
		Method:      "pdfcpu",
		Stripped: []string{
			"info_dictionary",
			"xmp_metadata",
			"object_streams",
			"linearization",
			"embedded_files",
			"acroform",
			"annotations",
		},
	})
}
