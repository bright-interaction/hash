// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"strings"
	"testing"
)

// These assertions keep the legal-record boundary in the SQL statement. A
// handler-only draft read is insufficient because send can win the race before
// the subsequent authoring mutation reaches PostgreSQL.
func TestAuthoringMutationsAreDraftGuarded(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		fragments []string
	}{
		{
			name:  "recipient insert",
			query: createRecipient,
			fragments: []string{
				"WITH draft_document AS MATERIALIZED", "FROM documents d", "d.status = 'draft'", "FOR UPDATE", "FROM draft_document d", "RETURNING",
			},
		},
		{
			name:  "recipient authoring update",
			query: updateRecipient,
			fragments: []string{
				"WITH draft_document AS MATERIALIZED", "FROM documents d", "d.status = 'draft'", "FOR UPDATE", "FROM draft_document d", "d.id = r.document_id", "RETURNING r.",
			},
		},
		{
			name:  "recipient delete protects signature cascade",
			query: deleteRecipient,
			fragments: []string{
				"WITH draft_document AS MATERIALIZED", "FROM documents d", "d.status = 'draft'", "FOR UPDATE", "USING draft_document d", "d.id = r.document_id", "RETURNING r.id",
			},
		},
		{
			name:  "author field insert",
			query: createDraftField,
			fragments: []string{
				"WITH draft_document AS MATERIALIZED", "FROM documents d", "d.status = 'draft'", "FOR UPDATE", "FROM draft_document d", "r.document_id = d.id", "RETURNING",
			},
		},
		{
			name:  "field delete protects signature cascade",
			query: deleteFieldByID,
			fragments: []string{
				"WITH draft_document AS MATERIALIZED", "FROM documents d", "JOIN document_fields candidate ON candidate.document_id = d.id", "candidate.id =", "d.status = 'draft'", "FOR UPDATE", "USING draft_document d", "d.id = f.document_id", "RETURNING f.id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fragment := range tt.fragments {
				if !strings.Contains(tt.query, fragment) {
					t.Errorf("query missing legal-record guard %q\n%s", fragment, tt.query)
				}
			}
		})
	}
}

func TestRequiredSignerFieldGateIncludesUnassignedFields(t *testing.T) {
	for _, want := range []string{
		"recipient_id = $2 OR recipient_id IS NULL",
		"required = TRUE",
		"value IS NULL OR value = ''",
	} {
		if !strings.Contains(countUnfilledRequiredForRecipient, want) {
			t.Fatalf("CountUnfilledRequiredForRecipient missing %q", want)
		}
	}
}
