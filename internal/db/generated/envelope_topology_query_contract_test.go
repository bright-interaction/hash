// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"strings"
	"testing"
)

func TestEnvelopeTopologyQueriesAreDraftOnlyAndParentLocked(t *testing.T) {
	tests := []struct {
		name               string
		query              string
		fragments          []string
		minimumDraftChecks int
	}{
		{
			name:  "promotion",
			query: markAsEnvelope,
			fragments: []string{
				"status = 'draft'",
				"parent_envelope_id IS NULL",
				"source_kind = 'blocks'",
				"deleted_at IS NULL",
			},
			minimumDraftChecks: 1,
		},
		{
			name:  "attach",
			query: attachToEnvelope,
			fragments: []string{
				"WITH locked_parent AS MATERIALIZED",
				"is_envelope = TRUE",
				"FOR UPDATE",
				"child.org_id = locked_parent.org_id",
				"child.is_envelope = FALSE",
				"child.parent_envelope_id IS NULL",
				"child.deleted_at IS NULL",
			},
			minimumDraftChecks: 2,
		},
		{
			name:  "detach",
			query: detachFromEnvelope,
			fragments: []string{
				"WITH locked_parent AS MATERIALIZED",
				"current_child.parent_envelope_id = parent.id",
				"parent.is_envelope = TRUE",
				"FOR UPDATE OF parent",
				"child.parent_envelope_id = locked_parent.id",
				"child.is_envelope = FALSE",
				"child.deleted_at IS NULL",
			},
			minimumDraftChecks: 3,
		},
		{
			name:  "reorder",
			query: reorderEnvelopeChild,
			fragments: []string{
				"WITH locked_parent AS MATERIALIZED",
				"is_envelope = TRUE",
				"FOR UPDATE",
				"child.parent_envelope_id = locked_parent.id",
				"child.org_id = $4",
				"child.is_envelope = FALSE",
				"child.deleted_at IS NULL",
			},
			minimumDraftChecks: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fragment := range tt.fragments {
				if !strings.Contains(tt.query, fragment) {
					t.Errorf("query missing safety clause %q\n%s", fragment, tt.query)
				}
			}
			if got := strings.Count(tt.query, "status = 'draft'"); got < tt.minimumDraftChecks {
				t.Errorf("query has %d draft checks, want at least %d\n%s", got, tt.minimumDraftChecks, tt.query)
			}
		})
	}
}
