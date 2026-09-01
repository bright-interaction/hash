// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

// These contracts cover the concurrency/readiness clauses that are easy to
// accidentally drop while editing or regenerating sqlc queries. Behavioral DB
// tests exercise the surrounding engines; these assertions keep the terminal
// SQL primitives fail-closed even in the default unit-test suite.
func TestStateMachineQueriesAreGuarded(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		fragments []string
	}{
		{
			name:  "void only mutates active ceremony states",
			query: voidDocumentIfActive,
			fragments: []string{
				"status IN ('sent', 'in_progress')", "RETURNING",
			},
		},
		{
			name:  "generic status helper cannot allocate durable lifecycle states",
			query: setDocumentStatus,
			fragments: []string{
				"($3 = 'in_progress' AND documents.status = 'sent')",
				"($3 = 'expired' AND documents.status IN ('sent', 'in_progress'))",
				"updated_at = now()", "RETURNING",
			},
		},
		{
			name:  "send sealing begins from draft only",
			query: beginDocumentSendSealing,
			fragments: []string{
				"status = 'sealing'", "status = 'draft'", "deleted_at IS NULL", "RETURNING",
			},
		},
		{
			name:  "send intent pins the legal epoch and exact retention deadline before storage",
			query: createSendSealingIntent,
			fragments: []string{
				"next_epoch AS MATERIALIZED", "statement_timestamp()", "clock_timestamp()",
				"parent.article13_notice_epoch_at + interval '1 microsecond'", "max(child.article13_notice_epoch_at) + interval '1 microsecond'",
				"article13_notice_epoch_at, retain_until", "hash_evidence_retain_until(next_epoch.value, 7)", "parent.status = 'draft'", "RETURNING",
			},
		},
		{
			name:  "send completes only from exact pinned durable sealing",
			query: completeDocumentSendSealing + completeEnvelopeChildrenSendSealing,
			fragments: []string{
				"status = 'sent'", "status = 'sealing'", "deleted_at IS NULL",
				"evidence_version_pins_required = TRUE", "send_sealing_intents", "ceremony_epoch AS MATERIALIZED",
				"sent_at = ceremony_epoch.value", "article13_notice_epoch_at = ceremony_epoch.value",
				"retention_started_at IS NOT NULL", "retention_completed_at IS NOT NULL",
				"retain_until = hash_evidence_retain_until", "article13_notice_epoch_v61_committed = TRUE", "RETURNING",
			},
		},
		{
			name:  "send pins source versions before retention and never replaces them",
			query: pinDocumentSendEvidenceVersions,
			fragments: []string{
				"evidence_version_pins_required = TRUE", "COALESCE(pdf_storage_version_id", "COALESCE(rendered_pdf_version_id",
				"status IN ('sealing','sent','in_progress','finalizing')", "pdf_storage_version_id IS NULL OR pdf_storage_version_id =",
				"rendered_pdf_version_id IS NULL OR rendered_pdf_version_id =", "RETURNING",
			},
		},
		{
			name:  "document finalization closes interaction before rendering",
			query: beginDocumentFinalization,
			fragments: []string{
				"finalizing_root AS MATERIALIZED", "lifecycle_clock AS MATERIALIZED", "GREATEST(", "statement_timestamp()",
				"max(member.sent_at) + interval '1 microsecond'", "max(r.signed_at) + interval '1 microsecond'",
				"max(s.signed_at) + interval '1 microsecond'", "max(e.created_at) + interval '1 microsecond'",
				"member.parent_envelope_id = root.id", "status = 'finalizing'", "d.status = 'in_progress'", "target.status = 'in_progress'",
				"d.sent_at IS NOT NULL", "target.sent_at IS NOT NULL", "completion_effective_at_bound = TRUE",
				"completion_effective_at = COALESCE(target.completion_effective_at, lifecycle_clock.effective_at)",
				"finalization_retain_until = COALESCE", "hash_evidence_retain_until(", "updated_at = lifecycle_clock.effective_at", "deleted_at IS NULL", "RETURNING",
			},
		},
		{
			name:  "document retention completion requires a started checkpoint",
			query: markDocumentFinalizationRetentionStarted + markDocumentFinalizationRetentionComplete,
			fragments: []string{
				"retention_started_at", "retention_completed_at", "retention_started_at IS NOT NULL", "retain_until IS NOT NULL", "COALESCE", "updated_at = now()",
			},
		},
		{
			name:  "document completion requires the exact retained intent",
			query: completeDocumentFinalization,
			fragments: []string{
				"documents.status = 'finalizing'", "documents.evidence_version_pins_required = TRUE", "document_finalization_intents", "retention_completed_at IS NOT NULL",
				"documents.completion_effective_at_bound = TRUE", "documents.finalization_retain_until IS NOT NULL", "completed_at = documents.completion_effective_at",
				"i.completion_effective_at = documents.completion_effective_at", "i.retain_until = documents.finalization_retain_until",
				"i.final_pdf_key", "i.final_pdf_sha256", "i.final_pdf_version_id",
				"i.audit_cert_key", "i.audit_cert_sha256", "i.audit_cert_version_id",
				"i.audit_payload_key", "i.audit_payload_sha256", "i.audit_payload_version_id",
				"i.audit_signature_key", "i.audit_signature_sha256", "i.audit_signature_version_id",
				"i.evidence_version_pins_required = TRUE", "RETURNING",
			},
		},
		{
			name:  "envelope finalization freezes the entire active family to the root commitment",
			query: beginEnvelopeChildrenFinalization,
			fragments: []string{
				"child.status IN ('sent','in_progress')", "child.deleted_at IS NULL",
				"parent.status = 'finalizing'", "parent.is_envelope = TRUE", "parent.parent_envelope_id IS NULL",
				"parent.completion_effective_at_bound = TRUE", "parent.completion_effective_at IS NOT NULL",
				"parent.finalization_retain_until IS NOT NULL", "status = 'finalizing'",
				"completion_effective_at = parent.completion_effective_at",
				"finalization_retain_until = parent.finalization_retain_until", "RETURNING child.id",
			},
		},
		{
			name:  "envelope children inherit the exact parent completion timestamp",
			query: completeEnvelopeChildren,
			fragments: []string{
				"completion_effective_at_bound = parent.completion_effective_at_bound", "completion_effective_at = parent.completion_effective_at",
				"finalization_retain_until = parent.finalization_retain_until", "completed_at = parent.completion_effective_at",
				"parent.status = 'completed'", "parent.completion_effective_at_bound = TRUE", "parent.completion_effective_at IS NOT NULL",
				"parent.finalization_retain_until IS NOT NULL", "child.status = 'finalizing'", "child.completion_effective_at_bound = TRUE",
				"child.completion_effective_at = parent.completion_effective_at",
				"child.finalization_retain_until = parent.finalization_retain_until", "RETURNING child.id",
			},
		},
		{
			name:  "legacy finalization intent pins all terminal versions atomically",
			query: pinLegacyDocumentFinalizationIntentVersions,
			fragments: []string{
				"final_pdf_version_id", "audit_cert_version_id", "audit_payload_version_id", "audit_signature_version_id",
				"evidence_version_pins_required = TRUE", "evidence_version_pins_required = FALSE", "RETURNING",
			},
		},
		{
			name:  "legacy signature image pin is one-way",
			query: pinLegacySignatureVersion,
			fragments: []string{
				"image_version_pin_required = TRUE", "image_version_pin_required = FALSE", "image_version_id IS NULL", "document_id", "RETURNING",
			},
		},
		{
			name:  "retention start and completion are durable intent markers",
			query: markSendSealingRetentionStarted + markSendSealingRetentionComplete,
			fragments: []string{
				"retention_started_at", "retention_completed_at", "retention_started_at IS NOT NULL",
				"retain_until = hash_evidence_retain_until(article13_notice_epoch_at, 7)", "COALESCE", "updated_at = now()",
			},
		},
		{
			name:  "stranded retry is broad bounded oldest first and leaves frozen role projection to engine",
			query: getStrandedDocuments,
			fragments: []string{
				"d.requires_signature = false", "d.requires_signature = true", "d.status IN ('in_progress','finalizing')", "d.status = 'finalizing'", "signed.status = 'signed'",
				"d.parent_envelope_id IS NULL",
				"ORDER BY (d.status = 'finalizing') DESC, d.updated_at ASC, d.id ASC", "LIMIT $1",
			},
		},
		{
			name:  "expiration is active and time guarded",
			query: expireDocumentIfActive,
			fragments: []string{
				"expires_at <= clock_timestamp()", "status IN ('sent','in_progress')", "RETURNING",
			},
		},
		{
			name:  "email dispatch claims with a recoverable lease",
			query: claimDueEmailDeliveries,
			fragments: []string{
				"FOR UPDATE SKIP LOCKED", "UPDATE email_deliveries", "interval '5 minutes'", "RETURNING",
			},
		},
		{
			name:  "change request is claimed for update",
			query: getChangeRequestForUpdate,
			fragments: []string{
				"d.org_id", "FOR UPDATE OF cr",
			},
		},
		{
			name:  "revision reset cannot erase captured evidence",
			query: resetRecipientsForRevision,
			fragments: []string{
				"status NOT IN ('declined','signed','accepted')", "signed_at IS NULL",
			},
		},
		{
			name:  "completed artifact access is limited to legal participants",
			query: setCompletedArtifactTokenExpiry,
			fragments: []string{
				"magic_token_expires_at", "status IN ('signed','accepted')", "document_id",
			},
		},
		{
			name:  "completed artifact credential is newly rotated behind terminal guards",
			query: rotateCompletedArtifactToken,
			fragments: []string{
				"magic_token_hash", "magic_token_expires_at", "d.status = 'completed'", "r.status IN ('signed','accepted')",
			},
		},
		{
			name:  "routing assurance metadata is SES-only and draft-only",
			query: setDocumentRoutingTier,
			fragments: []string{
				"status = 'draft'", "$3 = 'SES'", "routing_tier",
			},
		},
		{
			name:  "field fill rejects recipients who already responded",
			query: updateFieldValue,
			fragments: []string{
				"document_fields.recipient_id = $4", "r.status IN ('pending','sent','viewed')", "d.status IN ('sent', 'in_progress')",
			},
		},
		{
			name:  "send recipient transition is pending-only and row counted",
			query: markRecipientSent,
			fragments: []string{
				"status = 'pending'", "document_id", "sent_at = now()",
			},
		},
		{
			name:  "envelope children inherit all artifact identity",
			query: completeEnvelopeChildren,
			fragments: []string{
				"final_pdf_key", "final_pdf_sha", "final_pdf_version_id",
				"audit_cert_key", "audit_cert_sha256", "audit_cert_version_id",
				"audit_payload_key", "audit_payload_sha256", "audit_payload_version_id",
				"audit_signature_key", "audit_signature_sha256", "audit_signature_version_id",
				"status = 'completed'", "parent_envelope_id", "child.status = 'finalizing'", "evidence_version_pins_required = TRUE",
				"child.completion_effective_at = parent.completion_effective_at",
				"child.finalization_retain_until = parent.finalization_retain_until",
			},
		},
		{
			name:  "soft delete purge uses a recoverable bounded lease",
			query: claimSoftDeletedDocumentsForPurge,
			fragments: []string{
				"status = 'draft'", "interval '15 minutes'", "FOR UPDATE SKIP LOCKED", "LIMIT", "SET updated_at = now()", "RETURNING",
			},
		},
		{
			name:  "soft delete hard delete uses claimed lease cas",
			query: deleteClaimedSoftDeletedDocument,
			fragments: []string{
				"deleted_at IS NOT NULL", "status = 'draft'", "updated_at =",
			},
		},
		{
			name:  "audit chain head carries ordering timestamp",
			query: latestEventChainHeadForOrg,
			fragments: []string{
				"row_hash", "created_at", "ORDER BY created_at DESC, id DESC",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, fragment := range tt.fragments {
				if !strings.Contains(tt.query, fragment) {
					t.Errorf("query missing safety clause %q\n%s", fragment, tt.query)
				}
			}
		})
	}
}

func TestGenericDocumentStatusHelperCannotAllocateDurableStateOrTimestamps(t *testing.T) {
	for _, forbidden := range []string{
		"$3 = 'sealing'",
		"$3 = 'sent'",
		"$3 = 'finalizing'",
		"$3 = 'completed'",
		"sent_at =",
		"completed_at =",
	} {
		if strings.Contains(setDocumentStatus, forbidden) {
			t.Fatalf("generic status helper still contains durable lifecycle surface %q\n%s", forbidden, setDocumentStatus)
		}
	}
}

func TestCompletionTimestampMigrationInventoryChecksAreWriteLocked(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00059_durable_completion_effective_timestamp.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(raw)
	lock := "LOCK TABLE documents, document_finalization_intents IN ACCESS EXCLUSIVE MODE"
	if got := strings.Count(migration, lock); got != 2 {
		t.Fatalf("completion timestamp migration has %d write-excluding inventory locks, want one for Up and one for Down", got)
	}
	guard := "cannot roll back completion timestamps after bound evidence has been completed"
	if !strings.Contains(migration, guard) {
		t.Fatalf("completion timestamp migration is missing its one-way bound-evidence rollback guard")
	}
}
