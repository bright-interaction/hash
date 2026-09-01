// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func ceremonyArticle13Copy() article13.Copy {
	return article13.Copy{
		Title:                  "Title",
		Intro:                  "Intro",
		ControllerLabel:        "Controller",
		ControllerContactLabel: "Controller contact",
		ProcessorLabel:         "Processor",
		PurposeLabel:           "Purpose",
		LegalBasisLabel:        "Legal basis",
		RetentionLabel:         "Retention",
		RetentionValue:         "Seven years",
		AuthorityLabel:         "Authority",
		RightsSummary:          "Rights",
		RightsBody:             "Rights body",
		SubmitRequestLabel:     "Submit request",
		KindLabel:              "Kind",
		DSRAccessLabel:         "Access (Art. 15)",
		DSRRectificationLabel:  "Rectification (Art. 16)",
		DSRErasureLabel:        "Erasure (Art. 17)",
		DSRRestrictionLabel:    "Restriction (Art. 18)",
		DSRPortabilityLabel:    "Portability (Art. 20)",
		DSRObjectionLabel:      "Objection (Art. 21)",
		NoteLabel:              "Note",
		NotePlaceholder:        "Optional note",
		SendRequestLabel:       "Send request",
		RequestReceived:        "Request received",
		ReadPolicyLabel:        "Read policy",
		AcknowledgementLabel:   "Continue",
		FinePrint:              "Fine print",
	}
}

func ceremonyArticle13Evidence(t *testing.T, orgID, documentID, recipientID uuid.UUID) article13.Evidence {
	return ceremonyArticle13EvidenceAt(t, orgID, documentID, recipientID, time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC))
}

func ceremonyArticle13EvidenceAt(t *testing.T, orgID, documentID, recipientID uuid.UUID, sentAt time.Time) article13.Evidence {
	t.Helper()
	snapshot, err := article13.NewSnapshot(article13.Input{
		DocumentID:           documentID,
		OrgID:                orgID,
		RecipientID:          recipientID,
		SentAt:               sentAt,
		Controller:           "Customer AB",
		ControllerContact:    "contracts@customer.example",
		Processor:            "Operator AB",
		ProcessorContact:     "privacy@operator.example",
		PurposeSummary:       "Collect a document response.",
		LegalBasisDisclosure: "GDPR Article 6(1)(b).",
		RetentionYears:       article13.RetentionYearsV1,
		SupervisoryAuthority: "Applicable authority",
		PolicyURL:            "https://operator.example/privacy",
		DSRCapability:        article13.DSRCapabilitySignerRequest,
		Copy:                 ceremonyArticle13Copy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func ceremonyArticle13MarkerPayload(t *testing.T, sentAt time.Time) []byte {
	t.Helper()
	canonical, err := article13.CanonicalSentAt(sentAt)
	if err != nil {
		t.Fatal(err)
	}
	return ceremonyJSONPayload(t, map[string]any{
		article13.AuditRequiredNoticeSchemaKey: article13.CurrentSchema,
		article13.AuditRequiredNoticeSentAtKey: canonical,
	})
}

func ceremonyArticle13Payload(t *testing.T, evidence article13.Evidence) []byte {
	t.Helper()
	payload := map[string]any{"side": "signer"}
	if err := evidence.BindAuditPayload(payload); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ceremonyTestEvent(t *testing.T, orgID, documentID uuid.UUID, recipientID pgtype.UUID, payload []byte) *generated.Event {
	t.Helper()
	row := &generated.Event{
		ID:            uuid.New(),
		OrgID:         orgID,
		DocumentID:    pgtype.UUID{Bytes: documentID, Valid: true},
		RecipientID:   recipientID,
		Kind:          audit.KindDocumentSigned,
		PayloadJson:   append(json.RawMessage(nil), payload...),
		PayloadHashed: append([]byte(nil), payload...),
		CreatedAt:     pgtype.Timestamptz{Time: time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC), Valid: true},
	}
	recomputed, err := audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal(err)
	}
	row.RowHash = recomputed
	return row
}

func ceremonyTestEventAt(t *testing.T, orgID, documentID uuid.UUID, recipientID pgtype.UUID, kind string, payload []byte, createdAt time.Time) *generated.Event {
	t.Helper()
	row := ceremonyTestEvent(t, orgID, documentID, recipientID, payload)
	row.Kind = kind
	row.CreatedAt = pgtype.Timestamptz{Time: createdAt, Valid: true}
	recomputed, err := audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal(err)
	}
	row.RowHash = recomputed
	return row
}

func ceremonyJSONPayload(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func tamperCeremonyNoticeSnapshot(t *testing.T, payload []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(object[article13.AuditNoticeSnapshotKey], &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot["purpose_summary"] = "Tampered after the digest was created."
	mutatedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	object[article13.AuditNoticeSnapshotKey] = mutatedSnapshot
	mutatedPayload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return mutatedPayload
}

func ceremonyEventsFileForRow(t *testing.T, row *generated.Event) ([]byte, string) {
	t.Helper()
	return ceremonyEventsFileForRows(t, ceremonyEventsSchemaV1, []*generated.Event{row})
}

func ceremonyEventsFileForRows(t *testing.T, schemaVersion int, rows []*generated.Event) ([]byte, string) {
	t.Helper()
	digest, err := audit.DocumentEventSetDigest(rows)
	if err != nil {
		t.Fatal(err)
	}
	digestHex := hex.EncodeToString(digest[:])
	file := CeremonyEventsFile{
		SchemaVersion:    schemaVersion,
		DocumentID:       uuid.UUID(rows[0].DocumentID.Bytes).String(),
		OrgID:            rows[0].OrgID.String(),
		CommitmentDomain: ceremonyEventsCommitmentDomain,
		CommitmentSHA256: digestHex,
		Count:            len(rows),
		Events:           make([]CanonicalCeremonyEvent, 0, len(rows)),
	}
	for _, row := range rows {
		file.Events = append(file.Events, canonicalCeremonyEvent(row))
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	return raw, digestHex
}

func TestCeremonyEventsRejectTamperedArticle13SnapshotDespiteValidOuterHashes(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	evidence := ceremonyArticle13Evidence(t, orgID, documentID, recipientID)
	tamperedPayload := tamperCeremonyNoticeSnapshot(t, ceremonyArticle13Payload(t, evidence))
	row := ceremonyTestEvent(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true}, tamperedPayload)

	recomputed, err := audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(recomputed, row.RowHash) != 1 {
		t.Fatal("test fixture does not have a valid recomputed audit row hash")
	}
	if _, _, _, err := BuildCeremonyEventsJSON(documentID, []*generated.Event{row}); !errors.Is(err, article13.ErrInvalidAuditPayload) {
		t.Fatalf("BuildCeremonyEventsJSON() error = %v, want Article 13 payload rejection", err)
	}

	file, digest := ceremonyEventsFileForRow(t, row)
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, 1); !errors.Is(err, article13.ErrInvalidAuditPayload) {
		t.Fatalf("VerifyCeremonyEventsJSON() error = %v, want Article 13 payload rejection", err)
	}
}

func TestCeremonyEventsRequireRecipientIdentityForNoticeEvidence(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	evidence := ceremonyArticle13Evidence(t, orgID, documentID, recipientID)
	row := ceremonyTestEvent(t, orgID, documentID, pgtype.UUID{}, ceremonyArticle13Payload(t, evidence))

	if _, _, _, err := BuildCeremonyEventsJSON(documentID, []*generated.Event{row}); !errors.Is(err, article13.ErrInvalidAuditPayload) {
		t.Fatalf("BuildCeremonyEventsJSON() error = %v, want missing-recipient rejection", err)
	}
	file, digest := ceremonyEventsFileForRow(t, row)
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, 1); !errors.Is(err, article13.ErrInvalidAuditPayload) {
		t.Fatalf("VerifyCeremonyEventsJSON() error = %v, want missing-recipient rejection", err)
	}
}

func TestCeremonyEventsKeepLegacyPayloadWithoutNoticeValid(t *testing.T) {
	orgID, documentID := uuid.New(), uuid.New()
	row := ceremonyTestEvent(t, orgID, documentID, pgtype.UUID{}, []byte(`{"method":"ses"}`))

	file, digest, count, err := BuildCeremonyEventsJSON(documentID, []*generated.Event{row})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("event count = %d, want 1", count)
	}
	var decoded CeremonyEventsFile
	if err := json.Unmarshal(file, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != ceremonyEventsSchemaV1 {
		t.Fatalf("legacy schema_version = %d, want %d", decoded.SchemaVersion, ceremonyEventsSchemaV1)
	}
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, count); err != nil {
		t.Fatal(err)
	}
}

func TestCeremonyEventsV2RequiresNoticeForEveryPostCutoverRecipientEvent(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		payload map[string]any
	}{
		{name: "view", kind: audit.KindDocumentViewed, payload: map[string]any{}},
		{name: "field", kind: audit.KindDocumentFieldFill, payload: map[string]any{"field_id": uuid.New().String()}},
		{name: "sign", kind: audit.KindDocumentSigned, payload: map[string]any{"method": "ses"}},
		{name: "accept", kind: audit.KindDocumentAccepted, payload: map[string]any{}},
		{name: "decline", kind: audit.KindDocumentDeclined, payload: map[string]any{"reason": "no"}},
		{name: "change", kind: audit.KindChangesRequested, payload: map[string]any{"message": "change it"}},
		{name: "comment", kind: audit.KindCommentPosted, payload: map[string]any{"side": "signer"}},
		{name: "clarifier request", kind: "clarifier.requested", payload: map[string]any{"block_id": "clause"}},
		{name: "clarifier answer", kind: "clarifier.answered", payload: map[string]any{"block_id": "clause"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
			base := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
			marker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
				ceremonyArticle13MarkerPayload(t, base), base)
			response := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true}, test.kind,
				ceremonyJSONPayload(t, test.payload), base.Add(time.Minute))

			if _, _, _, err := BuildCeremonyEventsJSON(documentID, []*generated.Event{marker, response}); err == nil || !strings.Contains(err.Error(), "omits Article 13 evidence") {
				t.Fatalf("BuildCeremonyEventsJSON() error = %v, want post-cutover notice omission rejection", err)
			}
		})
	}
}

func TestCeremonyEventsV2RoundTripAllowsLegacyRowsBeforeFirstOfMultipleMarkers(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	base := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	legacyView := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindDocumentViewed, []byte(`{}`), base)
	legacySend := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		[]byte(`{"legacy":true}`), base.Add(time.Minute))
	firstEpoch := base.Add(2 * time.Minute)
	firstMarker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, firstEpoch), firstEpoch)
	evidence := ceremonyArticle13EvidenceAt(t, orgID, documentID, recipientID, firstEpoch)
	signed := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindDocumentSigned, ceremonyArticle13Payload(t, evidence), base.Add(3*time.Minute))
	secondEpoch := base.Add(4 * time.Minute)
	secondMarker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, secondEpoch), secondEpoch)
	resendEvidence := ceremonyArticle13EvidenceAt(t, orgID, documentID, recipientID, secondEpoch)
	comment := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindCommentPosted, ceremonyArticle13Payload(t, resendEvidence), base.Add(5*time.Minute))
	senderResolution := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindChangesRequested,
		ceremonyJSONPayload(t, map[string]any{"change_request": uuid.New().String(), "resolution": "approved"}), base.Add(6*time.Minute))
	senderComment := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindCommentPosted,
		ceremonyJSONPayload(t, map[string]any{"side": "sender"}), base.Add(7*time.Minute))
	rows := []*generated.Event{legacyView, legacySend, firstMarker, signed, secondMarker, comment, senderResolution, senderComment}

	file, digest, count, err := BuildCeremonyEventsJSON(documentID, rows)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CeremonyEventsFile
	if err := json.Unmarshal(file, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != ceremonyEventsSchemaV2 {
		t.Fatalf("schema_version = %d, want %d", decoded.SchemaVersion, ceremonyEventsSchemaV2)
	}
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, count); err != nil {
		t.Fatal(err)
	}
}

func TestCeremonyEventsV2RejectsStaleNoticeSnapshotAfterResend(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	firstEpoch := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secondEpoch := firstEpoch.Add(time.Hour)
	firstMarker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, firstEpoch), firstEpoch)
	secondMarker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, secondEpoch), secondEpoch)
	staleEvidence := ceremonyArticle13EvidenceAt(t, orgID, documentID, recipientID, firstEpoch)
	staleResponse := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindDocumentSigned, ceremonyArticle13Payload(t, staleEvidence), secondEpoch.Add(time.Minute))
	rows := []*generated.Event{firstMarker, secondMarker, staleResponse}

	if _, _, _, err := BuildCeremonyEventsJSON(documentID, rows); err == nil || !strings.Contains(err.Error(), "stale Article 13 evidence") {
		t.Fatalf("BuildCeremonyEventsJSON(stale resend evidence) error = %v", err)
	}
	file, digest := ceremonyEventsFileForRows(t, ceremonyEventsSchemaV2, rows)
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, len(rows)); err == nil || !strings.Contains(err.Error(), "stale Article 13 evidence") {
		t.Fatalf("VerifyCeremonyEventsJSON(stale resend evidence) error = %v", err)
	}
}

func TestActiveNoticeBindingRequiresBothSchemaAndEpochAcrossRollingSchemas(t *testing.T) {
	const (
		historical = article13.SchemaV1
		future     = "hash-a13-2099-01-01"
		firstEpoch = "2026-08-31T10:00:00Z"
		nextEpoch  = "2026-08-31T11:00:00Z"
	)
	if err := validateActiveNoticeBinding(historical, firstEpoch, historical, firstEpoch); err != nil {
		t.Fatalf("supported historical binding rejected: %v", err)
	}
	// The comparison is schema-agnostic after the marker parser has admitted a
	// schema through article13's registry. This fixture models a later rolling
	// release without prematurely trusting that future schema today.
	if err := validateActiveNoticeBinding(future, nextEpoch, future, nextEpoch); err != nil {
		t.Fatalf("future registered-schema binding shape rejected: %v", err)
	}
	if err := validateActiveNoticeBinding(future, nextEpoch, historical, nextEpoch); err == nil || !strings.Contains(err.Error(), "different notice schema") {
		t.Fatalf("historical evidence under future marker error = %v, want schema mismatch", err)
	}
	if err := validateActiveNoticeBinding(historical, nextEpoch, historical, firstEpoch); err == nil || !strings.Contains(err.Error(), "different send epoch") {
		t.Fatalf("stale historical epoch error = %v, want epoch mismatch", err)
	}
}

func TestCeremonyEventsRejectUnregisteredFutureMarker(t *testing.T) {
	orgID, documentID := uuid.New(), uuid.New()
	base := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	marker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyJSONPayload(t, map[string]any{
			article13.AuditRequiredNoticeSchemaKey: "hash-a13-2099-01-01",
			article13.AuditRequiredNoticeSentAtKey: base.Format(time.RFC3339Nano),
		}), base)
	if _, _, _, err := BuildCeremonyEventsJSON(documentID, []*generated.Event{marker}); err == nil || !strings.Contains(err.Error(), "invalid or conflicting notice requirement marker") {
		t.Fatalf("future marker error = %v, want fail-closed registry rejection", err)
	}
}

func TestCeremonyEventsV2RejectsOmittedResendMarkerWithNewEpochSnapshot(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	firstEpoch := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secondEpoch := firstEpoch.Add(time.Hour)
	firstMarker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, firstEpoch), firstEpoch)
	newEpochEvidence := ceremonyArticle13EvidenceAt(t, orgID, documentID, recipientID, secondEpoch)
	responseWithoutResendMarker := ceremonyTestEventAt(t, orgID, documentID,
		pgtype.UUID{Bytes: recipientID, Valid: true}, audit.KindDocumentSigned,
		ceremonyArticle13Payload(t, newEpochEvidence), secondEpoch.Add(time.Minute))
	rows := []*generated.Event{firstMarker, responseWithoutResendMarker}

	if _, _, _, err := BuildCeremonyEventsJSON(documentID, rows); err == nil || !strings.Contains(err.Error(), "different send epoch") {
		t.Fatalf("BuildCeremonyEventsJSON(omitted resend marker) error = %v", err)
	}
	file, digest := ceremonyEventsFileForRows(t, ceremonyEventsSchemaV2, rows)
	if err := VerifyCeremonyEventsJSON(file, documentID.String(), orgID.String(), digest, len(rows)); err == nil || !strings.Contains(err.Error(), "different send epoch") {
		t.Fatalf("VerifyCeremonyEventsJSON(omitted resend marker) error = %v", err)
	}
}

func TestCeremonyEventsV2RejectsInvalidMarkerPlacementAndPostCutoverOmission(t *testing.T) {
	tests := []struct {
		name string
		rows func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event
	}{
		{
			name: "conflicting schema",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
					ceremonyJSONPayload(t, map[string]any{
						article13.AuditRequiredNoticeSchemaKey: "different-schema",
						article13.AuditRequiredNoticeSentAtKey: base.Format(time.RFC3339Nano),
					}), base)}
			},
		},
		{
			name: "schema without epoch",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
					ceremonyJSONPayload(t, map[string]any{article13.AuditRequiredNoticeSchemaKey: article13.CurrentSchema}), base)}
			},
		},
		{
			name: "epoch without schema",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
					ceremonyJSONPayload(t, map[string]any{article13.AuditRequiredNoticeSentAtKey: base.Format(time.RFC3339Nano)}), base)}
			},
		},
		{
			name: "noncanonical epoch",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
					ceremonyJSONPayload(t, map[string]any{
						article13.AuditRequiredNoticeSchemaKey: article13.CurrentSchema,
						article13.AuditRequiredNoticeSentAtKey: "2026-08-31T10:00:00+00:00",
					}), base)}
			},
		},
		{
			name: "marker outside sent event",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentCreated,
					ceremonyArticle13MarkerPayload(t, base), base)}
			},
		},
		{
			name: "marker carries recipient",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{ceremonyTestEventAt(t, orgID, documentID,
					pgtype.UUID{Bytes: uuid.New(), Valid: true}, audit.KindDocumentSent,
					ceremonyArticle13MarkerPayload(t, base), base)}
			},
		},
		{
			name: "later sent event omits marker",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{
					ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
						ceremonyArticle13MarkerPayload(t, base), base),
					ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent, []byte(`{}`), base.Add(time.Minute)),
				}
			},
		},
		{
			name: "later epoch does not advance",
			rows: func(t *testing.T, orgID, documentID uuid.UUID, base time.Time) []*generated.Event {
				return []*generated.Event{
					ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
						ceremonyArticle13MarkerPayload(t, base), base),
					ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
						ceremonyArticle13MarkerPayload(t, base), base.Add(time.Minute)),
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orgID, documentID := uuid.New(), uuid.New()
			rows := test.rows(t, orgID, documentID, time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC))
			if _, _, _, err := BuildCeremonyEventsJSON(documentID, rows); err == nil {
				t.Fatal("BuildCeremonyEventsJSON() accepted invalid cutover markers")
			}
		})
	}
}

func TestVerifyCeremonyEventsV2RejectsOmissionDowngradeAndReordering(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	base := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	marker := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{}, audit.KindDocumentSent,
		ceremonyArticle13MarkerPayload(t, base), base)
	evidence := ceremonyArticle13Evidence(t, orgID, documentID, recipientID)
	signed := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindDocumentSigned, ceremonyArticle13Payload(t, evidence), base.Add(time.Minute))
	rows := []*generated.Event{marker, signed}
	fileRaw, digest := ceremonyEventsFileForRows(t, ceremonyEventsSchemaV2, rows)

	var file CeremonyEventsFile
	if err := json.Unmarshal(fileRaw, &file); err != nil {
		t.Fatal(err)
	}
	file.SchemaVersion = ceremonyEventsSchemaV1
	downgraded, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCeremonyEventsJSON(downgraded, documentID.String(), orgID.String(), digest, len(rows)); err == nil || !strings.Contains(err.Error(), "schema does not match") {
		t.Fatalf("VerifyCeremonyEventsJSON(downgrade) error = %v", err)
	}

	file.SchemaVersion = ceremonyEventsSchemaV2
	file.Events[0], file.Events[1] = file.Events[1], file.Events[0]
	reordered, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCeremonyEventsJSON(reordered, documentID.String(), orgID.String(), digest, len(rows)); err == nil || !strings.Contains(err.Error(), "strict chronological order") {
		t.Fatalf("VerifyCeremonyEventsJSON(reordered) error = %v", err)
	}

	omitted := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{Bytes: recipientID, Valid: true},
		audit.KindDocumentSigned, []byte(`{"method":"ses"}`), base.Add(time.Minute))
	omissionRows := []*generated.Event{marker, omitted}
	omissionFile, omissionDigest := ceremonyEventsFileForRows(t, ceremonyEventsSchemaV2, omissionRows)
	if err := VerifyCeremonyEventsJSON(omissionFile, documentID.String(), orgID.String(), omissionDigest, len(omissionRows)); err == nil || !strings.Contains(err.Error(), "omits Article 13 evidence") {
		t.Fatalf("VerifyCeremonyEventsJSON(omission) error = %v", err)
	}

	missingRecipient := ceremonyTestEventAt(t, orgID, documentID, pgtype.UUID{},
		audit.KindDocumentViewed, []byte(`{}`), base.Add(time.Minute))
	missingRecipientRows := []*generated.Event{marker, missingRecipient}
	missingRecipientFile, missingRecipientDigest := ceremonyEventsFileForRows(t, ceremonyEventsSchemaV2, missingRecipientRows)
	if err := VerifyCeremonyEventsJSON(missingRecipientFile, documentID.String(), orgID.String(), missingRecipientDigest, len(missingRecipientRows)); err == nil || !strings.Contains(err.Error(), "no recipient identity") {
		t.Fatalf("VerifyCeremonyEventsJSON(missing recipient) error = %v", err)
	}
}
