// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const (
	ceremonyEventsCommitmentDomain = "hash:document-events:v1"
	ceremonyEventsSchemaV1         = 1
	ceremonyEventsSchemaV2         = 2
)

// CeremonyEventsFile is the canonical, machine-verifiable document subset of
// the audit ledger that existed immediately before finalization. It includes
// every byte that contributes to each row hash. It intentionally does not
// claim that a document-only subset proves continuity through interleaved
// organization events; the separately signed pre-final org head is that
// external anchor.
type CeremonyEventsFile struct {
	SchemaVersion    int                      `json:"schema_version"`
	DocumentID       string                   `json:"document_id"`
	OrgID            string                   `json:"org_id"`
	CommitmentDomain string                   `json:"commitment_domain"`
	CommitmentSHA256 string                   `json:"commitment_sha256"`
	Count            int                      `json:"count"`
	Events           []CanonicalCeremonyEvent `json:"events"`
}

// CanonicalCeremonyEvent carries both readable JSON and the exact payload
// bytes used by the audit hash. Nullable IDs are JSON null rather than a zero
// UUID so a third-party verifier can reconstruct the original hash input.
type CanonicalCeremonyEvent struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"org_id"`
	DocumentID       *string         `json:"document_id"`
	RecipientID      *string         `json:"recipient_id"`
	ActorUserID      *string         `json:"actor_user_id"`
	Kind             string          `json:"kind"`
	IP               string          `json:"ip"`
	UserAgent        string          `json:"user_agent"`
	CreatedAt        string          `json:"created_at"`
	PayloadJSON      json.RawMessage `json:"payload_json"`
	PayloadHashedB64 string          `json:"payload_hashed_b64"`
	PrevHashHex      string          `json:"prev_hash_hex"`
	RowHashSHA256    string          `json:"row_hash_sha256"`
}

// BuildCeremonyEventsJSON validates and serializes the exact chronological
// pre-final rows committed by the signed audit certificate.
func BuildCeremonyEventsJSON(documentID uuid.UUID, rows []*generated.Event) ([]byte, string, int, error) {
	if documentID == uuid.Nil {
		return nil, "", 0, errors.New("evidence: ceremony events require a document id")
	}
	if len(rows) == 0 || len(rows) > maxEvidenceEvents {
		return nil, "", 0, fmt.Errorf("evidence: ceremony event count must be between 1 and %d", maxEvidenceEvents)
	}
	ordered := append([]*generated.Event(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] == nil || ordered[j] == nil {
			return ordered[j] == nil
		}
		if !ordered[i].CreatedAt.Time.Equal(ordered[j].CreatedAt.Time) {
			return ordered[i].CreatedAt.Time.Before(ordered[j].CreatedAt.Time)
		}
		return bytes.Compare(ordered[i].ID[:], ordered[j].ID[:]) < 0
	})

	canonical := make([]CanonicalCeremonyEvent, 0, len(ordered))
	var orgID uuid.UUID
	for i, row := range ordered {
		if row == nil {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %d is nil", i)
		}
		if row.ID == uuid.Nil || row.OrgID == uuid.Nil || !row.DocumentID.Valid || uuid.UUID(row.DocumentID.Bytes) != documentID {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %s has invalid document or organization identity", row.ID)
		}
		if orgID == uuid.Nil {
			orgID = row.OrgID
		} else if row.OrgID != orgID {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %s belongs to a different organization", row.ID)
		}
		if !json.Valid(row.PayloadJson) || !json.Valid(row.PayloadHashed) || !jsonSemanticallyEqual(row.PayloadJson, row.PayloadHashed) {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %s payload representations disagree", row.ID)
		}
		if err := validateCeremonyArticle13Payload(row); err != nil {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %s Article 13 payload: %w", row.ID, err)
		}
		recomputed, err := audit.RecomputeEventRowHash(row)
		if err != nil {
			return nil, "", 0, fmt.Errorf("evidence: recompute ceremony event %s: %w", row.ID, err)
		}
		if len(row.RowHash) != sha256.Size || subtle.ConstantTimeCompare(recomputed, row.RowHash) != 1 {
			return nil, "", 0, fmt.Errorf("evidence: ceremony event %s row hash is invalid", row.ID)
		}
		canonical = append(canonical, canonicalCeremonyEvent(row))
	}
	schemaVersion, err := ceremonyEventsSchemaVersion(ordered)
	if err != nil {
		return nil, "", 0, fmt.Errorf("evidence: Article 13 ceremony policy: %w", err)
	}
	digest, err := audit.DocumentEventSetDigest(ordered)
	if err != nil {
		return nil, "", 0, fmt.Errorf("evidence: document event commitment: %w", err)
	}
	digestHex := hex.EncodeToString(digest[:])
	file := CeremonyEventsFile{
		SchemaVersion:    schemaVersion,
		DocumentID:       documentID.String(),
		OrgID:            orgID.String(),
		CommitmentDomain: ceremonyEventsCommitmentDomain,
		CommitmentSHA256: digestHex,
		Count:            len(canonical),
		Events:           canonical,
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, "", 0, err
	}
	return raw, digestHex, len(canonical), nil
}

// VerifyCeremonyEventsJSON strictly decodes events.json, recomputes every row
// hash, and checks its exact set commitment against the signed certificate.
func VerifyCeremonyEventsJSON(raw []byte, documentID, orgID, expectedDigest string, expectedCount int) error {
	expectedDocumentID, err := parseCanonicalUUID(documentID)
	if err != nil {
		return fmt.Errorf("manifest document_id: %w", err)
	}
	expectedOrgID, err := parseCanonicalUUID(orgID)
	if err != nil {
		return fmt.Errorf("manifest org_id: %w", err)
	}
	expectedDigestBytes, err := decodeRequiredCanonicalHash(expectedDigest)
	if err != nil {
		return fmt.Errorf("signed ceremony-event digest: %w", err)
	}
	if expectedCount <= 0 || expectedCount > maxEvidenceEvents {
		return errors.New("signed ceremony-event count is out of range")
	}
	var file CeremonyEventsFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return fmt.Errorf("parse ceremony events: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("parse ceremony events: trailing JSON value")
	}
	if (file.SchemaVersion != ceremonyEventsSchemaV1 && file.SchemaVersion != ceremonyEventsSchemaV2) ||
		file.CommitmentDomain != ceremonyEventsCommitmentDomain {
		return errors.New("ceremony events schema or commitment domain is unsupported")
	}
	if file.DocumentID != documentID || file.OrgID != orgID {
		return errors.New("ceremony events document or organization does not match the manifest")
	}
	if file.Count != len(file.Events) || file.Count != expectedCount {
		return errors.New("ceremony events count does not match the signed certificate")
	}
	if file.CommitmentSHA256 != expectedDigest {
		return errors.New("ceremony events commitment does not match the signed certificate")
	}

	rows := make([]*generated.Event, 0, len(file.Events))
	seen := make(map[uuid.UUID]struct{}, len(file.Events))
	for i := range file.Events {
		row, err := file.Events[i].generatedEvent()
		if err != nil {
			return fmt.Errorf("ceremony event %d: %w", i, err)
		}
		if _, duplicate := seen[row.ID]; duplicate {
			return fmt.Errorf("ceremony event %d duplicates event id %s", i, row.ID)
		}
		seen[row.ID] = struct{}{}
		if uuid.UUID(row.DocumentID.Bytes) != expectedDocumentID || row.OrgID != expectedOrgID {
			return fmt.Errorf("ceremony event %s identity does not match the file", row.ID)
		}
		if err := validateCeremonyArticle13Payload(row); err != nil {
			return fmt.Errorf("ceremony event %s Article 13 payload: %w", row.ID, err)
		}
		recomputed, err := audit.RecomputeEventRowHash(row)
		if err != nil {
			return fmt.Errorf("ceremony event %s: %w", row.ID, err)
		}
		if subtle.ConstantTimeCompare(recomputed, row.RowHash) != 1 {
			return fmt.Errorf("ceremony event %s row hash is invalid", row.ID)
		}
		rows = append(rows, row)
	}
	detectedSchemaVersion, err := ceremonyEventsSchemaVersion(rows)
	if err != nil {
		return fmt.Errorf("ceremony events Article 13 policy: %w", err)
	}
	if file.SchemaVersion != detectedSchemaVersion {
		return errors.New("ceremony events schema does not match the committed Article 13 cutover marker")
	}
	digest, err := audit.DocumentEventSetDigest(rows)
	if err != nil {
		return fmt.Errorf("ceremony event set: %w", err)
	}
	if subtle.ConstantTimeCompare(digest[:], expectedDigestBytes) != 1 {
		return errors.New("ceremony event-set digest does not match the signed certificate")
	}
	return nil
}

func validateCeremonyArticle13Payload(row *generated.Event) error {
	recipientID := uuid.Nil
	if row.RecipientID.Valid {
		recipientID = uuid.UUID(row.RecipientID.Bytes)
	}
	documentID := uuid.Nil
	if row.DocumentID.Valid {
		documentID = uuid.UUID(row.DocumentID.Bytes)
	}
	return article13.ValidateAuditPayload(row.PayloadHashed, row.OrgID, documentID, recipientID)
}

// ceremonyEventsSchemaVersion pre-scans the complete event set for the
// document.sent cutover marker and its send epoch before enforcing any later
// response row. That two-pass shape prevents a reordered event file from
// moving an unbound or stale response ahead of the relevant resend marker to
// regain legacy treatment. V2 additionally requires strict chronological
// order here; DocumentEventSetDigest repeats the check when computing the
// signed set commitment.
func ceremonyEventsSchemaVersion(rows []*generated.Event) (int, error) {
	markerAt := make([]bool, len(rows))
	markerSchemaAt := make([]string, len(rows))
	markerEpochAt := make([]string, len(rows))
	firstMarker := -1
	for i, row := range rows {
		if row == nil {
			return 0, fmt.Errorf("event %d is nil", i)
		}
		payload, err := ceremonyPayloadObject(row.PayloadHashed)
		if err != nil {
			return 0, fmt.Errorf("event %s payload: %w", row.ID, err)
		}
		rawSchema, hasSchema := payload[article13.AuditRequiredNoticeSchemaKey]
		rawSentAt, hasSentAt := payload[article13.AuditRequiredNoticeSentAtKey]
		if hasSchema != hasSentAt {
			return 0, fmt.Errorf("event %s has a partial notice requirement epoch marker", row.ID)
		}
		if !hasSchema {
			continue
		}
		var markerSchema string
		if err := json.Unmarshal(rawSchema, &markerSchema); err != nil || !article13.IsSupportedSchema(markerSchema) {
			return 0, fmt.Errorf("event %s has an invalid or conflicting notice requirement marker", row.ID)
		}
		var markerSentAt string
		if err := json.Unmarshal(rawSentAt, &markerSentAt); err != nil || article13.ValidateCanonicalSentAt(markerSentAt) != nil {
			return 0, fmt.Errorf("event %s has an invalid notice requirement send epoch", row.ID)
		}
		if row.Kind != audit.KindDocumentSent {
			return 0, fmt.Errorf("event %s carries a notice requirement epoch marker outside document.sent", row.ID)
		}
		if row.RecipientID.Valid {
			return 0, fmt.Errorf("document.sent epoch marker %s unexpectedly carries a recipient identity", row.ID)
		}
		markerAt[i] = true
		markerSchemaAt[i] = markerSchema
		markerEpochAt[i] = markerSentAt
		if firstMarker < 0 {
			firstMarker = i
		}
	}
	if firstMarker < 0 {
		return ceremonyEventsSchemaV1, nil
	}
	if err := requireStrictCeremonyOrder(rows); err != nil {
		return 0, err
	}

	var latestSchema, latestEpoch string
	var latestEpochTime time.Time
	for i := firstMarker; i < len(rows); i++ {
		row := rows[i]
		payload, err := ceremonyPayloadObject(row.PayloadHashed)
		if err != nil {
			return 0, fmt.Errorf("event %s payload: %w", row.ID, err)
		}
		if row.Kind == audit.KindDocumentSent && !markerAt[i] {
			return 0, fmt.Errorf("post-cutover document.sent event %s omits the notice requirement epoch marker", row.ID)
		}
		if markerAt[i] {
			epoch, err := time.Parse(time.RFC3339Nano, markerEpochAt[i])
			if err != nil {
				return 0, fmt.Errorf("event %s has an invalid notice requirement send epoch", row.ID)
			}
			if latestEpoch != "" && !epoch.After(latestEpochTime) {
				return 0, fmt.Errorf("event %s has a conflicting or non-increasing notice requirement send epoch", row.ID)
			}
			latestSchema = markerSchemaAt[i]
			latestEpoch = markerEpochAt[i]
			latestEpochTime = epoch
		}
		required, err := recipientEventRequiresNotice(row, payload)
		if err != nil {
			return 0, fmt.Errorf("event %s: %w", row.ID, err)
		}
		if !required {
			continue
		}
		if !row.RecipientID.Valid {
			return 0, fmt.Errorf("recipient-gated %s event has no recipient identity", row.Kind)
		}
		if _, ok := payload[article13.AuditNoticeSchemaKey]; !ok {
			return 0, fmt.Errorf("recipient-gated %s event omits Article 13 evidence", row.Kind)
		}
		noticeSchema, snapshotSentAt, err := noticeSnapshotBinding(payload)
		if err != nil {
			return 0, fmt.Errorf("recipient-gated %s event has invalid Article 13 marker binding: %w", row.Kind, err)
		}
		if err := validateActiveNoticeBinding(latestSchema, latestEpoch, noticeSchema, snapshotSentAt); err != nil {
			return 0, fmt.Errorf("recipient-gated %s event %w", row.Kind, err)
		}
	}
	return ceremonyEventsSchemaV2, nil
}

func validateActiveNoticeBinding(activeSchema, activeSentAt, evidenceSchema, evidenceSentAt string) error {
	if evidenceSchema != activeSchema {
		return errors.New("carries Article 13 evidence for a different notice schema")
	}
	if evidenceSentAt != activeSentAt {
		return errors.New("carries stale Article 13 evidence for a different send epoch")
	}
	return nil
}

func noticeSnapshotBinding(payload map[string]json.RawMessage) (string, string, error) {
	rawSchema, ok := payload[article13.AuditNoticeSchemaKey]
	if !ok {
		return "", "", errors.New("notice schema is missing")
	}
	var schema string
	if err := json.Unmarshal(rawSchema, &schema); err != nil || !article13.IsSupportedSchema(schema) {
		return "", "", errors.New("notice schema is unsupported")
	}
	raw, ok := payload[article13.AuditNoticeSnapshotKey]
	if !ok {
		return "", "", errors.New("notice snapshot is missing")
	}
	var snapshot article13.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return "", "", errors.New("notice snapshot is malformed")
	}
	if snapshot.Schema != schema {
		return "", "", errors.New("notice envelope and snapshot schemas disagree")
	}
	if err := article13.ValidateCanonicalSentAt(snapshot.SentAt); err != nil {
		return "", "", err
	}
	return schema, snapshot.SentAt, nil
}

func ceremonyPayloadObject(raw []byte) (map[string]json.RawMessage, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil || payload == nil {
		return nil, errors.New("must be a JSON object")
	}
	return payload, nil
}

func requireStrictCeremonyOrder(rows []*generated.Event) error {
	for i := 1; i < len(rows); i++ {
		previous, current := rows[i-1], rows[i]
		if previous == nil || current == nil || !previous.CreatedAt.Valid || !current.CreatedAt.Valid {
			return errors.New("v2 ceremony events lack canonical timestamps")
		}
		if current.CreatedAt.Time.Before(previous.CreatedAt.Time) ||
			(current.CreatedAt.Time.Equal(previous.CreatedAt.Time) && bytes.Compare(current.ID[:], previous.ID[:]) <= 0) {
			return fmt.Errorf("v2 ceremony events are not in strict chronological order at index %d", i)
		}
	}
	return nil
}

func recipientEventRequiresNotice(row *generated.Event, payload map[string]json.RawMessage) (bool, error) {
	switch row.Kind {
	case audit.KindDocumentViewed,
		audit.KindDocumentFieldFill,
		audit.KindDocumentSigned,
		audit.KindDocumentAccepted,
		audit.KindDocumentDeclined,
		"clarifier.requested",
		"clarifier.answered":
		return true, nil
	case audit.KindChangesRequested:
		if row.RecipientID.Valid {
			return true, nil
		}
		// The same historical kind is also used for the sender's resolution
		// event. Its exact server-authored shape makes that non-recipient case
		// distinguishable without allowing a missing recipient ID to downgrade
		// a signer request.
		var changeRequest, resolution string
		if err := json.Unmarshal(payload["change_request"], &changeRequest); err != nil {
			return false, errors.New("change event has neither a recipient nor a valid sender resolution")
		}
		if _, err := uuid.Parse(changeRequest); err != nil {
			return false, errors.New("change event has an invalid sender resolution identity")
		}
		if err := json.Unmarshal(payload["resolution"], &resolution); err != nil ||
			(resolution != "approved" && resolution != "denied") {
			return false, errors.New("change event has an invalid sender resolution")
		}
		return false, nil
	case audit.KindCommentPosted:
		var side string
		if err := json.Unmarshal(payload["side"], &side); err != nil {
			return false, errors.New("comment event has no canonical side")
		}
		switch side {
		case "signer":
			return true, nil
		case "sender":
			if row.RecipientID.Valid {
				return false, errors.New("sender comment unexpectedly carries a recipient identity")
			}
			return false, nil
		default:
			return false, errors.New("comment event has an unsupported side")
		}
	default:
		return false, nil
	}
}

func canonicalCeremonyEvent(row *generated.Event) CanonicalCeremonyEvent {
	return CanonicalCeremonyEvent{
		ID:               row.ID.String(),
		OrgID:            row.OrgID.String(),
		DocumentID:       nullableUUIDString(row.DocumentID),
		RecipientID:      nullableUUIDString(row.RecipientID),
		ActorUserID:      nullableUUIDString(row.ActorUserID),
		Kind:             row.Kind,
		IP:               canonicalIP(row.Ip),
		UserAgent:        nullableTextString(row.Ua),
		CreatedAt:        row.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		PayloadJSON:      append(json.RawMessage(nil), row.PayloadJson...),
		PayloadHashedB64: base64.StdEncoding.EncodeToString(row.PayloadHashed),
		PrevHashHex:      hex.EncodeToString(row.PrevHash),
		RowHashSHA256:    hex.EncodeToString(row.RowHash),
	}
}

func (event CanonicalCeremonyEvent) generatedEvent() (*generated.Event, error) {
	id, err := parseCanonicalUUID(event.ID)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	organizationID, err := parseCanonicalUUID(event.OrgID)
	if err != nil {
		return nil, fmt.Errorf("org_id: %w", err)
	}
	documentID, err := parseNullableCanonicalUUID(event.DocumentID)
	if err != nil || !documentID.Valid {
		return nil, errors.New("document_id must be a canonical UUID")
	}
	recipientID, err := parseNullableCanonicalUUID(event.RecipientID)
	if err != nil {
		return nil, fmt.Errorf("recipient_id: %w", err)
	}
	actorID, err := parseNullableCanonicalUUID(event.ActorUserID)
	if err != nil {
		return nil, fmt.Errorf("actor_user_id: %w", err)
	}
	if event.Kind == "" || strings.TrimSpace(event.Kind) != event.Kind {
		return nil, errors.New("kind is missing or non-canonical")
	}
	var ip *netip.Addr
	if event.IP != "" {
		parsed, err := netip.ParseAddr(event.IP)
		if err != nil || parsed.String() != event.IP {
			return nil, errors.New("ip is not canonical")
		}
		ip = &parsed
	}
	createdAt, err := time.Parse(time.RFC3339Nano, event.CreatedAt)
	if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != event.CreatedAt {
		return nil, errors.New("created_at is not canonical UTC RFC3339Nano")
	}
	payloadHashed, err := base64.StdEncoding.DecodeString(event.PayloadHashedB64)
	if err != nil || base64.StdEncoding.EncodeToString(payloadHashed) != event.PayloadHashedB64 || !json.Valid(payloadHashed) {
		return nil, errors.New("payload_hashed_b64 is not canonical base64 JSON")
	}
	if !json.Valid(event.PayloadJSON) || !jsonSemanticallyEqual(event.PayloadJSON, payloadHashed) {
		return nil, errors.New("payload_json does not match payload_hashed_b64")
	}
	prevHash, err := decodeOptionalCanonicalHash(event.PrevHashHex)
	if err != nil {
		return nil, fmt.Errorf("prev_hash_hex: %w", err)
	}
	rowHash, err := decodeRequiredCanonicalHash(event.RowHashSHA256)
	if err != nil {
		return nil, fmt.Errorf("row_hash_sha256: %w", err)
	}
	return &generated.Event{
		ID: id, OrgID: organizationID, DocumentID: documentID,
		RecipientID: recipientID, ActorUserID: actorID, Kind: event.Kind,
		Ip: ip, Ua: pgtype.Text{String: event.UserAgent, Valid: event.UserAgent != ""},
		PayloadJson:   append(json.RawMessage(nil), event.PayloadJSON...),
		PayloadHashed: payloadHashed, PrevHash: prevHash, RowHash: rowHash,
		CreatedAt: pgtype.Timestamptz{Time: createdAt, Valid: true},
	}, nil
}

func nullableUUIDString(value pgtype.UUID) *string {
	if !value.Valid {
		return nil
	}
	text := uuid.UUID(value.Bytes).String()
	return &text
}

func parseNullableCanonicalUUID(value *string) (pgtype.UUID, error) {
	if value == nil {
		return pgtype.UUID{}, nil
	}
	parsed, err := parseCanonicalUUID(*value)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func parseCanonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, errors.New("must be a canonical non-zero UUID")
	}
	return parsed, nil
}

func nullableTextString(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func canonicalIP(value *netip.Addr) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func decodeOptionalCanonicalHash(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return decodeRequiredCanonicalHash(value)
}

func decodeRequiredCanonicalHash(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return nil, errors.New("must be canonical lowercase SHA-256 hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("must be canonical lowercase SHA-256 hex")
	}
	return decoded, nil
}

func jsonSemanticallyEqual(left, right []byte) bool {
	decode := func(raw []byte) (any, error) {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, errors.New("trailing JSON")
		}
		return value, nil
	}
	a, err := decode(left)
	if err != nil {
		return false
	}
	b, err := decode(right)
	return err == nil && reflect.DeepEqual(a, b)
}
