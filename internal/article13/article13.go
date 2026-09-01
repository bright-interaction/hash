// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package article13 defines the durable, self-contained snapshot committed by
// Hash's signer-facing GDPR Article 13 acknowledgement.
package article13

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type schemaDefinition struct {
	validate      func(Snapshot) error
	canonicalJSON func(Snapshot) ([]byte, error)
}

// supportedSchemaRegistry is the complete set of notice schemas this binary
// can validate without consulting mutable runtime configuration. Historical
// schemas stay registered after a newer schema becomes current so a rolling
// release can continue to verify retained evidence and an already-active
// ceremony. Adding a constant without a validator/canonicalizer here does not
// make it trusted.
var supportedSchemaRegistry = map[string]schemaDefinition{
	SchemaV1: {
		validate:      validateV1,
		canonicalJSON: canonicalJSONV1,
	},
}

const (
	// SchemaV1 identifies the exact fields and canonical encoding introduced on
	// 2026-08-31. It must remain supported when a future schema becomes current:
	// historical evidence is verified against the rules that created it, never
	// reinterpreted using new runtime disclosure settings.
	SchemaV1 = "hash-a13-2026-08-31"

	// CurrentSchema is the schema used by NewSnapshot.
	CurrentSchema = SchemaV1

	// Schema is the concise public name for the schema emitted today.
	Schema = CurrentSchema

	// RetentionYearsV1 is the evidentiary retention period disclosed by V1.
	// Changing it requires a new schema rather than redefining historical V1.
	RetentionYearsV1 = 7

	// AuditNoticeSchemaKey, AuditNoticeDigestKey, and AuditNoticeSnapshotKey
	// are the inseparable audit-payload fields used for Article 13 evidence.
	AuditNoticeSchemaKey   = "notice_schema"
	AuditNoticeDigestKey   = "notice_digest"
	AuditNoticeSnapshotKey = "notice_snapshot"

	// AuditRequiredNoticeSchemaKey is the schema half of the document.sent
	// cutover marker. Unlike AuditNoticeSchemaKey, it does not claim that the
	// sent event itself is a signer acknowledgement; together with the exact
	// send epoch below it commits later recipient-gated events to fresh notice
	// evidence for that ceremony epoch.
	AuditRequiredNoticeSchemaKey = "required_notice_schema"

	// AuditRequiredNoticeSentAtKey binds the cutover marker to the exact send
	// epoch rendered in subsequent signer notices. The schema and sent-at
	// markers are inseparable on every current document.sent event.
	AuditRequiredNoticeSentAtKey = "required_notice_sent_at"
)

// DSRCapability is a non-secret description of the data-subject-request
// facility displayed with the notice. It deliberately carries no endpoint,
// bearer token, or other ceremony credential.
type DSRCapability string

const (
	// DSRCapabilitySignerRequest means the signer can submit a request from the
	// authenticated signer ceremony.
	DSRCapabilitySignerRequest DSRCapability = "signer_request_submission"
)

var (
	// ErrInvalidSnapshot identifies a malformed or unsupported Article 13
	// snapshot. Validation errors wrap this sentinel without echoing field data.
	ErrInvalidSnapshot = errors.New("invalid Article 13 snapshot")

	// ErrInvalidEvidence identifies an inconsistent evidence envelope or digest.
	ErrInvalidEvidence = errors.New("invalid Article 13 evidence")

	// ErrInvalidAuditPayload identifies malformed, partial, tampered, or
	// incorrectly scoped Article 13 evidence in an audit payload.
	ErrInvalidAuditPayload = errors.New("invalid Article 13 audit payload")

	// ErrUnsupportedLegalBasis identifies a controller basis for which the V1
	// signer disclosure has no implemented, evidence-backed wording.
	ErrUnsupportedLegalBasis = errors.New("unsupported Article 13 lawful basis")
)

// Copy contains every fixed string rendered by the V1 notice card. Keeping the
// rendered words inside the snapshot makes the evidence self-contained even if
// application copy or runtime localization changes after acknowledgement.
type Copy struct {
	Title                  string `json:"title"`
	Intro                  string `json:"intro"`
	ControllerLabel        string `json:"controller_label"`
	ControllerContactLabel string `json:"controller_contact_label"`
	ProcessorLabel         string `json:"processor_label"`
	PurposeLabel           string `json:"purpose_label"`
	LegalBasisLabel        string `json:"legal_basis_label"`
	RetentionLabel         string `json:"retention_label"`
	RetentionValue         string `json:"retention_value"`
	AuthorityLabel         string `json:"authority_label"`
	RightsSummary          string `json:"rights_summary"`
	RightsBody             string `json:"rights_body"`
	SubmitRequestLabel     string `json:"submit_request_label"`
	KindLabel              string `json:"kind_label"`
	DSRAccessLabel         string `json:"dsr_access_label"`
	DSRRectificationLabel  string `json:"dsr_rectification_label"`
	DSRErasureLabel        string `json:"dsr_erasure_label"`
	DSRRestrictionLabel    string `json:"dsr_restriction_label"`
	DSRPortabilityLabel    string `json:"dsr_portability_label"`
	DSRObjectionLabel      string `json:"dsr_objection_label"`
	NoteLabel              string `json:"note_label"`
	NotePlaceholder        string `json:"note_placeholder"`
	SendRequestLabel       string `json:"send_request_label"`
	RequestReceived        string `json:"request_received"`
	ReadPolicyLabel        string `json:"read_policy_label"`
	AcknowledgementLabel   string `json:"acknowledgement_label"`
	FinePrint              string `json:"fine_print"`
}

// Snapshot is the complete disclosure material committed by a signer
// acknowledgement. SentAt is canonical UTC RFC3339Nano text so the JSON and
// its SHA-256 digest remain stable across databases, processes, and time zones.
//
// There is intentionally no DSR URL or magic-token field. DSRCapability records
// only the non-secret product capability that was displayed.
type Snapshot struct {
	Schema               string        `json:"schema"`
	DocumentID           uuid.UUID     `json:"document_id"`
	OrgID                uuid.UUID     `json:"org_id"`
	RecipientID          uuid.UUID     `json:"recipient_id"`
	SentAt               string        `json:"sent_at"`
	Controller           string        `json:"controller"`
	ControllerContact    string        `json:"controller_contact"`
	Processor            string        `json:"processor"`
	ProcessorContact     string        `json:"processor_contact"`
	PurposeSummary       string        `json:"purpose_summary"`
	LegalBasisDisclosure string        `json:"legal_basis_disclosure"`
	RetentionYears       int           `json:"retention_years"`
	SupervisoryAuthority string        `json:"supervisory_authority"`
	PolicyURL            string        `json:"policy_url"`
	DSRCapability        DSRCapability `json:"dsr_capability"`
	Copy                 Copy          `json:"copy"`
}

// Input contains the disclosure material needed to construct the current
// snapshot. NewSnapshot owns schema selection and timestamp canonicalization.
type Input struct {
	DocumentID           uuid.UUID
	OrgID                uuid.UUID
	RecipientID          uuid.UUID
	SentAt               time.Time
	Controller           string
	ControllerContact    string
	Processor            string
	ProcessorContact     string
	PurposeSummary       string
	LegalBasisDisclosure string
	RetentionYears       int
	SupervisoryAuthority string
	PolicyURL            string
	DSRCapability        DSRCapability
	Copy                 Copy
}

// DisclosurePreflight contains the mutable, customer-authored material that
// is frozen when a document is sent. Runtime operator identity is validated at
// process startup; this preflight closes the separate authoring-to-signer gap.
type DisclosurePreflight struct {
	DocumentName      string
	Controller        string
	ControllerContact string
	LawfulBasis       string
}

// PurposeSummaryV1 returns the exact English purpose rendered by the current
// V1 signer notice. Keep this text here, rather than in runtime localization,
// so send preflight, rendering, and historical evidence cannot drift.
func PurposeSummaryV1(documentName string) string {
	return "Administering the response process for " + documentName +
		", recording participant actions, producing applicable final artifacts, and retaining captured evidence under Hash's fixed seven-year evidence policy. The controller must ensure that period is lawful and Hash does not determine legal effect for the document."
}

// LegalBasisDisclosureV1 returns the exact V1 signer-facing wording for the
// only basis whose ceremony Hash currently implements.
func LegalBasisDisclosureV1(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "contract":
		return "Controller confirmed: GDPR Article 6(1)(b) — processing necessary for a contract or requested pre-contractual steps.", nil
	default:
		return "", ErrUnsupportedLegalBasis
	}
}

// RenderedCopyV1 returns every fixed English string rendered inside the V1
// notice, including the pre-acknowledgement data-subject request form.
func RenderedCopyV1(documentName string) Copy {
	return Copy{
		Title:                  "Before you respond: how we handle your data",
		Intro:                  "You are about to respond to " + documentName + ". Under GDPR Article 13 we have to tell you who is processing your data, why, and how to exercise your rights.",
		ControllerLabel:        "Data controller",
		ControllerContactLabel: "Controller contact",
		ProcessorLabel:         "Data processor",
		PurposeLabel:           "Purpose",
		LegalBasisLabel:        "Legal basis",
		RetentionLabel:         "Retention",
		RetentionValue:         "Hash applies a fixed 7-year evidence-retention policy to independently owned source or rendered PDF versions when a document is sent, completed final PDFs and audit certificates, and signature artifacts captured before a signing ceremony later ends without completion. The controller must ensure that period matches the applicable contract and law.",
		AuthorityLabel:         "Supervisory authority",
		RightsSummary:          "Your rights under GDPR Art. 15-22",
		RightsBody:             "Access, rectification, erasure, restriction, portability, objection. Use the form below to send a request directly from this page.",
		SubmitRequestLabel:     "Submit a data-subject request",
		KindLabel:              "Kind",
		DSRAccessLabel:         "Access (Art. 15)",
		DSRRectificationLabel:  "Rectification (Art. 16)",
		DSRErasureLabel:        "Erasure (Art. 17)",
		DSRRestrictionLabel:    "Restriction (Art. 18)",
		DSRPortabilityLabel:    "Portability (Art. 20)",
		DSRObjectionLabel:      "Objection (Art. 21)",
		NoteLabel:              "Note (optional)",
		NotePlaceholder:        "Anything that helps us scope the request",
		SendRequestLabel:       "Send request",
		RequestReceived:        "Request received. The controller will respond under the applicable GDPR deadline; identity checks or a lawful extension may affect timing.",
		ReadPolicyLabel:        "Read the full privacy policy",
		AcknowledgementLabel:   "I understand, continue",
		FinePrint:              "Acknowledging this notice is required to respond to this document. It does not change the fixed Hash evidence-retention period; deletion remains subject to immutable retention and applicable controller obligations.",
	}
}

// ValidateDisclosurePreflight validates the exact customer-authored material
// which the V1 signer handler will render. A complete synthetic Snapshot is
// used deliberately: adding a required V1 material field later cannot leave
// send validation silently weaker than signer bootstrap validation.
func ValidateDisclosurePreflight(in DisclosurePreflight) error {
	if !validPlainText(in.DocumentName, 2000) {
		return invalidSnapshotField("document_name")
	}
	legalBasis, err := LegalBasisDisclosureV1(in.LawfulBasis)
	if err != nil {
		return fmt.Errorf("%w: lawful_basis", ErrInvalidSnapshot)
	}
	_, err = NewSnapshot(Input{
		DocumentID:           uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		OrgID:                uuid.MustParse("00000000-0000-4000-8000-000000000002"),
		RecipientID:          uuid.MustParse("00000000-0000-4000-8000-000000000003"),
		SentAt:               time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC),
		Controller:           in.Controller,
		ControllerContact:    in.ControllerContact,
		Processor:            "Hash disclosure preflight",
		ProcessorContact:     "privacy@example.invalid",
		PurposeSummary:       PurposeSummaryV1(in.DocumentName),
		LegalBasisDisclosure: legalBasis,
		RetentionYears:       RetentionYearsV1,
		SupervisoryAuthority: "Disclosure preflight authority",
		PolicyURL:            "https://example.invalid/privacy",
		DSRCapability:        DSRCapabilitySignerRequest,
		Copy:                 RenderedCopyV1(in.DocumentName),
	})
	return err
}

// CanonicalSentAt returns the timestamp encoding committed by V1 snapshots
// and document.sent cutover markers. PostgreSQL timestamps survive this
// conversion exactly at their stored microsecond precision.
func CanonicalSentAt(value time.Time) (string, error) {
	canonical := value.UTC().Format(time.RFC3339Nano)
	if !isCanonicalUTC(canonical) {
		return "", invalidSnapshotField("sent_at")
	}
	return canonical, nil
}

// ValidateCanonicalSentAt rejects alternate RFC3339 spellings, offsets, and
// the zero timestamp so an epoch can be compared byte-for-byte offline.
func ValidateCanonicalSentAt(value string) error {
	if !isCanonicalUTC(value) {
		return invalidSnapshotField("sent_at")
	}
	return nil
}

// NewSnapshot constructs and validates a snapshot using CurrentSchema.
func NewSnapshot(in Input) (Snapshot, error) {
	return NewSnapshotForSchema(CurrentSchema, in)
}

// NewSnapshotForSchema constructs a snapshot using one explicitly supported
// schema. Signer bootstrap uses the schema pinned to the active database
// ceremony rather than silently upgrading an already-sent document when a new
// application version changes CurrentSchema.
func NewSnapshotForSchema(schema string, in Input) (Snapshot, error) {
	if !IsSupportedSchema(schema) {
		return Snapshot{}, fmt.Errorf("%w: unsupported schema", ErrInvalidSnapshot)
	}
	sentAt, err := CanonicalSentAt(in.SentAt)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Schema:               schema,
		DocumentID:           in.DocumentID,
		OrgID:                in.OrgID,
		RecipientID:          in.RecipientID,
		SentAt:               sentAt,
		Controller:           in.Controller,
		ControllerContact:    in.ControllerContact,
		Processor:            in.Processor,
		ProcessorContact:     in.ProcessorContact,
		PurposeSummary:       in.PurposeSummary,
		LegalBasisDisclosure: in.LegalBasisDisclosure,
		RetentionYears:       in.RetentionYears,
		SupervisoryAuthority: in.SupervisoryAuthority,
		PolicyURL:            in.PolicyURL,
		DSRCapability:        in.DSRCapability,
		Copy:                 in.Copy,
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// IsSupportedSchema reports whether this binary has an immutable validator
// and canonical encoder for schema. It is intentionally distinct from
// CurrentSchema: old schemas remain supported during rolling upgrades and for
// the full evidentiary retention period.
func IsSupportedSchema(schema string) bool {
	_, ok := supportedSchemaRegistry[schema]
	return ok
}

// SupportedSchemas returns a sorted defensive snapshot of the registry. It is
// suitable for release checks and fixtures; callers cannot mutate the actual
// verifier registry.
func SupportedSchemas() []string {
	schemas := make([]string, 0, len(supportedSchemaRegistry))
	for schema := range supportedSchemaRegistry {
		schemas = append(schemas, schema)
	}
	sort.Strings(schemas)
	return schemas
}

// Validate verifies a snapshot according to the immutable rules for its
// schema. Add a new switch case for future schemas; do not alter or remove the
// V1 path, because retained evidence must remain independently verifiable.
func (s Snapshot) Validate() error {
	definition, ok := supportedSchemaRegistry[s.Schema]
	if !ok || definition.validate == nil || definition.canonicalJSON == nil {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidSnapshot)
	}
	return definition.validate(s)
}

func validateV1(s Snapshot) error {
	if s.DocumentID == uuid.Nil {
		return invalidSnapshotField("document_id")
	}
	if s.OrgID == uuid.Nil {
		return invalidSnapshotField("org_id")
	}
	if s.RecipientID == uuid.Nil {
		return invalidSnapshotField("recipient_id")
	}
	if !isCanonicalUTC(s.SentAt) {
		return invalidSnapshotField("sent_at")
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{name: "controller", value: s.Controller, max: 200},
		{name: "processor", value: s.Processor, max: 200},
		{name: "purpose_summary", value: s.PurposeSummary, max: 2000},
		{name: "legal_basis_disclosure", value: s.LegalBasisDisclosure, max: 2000},
		{name: "supervisory_authority", value: s.SupervisoryAuthority, max: 300},
	} {
		if !validPlainText(field.value, field.max) {
			return invalidSnapshotField(field.name)
		}
	}
	if !validEmail(s.ControllerContact) {
		return invalidSnapshotField("controller_contact")
	}
	if !validEmail(s.ProcessorContact) {
		return invalidSnapshotField("processor_contact")
	}
	if s.RetentionYears != RetentionYearsV1 {
		return invalidSnapshotField("retention_years")
	}
	if !validPolicyURLV1(s.PolicyURL) {
		return invalidSnapshotField("policy_url")
	}
	if s.DSRCapability != DSRCapabilitySignerRequest {
		return invalidSnapshotField("dsr_capability")
	}
	if err := validateCopyV1(s.Copy); err != nil {
		return err
	}
	return nil
}

func validateCopyV1(copy Copy) error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "copy.title", value: copy.Title},
		{name: "copy.intro", value: copy.Intro},
		{name: "copy.controller_label", value: copy.ControllerLabel},
		{name: "copy.controller_contact_label", value: copy.ControllerContactLabel},
		{name: "copy.processor_label", value: copy.ProcessorLabel},
		{name: "copy.purpose_label", value: copy.PurposeLabel},
		{name: "copy.legal_basis_label", value: copy.LegalBasisLabel},
		{name: "copy.retention_label", value: copy.RetentionLabel},
		{name: "copy.retention_value", value: copy.RetentionValue},
		{name: "copy.authority_label", value: copy.AuthorityLabel},
		{name: "copy.rights_summary", value: copy.RightsSummary},
		{name: "copy.rights_body", value: copy.RightsBody},
		{name: "copy.submit_request_label", value: copy.SubmitRequestLabel},
		{name: "copy.kind_label", value: copy.KindLabel},
		{name: "copy.dsr_access_label", value: copy.DSRAccessLabel},
		{name: "copy.dsr_rectification_label", value: copy.DSRRectificationLabel},
		{name: "copy.dsr_erasure_label", value: copy.DSRErasureLabel},
		{name: "copy.dsr_restriction_label", value: copy.DSRRestrictionLabel},
		{name: "copy.dsr_portability_label", value: copy.DSRPortabilityLabel},
		{name: "copy.dsr_objection_label", value: copy.DSRObjectionLabel},
		{name: "copy.note_label", value: copy.NoteLabel},
		{name: "copy.note_placeholder", value: copy.NotePlaceholder},
		{name: "copy.send_request_label", value: copy.SendRequestLabel},
		{name: "copy.request_received", value: copy.RequestReceived},
		{name: "copy.read_policy_label", value: copy.ReadPolicyLabel},
		{name: "copy.acknowledgement_label", value: copy.AcknowledgementLabel},
		{name: "copy.fine_print", value: copy.FinePrint},
	} {
		if !validPlainText(field.value, 4000) {
			return invalidSnapshotField(field.name)
		}
	}
	return nil
}

func invalidSnapshotField(name string) error {
	return fmt.Errorf("%w: invalid %s", ErrInvalidSnapshot, name)
}

func isCanonicalUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return false
	}
	return parsed.UTC().Format(time.RFC3339Nano) == value
}

func validPlainText(value string, max int) bool {
	if value == "" || len(value) > max || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	if !validPlainText(value, 254) {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func validPolicyURLV1(value string) bool {
	if value == "" || len(value) > 2048 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return false
	}
	// A policy reference is either an absolute HTTPS URL or a root-relative
	// local-development path. A signer/DSR route is never a policy reference
	// and could contain the bearer magic token, so explicitly reject it.
	if parsed.IsAbs() {
		if parsed.Scheme != "https" || parsed.Host == "" {
			return false
		}
	} else if parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return false
	}
	lowerEscapedPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(lowerEscapedPath, "%2f") || strings.Contains(lowerEscapedPath, "%5c") ||
		strings.Contains(parsed.Path, "\\") {
		return false
	}
	cleanPath := strings.ToLower(path.Clean(parsed.Path))
	return !strings.HasPrefix(cleanPath, "/sign/") && cleanPath != "/sign"
}

// CanonicalJSON returns a newly allocated, deterministic byte representation
// of the snapshot. V1 uses an explicit private wire struct so future fields or
// struct reordering cannot silently redefine historical V1 digests.
func (s Snapshot) CanonicalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	definition, ok := supportedSchemaRegistry[s.Schema]
	if !ok || definition.canonicalJSON == nil {
		return nil, fmt.Errorf("%w: unsupported schema", ErrInvalidSnapshot)
	}
	return definition.canonicalJSON(s)
}

func canonicalJSONV1(s Snapshot) ([]byte, error) {
	return json.Marshal(snapshotV1Canonical{
		Schema:               s.Schema,
		DocumentID:           s.DocumentID,
		OrgID:                s.OrgID,
		RecipientID:          s.RecipientID,
		SentAt:               s.SentAt,
		Controller:           s.Controller,
		ControllerContact:    s.ControllerContact,
		Processor:            s.Processor,
		ProcessorContact:     s.ProcessorContact,
		PurposeSummary:       s.PurposeSummary,
		LegalBasisDisclosure: s.LegalBasisDisclosure,
		RetentionYears:       s.RetentionYears,
		SupervisoryAuthority: s.SupervisoryAuthority,
		PolicyURL:            s.PolicyURL,
		DSRCapability:        s.DSRCapability,
		Copy:                 canonicalCopyV1(s.Copy),
	})
}

// snapshotV1Canonical fixes both the V1 field set and JSON field order.
type snapshotV1Canonical struct {
	Schema               string          `json:"schema"`
	DocumentID           uuid.UUID       `json:"document_id"`
	OrgID                uuid.UUID       `json:"org_id"`
	RecipientID          uuid.UUID       `json:"recipient_id"`
	SentAt               string          `json:"sent_at"`
	Controller           string          `json:"controller"`
	ControllerContact    string          `json:"controller_contact"`
	Processor            string          `json:"processor"`
	ProcessorContact     string          `json:"processor_contact"`
	PurposeSummary       string          `json:"purpose_summary"`
	LegalBasisDisclosure string          `json:"legal_basis_disclosure"`
	RetentionYears       int             `json:"retention_years"`
	SupervisoryAuthority string          `json:"supervisory_authority"`
	PolicyURL            string          `json:"policy_url"`
	DSRCapability        DSRCapability   `json:"dsr_capability"`
	Copy                 copyV1Canonical `json:"copy"`
}

// copyV1Canonical fixes the nested rendered-copy field set and order too.
type copyV1Canonical struct {
	Title                  string `json:"title"`
	Intro                  string `json:"intro"`
	ControllerLabel        string `json:"controller_label"`
	ControllerContactLabel string `json:"controller_contact_label"`
	ProcessorLabel         string `json:"processor_label"`
	PurposeLabel           string `json:"purpose_label"`
	LegalBasisLabel        string `json:"legal_basis_label"`
	RetentionLabel         string `json:"retention_label"`
	RetentionValue         string `json:"retention_value"`
	AuthorityLabel         string `json:"authority_label"`
	RightsSummary          string `json:"rights_summary"`
	RightsBody             string `json:"rights_body"`
	SubmitRequestLabel     string `json:"submit_request_label"`
	KindLabel              string `json:"kind_label"`
	DSRAccessLabel         string `json:"dsr_access_label"`
	DSRRectificationLabel  string `json:"dsr_rectification_label"`
	DSRErasureLabel        string `json:"dsr_erasure_label"`
	DSRRestrictionLabel    string `json:"dsr_restriction_label"`
	DSRPortabilityLabel    string `json:"dsr_portability_label"`
	DSRObjectionLabel      string `json:"dsr_objection_label"`
	NoteLabel              string `json:"note_label"`
	NotePlaceholder        string `json:"note_placeholder"`
	SendRequestLabel       string `json:"send_request_label"`
	RequestReceived        string `json:"request_received"`
	ReadPolicyLabel        string `json:"read_policy_label"`
	AcknowledgementLabel   string `json:"acknowledgement_label"`
	FinePrint              string `json:"fine_print"`
}

func canonicalCopyV1(copy Copy) copyV1Canonical {
	return copyV1Canonical{
		Title:                  copy.Title,
		Intro:                  copy.Intro,
		ControllerLabel:        copy.ControllerLabel,
		ControllerContactLabel: copy.ControllerContactLabel,
		ProcessorLabel:         copy.ProcessorLabel,
		PurposeLabel:           copy.PurposeLabel,
		LegalBasisLabel:        copy.LegalBasisLabel,
		RetentionLabel:         copy.RetentionLabel,
		RetentionValue:         copy.RetentionValue,
		AuthorityLabel:         copy.AuthorityLabel,
		RightsSummary:          copy.RightsSummary,
		RightsBody:             copy.RightsBody,
		SubmitRequestLabel:     copy.SubmitRequestLabel,
		KindLabel:              copy.KindLabel,
		DSRAccessLabel:         copy.DSRAccessLabel,
		DSRRectificationLabel:  copy.DSRRectificationLabel,
		DSRErasureLabel:        copy.DSRErasureLabel,
		DSRRestrictionLabel:    copy.DSRRestrictionLabel,
		DSRPortabilityLabel:    copy.DSRPortabilityLabel,
		DSRObjectionLabel:      copy.DSRObjectionLabel,
		NoteLabel:              copy.NoteLabel,
		NotePlaceholder:        copy.NotePlaceholder,
		SendRequestLabel:       copy.SendRequestLabel,
		RequestReceived:        copy.RequestReceived,
		ReadPolicyLabel:        copy.ReadPolicyLabel,
		AcknowledgementLabel:   copy.AcknowledgementLabel,
		FinePrint:              copy.FinePrint,
	}
}

// Digest returns the lowercase hexadecimal SHA-256 digest of CanonicalJSON.
func (s Snapshot) Digest() (string, error) {
	canonical, err := s.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// Evidence binds a self-contained snapshot to its canonical digest. Schema is
// repeated at the envelope level so verifiers can select the correct validator
// before interpreting Snapshot, while Validate requires both copies to agree.
type Evidence struct {
	Schema   string   `json:"schema"`
	Digest   string   `json:"digest"`
	Snapshot Snapshot `json:"snapshot"`
}

// NewEvidence validates snapshot and constructs its evidence envelope.
func NewEvidence(snapshot Snapshot) (Evidence, error) {
	digest, err := snapshot.Digest()
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{Schema: snapshot.Schema, Digest: digest, Snapshot: snapshot}, nil
}

// BindAuditPayload adds a complete validated evidence triplet to payload.
// Existing notice fields are rejected instead of being overwritten, and no
// mutation occurs unless evidence and all destinations have first validated.
func (e Evidence) BindAuditPayload(payload map[string]any) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuditPayload, err)
	}
	if payload == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidAuditPayload)
	}
	for _, key := range []string{AuditNoticeSchemaKey, AuditNoticeDigestKey, AuditNoticeSnapshotKey} {
		if _, exists := payload[key]; exists {
			return fmt.Errorf("%w: notice field already present", ErrInvalidAuditPayload)
		}
	}
	payload[AuditNoticeSchemaKey] = e.Schema
	payload[AuditNoticeDigestKey] = e.Digest
	payload[AuditNoticeSnapshotKey] = e.Snapshot
	return nil
}

// Validate verifies the supported schema, complete snapshot, digest encoding,
// and digest commitment. Digest comparison is constant-time after enforcing
// the fixed lowercase SHA-256 encoding.
func (e Evidence) Validate() error {
	if e.Schema == "" || e.Schema != e.Snapshot.Schema {
		return fmt.Errorf("%w: schema mismatch", ErrInvalidEvidence)
	}
	if err := e.Snapshot.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvidence, err)
	}
	if len(e.Digest) != sha256.Size*2 || e.Digest != strings.ToLower(e.Digest) {
		return fmt.Errorf("%w: invalid digest encoding", ErrInvalidEvidence)
	}
	if _, err := hex.DecodeString(e.Digest); err != nil {
		return fmt.Errorf("%w: invalid digest encoding", ErrInvalidEvidence)
	}
	expected, err := e.Snapshot.Digest()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvidence, err)
	}
	if subtle.ConstantTimeCompare([]byte(e.Digest), []byte(expected)) != 1 {
		return fmt.Errorf("%w: digest mismatch", ErrInvalidEvidence)
	}
	return nil
}

// ValidateAuditPayload validates the Article 13 evidence embedded in one
// arbitrary audit payload object. A payload with none of the three notice keys
// is accepted as legacy evidence. Once any notice key exists, the complete
// triplet is mandatory and its snapshot must bind to the audit row identities.
func ValidateAuditPayload(raw []byte, expectedOrgID, expectedDocumentID, expectedRecipientID uuid.UUID) error {
	if err := validateUniqueJSONObject(raw); err != nil {
		return fmt.Errorf("%w: invalid JSON object", ErrInvalidAuditPayload)
	}

	var payload map[string]json.RawMessage
	if err := decodeSingleJSON(raw, &payload, false); err != nil || payload == nil {
		return fmt.Errorf("%w: invalid JSON object", ErrInvalidAuditPayload)
	}
	schemaRaw, hasSchema := payload[AuditNoticeSchemaKey]
	digestRaw, hasDigest := payload[AuditNoticeDigestKey]
	snapshotRaw, hasSnapshot := payload[AuditNoticeSnapshotKey]
	present := 0
	for _, exists := range []bool{hasSchema, hasDigest, hasSnapshot} {
		if exists {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != 3 {
		return fmt.Errorf("%w: partial notice evidence", ErrInvalidAuditPayload)
	}

	var schema string
	if err := decodeSingleJSON(schemaRaw, &schema, false); err != nil || schema == "" {
		return fmt.Errorf("%w: invalid notice schema", ErrInvalidAuditPayload)
	}
	var digest string
	if err := decodeSingleJSON(digestRaw, &digest, false); err != nil || digest == "" {
		return fmt.Errorf("%w: invalid notice digest", ErrInvalidAuditPayload)
	}
	if err := validateUniqueJSONObject(snapshotRaw); err != nil {
		return fmt.Errorf("%w: invalid notice snapshot", ErrInvalidAuditPayload)
	}
	var snapshot Snapshot
	if err := decodeSingleJSON(snapshotRaw, &snapshot, true); err != nil {
		return fmt.Errorf("%w: invalid notice snapshot", ErrInvalidAuditPayload)
	}
	evidence := Evidence{Schema: schema, Digest: digest, Snapshot: snapshot}
	if err := evidence.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuditPayload, err)
	}
	if expectedOrgID == uuid.Nil || expectedDocumentID == uuid.Nil || expectedRecipientID == uuid.Nil {
		return fmt.Errorf("%w: missing expected identity", ErrInvalidAuditPayload)
	}
	if snapshot.OrgID != expectedOrgID || snapshot.DocumentID != expectedDocumentID || snapshot.RecipientID != expectedRecipientID {
		return fmt.Errorf("%w: notice identity mismatch", ErrInvalidAuditPayload)
	}
	return nil
}

func decodeSingleJSON(raw []byte, destination any, disallowUnknown bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// validateUniqueJSONObject requires exactly one JSON object and rejects
// duplicate names at every nesting level. encoding/json otherwise accepts the
// last duplicate, which would make an evidentiary payload ambiguous.
func validateUniqueJSONObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := opening.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("JSON value is not an object")
	}
	if err := consumeJSONObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func consumeJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate JSON object key")
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := closing.(json.Delim); !ok || delim != '}' {
		return errors.New("invalid JSON object close")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closeDelim, ok := closing.(json.Delim); !ok || closeDelim != ']' {
			return errors.New("invalid JSON array close")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
