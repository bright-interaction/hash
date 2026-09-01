// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package article13

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	documentID  = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	orgID       = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	recipientID = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

const goldenCanonicalJSON = `{"schema":"hash-a13-2026-08-31","document_id":"11111111-1111-4111-8111-111111111111","org_id":"22222222-2222-4222-8222-222222222222","recipient_id":"33333333-3333-4333-8333-333333333333","sent_at":"2026-08-31T10:34:56.123456789Z","controller":"Customer AB","controller_contact":"contracts@customer.example","processor":"Operator AB","processor_contact":"privacy@operator.example","purpose_summary":"Collect your response to Customer agreement and preserve evidence of the process.","legal_basis_disclosure":"Controller confirmed: GDPR Article 6(1)(b) — processing necessary for a contract or requested pre-contractual steps.","retention_years":7,"supervisory_authority":"Integritetsskyddsmyndigheten (IMY), Sweden","policy_url":"https://operator.example/legal/privacy","dsr_capability":"signer_request_submission","copy":{"title":"Before you respond: how we handle your data","intro":"You are about to respond to Customer agreement. Under GDPR Article 13 we have to tell you who is processing your data, why, and how to exercise your rights.","controller_label":"Data controller","controller_contact_label":"Controller contact","processor_label":"Data processor","purpose_label":"Purpose","legal_basis_label":"Legal basis","retention_label":"Retention","retention_value":"Hash applies a fixed 7-year evidence-retention policy to independently owned source or rendered PDF versions when a document is sent, completed final PDFs and audit certificates, and signature artifacts captured before a signing ceremony later ends without completion. The controller must ensure that period matches the applicable contract and law.","authority_label":"Supervisory authority","rights_summary":"Your rights under GDPR Art. 15-22","rights_body":"Access, rectification, erasure, restriction, portability, objection. Use the form below to send a request directly from this page.","submit_request_label":"Submit a data-subject request","kind_label":"Kind","dsr_access_label":"Access (Art. 15)","dsr_rectification_label":"Rectification (Art. 16)","dsr_erasure_label":"Erasure (Art. 17)","dsr_restriction_label":"Restriction (Art. 18)","dsr_portability_label":"Portability (Art. 20)","dsr_objection_label":"Objection (Art. 21)","note_label":"Note (optional)","note_placeholder":"Anything that helps us scope the request","send_request_label":"Send request","request_received":"Request received. The controller will respond under the applicable GDPR deadline; identity checks or a lawful extension may affect timing.","read_policy_label":"Read the full privacy policy","acknowledgement_label":"I understand, continue","fine_print":"Acknowledging this notice is required to respond to this document. It does not change the fixed Hash evidence-retention period; deletion remains subject to immutable retention and applicable controller obligations."}}`

const goldenDigest = "860e2e8088c8518a1a96c2d2c28c6684c759d98ca9adb79e71f5c8073ab0cb36"

func validInput() Input {
	return Input{
		DocumentID:           documentID,
		OrgID:                orgID,
		RecipientID:          recipientID,
		SentAt:               time.Date(2026, time.August, 31, 12, 34, 56, 123456789, time.FixedZone("CEST", 2*60*60)),
		Controller:           "Customer AB",
		ControllerContact:    "contracts@customer.example",
		Processor:            "Operator AB",
		ProcessorContact:     "privacy@operator.example",
		PurposeSummary:       "Collect your response to Customer agreement and preserve evidence of the process.",
		LegalBasisDisclosure: "Controller confirmed: GDPR Article 6(1)(b) — processing necessary for a contract or requested pre-contractual steps.",
		RetentionYears:       RetentionYearsV1,
		SupervisoryAuthority: "Integritetsskyddsmyndigheten (IMY), Sweden",
		PolicyURL:            "https://operator.example/legal/privacy",
		DSRCapability:        DSRCapabilitySignerRequest,
		Copy:                 validCopy(),
	}
}

func validCopy() Copy {
	return Copy{
		Title:                  "Before you respond: how we handle your data",
		Intro:                  "You are about to respond to Customer agreement. Under GDPR Article 13 we have to tell you who is processing your data, why, and how to exercise your rights.",
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

func validSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(validInput())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestNewSnapshotCanonicalizesSentAtAndValidates(t *testing.T) {
	snapshot := validSnapshot(t)
	if Schema != SchemaV1 {
		t.Fatalf("current schema alias = %q, want %q", Schema, SchemaV1)
	}
	if snapshot.Schema != SchemaV1 {
		t.Fatalf("schema = %q", snapshot.Schema)
	}
	if snapshot.SentAt != "2026-08-31T10:34:56.123456789Z" {
		t.Fatalf("sent_at = %q", snapshot.SentAt)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSupportedSchemaRegistryKeepsHistoricalSchemasAndRejectsFutureOnes(t *testing.T) {
	if !IsSupportedSchema(SchemaV1) {
		t.Fatal("historical V1 schema is absent from the supported registry")
	}
	if !IsSupportedSchema(CurrentSchema) {
		t.Fatal("current schema is absent from the supported registry")
	}
	const futureSchema = "hash-a13-2099-01-01"
	if IsSupportedSchema(futureSchema) {
		t.Fatal("unimplemented future schema is trusted")
	}

	first := SupportedSchemas()
	if !reflect.DeepEqual(first, []string{SchemaV1}) {
		t.Fatalf("SupportedSchemas() = %#v, want frozen historical registry", first)
	}
	first[0] = futureSchema
	if !reflect.DeepEqual(SupportedSchemas(), []string{SchemaV1}) {
		t.Fatal("caller mutated the supported schema registry")
	}

	if _, err := NewSnapshotForSchema(SchemaV1, validInput()); err != nil {
		t.Fatalf("rolling reader rejected supported historical schema: %v", err)
	}
	if _, err := NewSnapshotForSchema(futureSchema, validInput()); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("future schema construction error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestCanonicalSentAtIsSharedBySnapshotAndSendEpochMarkers(t *testing.T) {
	value := time.Date(2026, 8, 31, 12, 34, 56, 123456789, time.FixedZone("CEST", 2*60*60))
	canonical, err := CanonicalSentAt(value)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "2026-08-31T10:34:56.123456789Z" {
		t.Fatalf("CanonicalSentAt() = %q", canonical)
	}
	if err := ValidateCanonicalSentAt(canonical); err != nil {
		t.Fatalf("canonical timestamp rejected: %v", err)
	}
	for _, invalid := range []string{
		"", "0001-01-01T00:00:00Z", "2026-08-31T10:34:56+00:00", "2026-08-31T10:34:56.1200Z",
	} {
		if err := ValidateCanonicalSentAt(invalid); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("ValidateCanonicalSentAt(%q) error = %v, want ErrInvalidSnapshot", invalid, err)
		}
	}
	if _, err := CanonicalSentAt(time.Time{}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("CanonicalSentAt(zero) error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestV1RenderedMaterialConstructorsMatchFrozenEnglishContract(t *testing.T) {
	const documentName = "Customer agreement"
	if got := RenderedCopyV1(documentName); !reflect.DeepEqual(got, validCopy()) {
		t.Fatalf("RenderedCopyV1() drifted from frozen V1 copy\n got: %#v\nwant: %#v", got, validCopy())
	}
	const wantPurpose = "Administering the response process for Customer agreement, recording participant actions, producing applicable final artifacts, and retaining captured evidence under Hash's fixed seven-year evidence policy. The controller must ensure that period is lawful and Hash does not determine legal effect for the document."
	if got := PurposeSummaryV1(documentName); got != wantPurpose {
		t.Fatalf("PurposeSummaryV1() = %q, want %q", got, wantPurpose)
	}
	wantBasis := validInput().LegalBasisDisclosure
	if got, err := LegalBasisDisclosureV1("contract"); err != nil || got != wantBasis {
		t.Fatalf("LegalBasisDisclosureV1() = %q, %v; want %q", got, err, wantBasis)
	}
}

func TestValidateDisclosurePreflightMatchesCompleteV1SnapshotRules(t *testing.T) {
	valid := DisclosurePreflight{
		DocumentName:      "Customer agreement",
		Controller:        "Customer AB",
		ControllerContact: "contracts@customer.example",
		LawfulBasis:       "contract",
	}
	if err := ValidateDisclosurePreflight(valid); err != nil {
		t.Fatalf("valid disclosure rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*DisclosurePreflight)
	}{
		{name: "blank document name", mutate: func(in *DisclosurePreflight) { in.DocumentName = " " }},
		{name: "document control character", mutate: func(in *DisclosurePreflight) { in.DocumentName = "Agreement\nInjected" }},
		{name: "document exceeds generated purpose limit", mutate: func(in *DisclosurePreflight) { in.DocumentName = strings.Repeat("x", 1900) }},
		{name: "controller too long", mutate: func(in *DisclosurePreflight) { in.Controller = strings.Repeat("x", 201) }},
		{name: "controller control character", mutate: func(in *DisclosurePreflight) { in.Controller = "Customer\tAB" }},
		{name: "invalid controller contact", mutate: func(in *DisclosurePreflight) { in.ControllerContact = "Customer <contracts@customer.example>" }},
		{name: "unsupported lawful basis", mutate: func(in *DisclosurePreflight) { in.LawfulBasis = "consent" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := ValidateDisclosurePreflight(candidate); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("ValidateDisclosurePreflight() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestCanonicalJSONAndDigestAreGoldenAndReturnIndependentBytes(t *testing.T) {
	snapshot := validSnapshot(t)
	wantJSON := goldenCanonicalJSON

	first, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != wantJSON {
		t.Fatalf("canonical JSON changed\n got: %s\nwant: %s", first, wantJSON)
	}
	first[0] = 'X'
	second, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != wantJSON {
		t.Fatalf("caller mutation affected later canonical bytes: %s", second)
	}

	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != goldenDigest {
		t.Fatalf("digest = %q, want %q", digest, goldenDigest)
	}
}

func TestSnapshotValidationRejectsEveryInvalidMaterialClass(t *testing.T) {
	base := validSnapshot(t)
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{name: "unsupported schema", mutate: func(s *Snapshot) { s.Schema = "hash-a13-future" }},
		{name: "nil document", mutate: func(s *Snapshot) { s.DocumentID = uuid.Nil }},
		{name: "nil org", mutate: func(s *Snapshot) { s.OrgID = uuid.Nil }},
		{name: "nil recipient", mutate: func(s *Snapshot) { s.RecipientID = uuid.Nil }},
		{name: "sent at timezone offset", mutate: func(s *Snapshot) { s.SentAt = "2026-08-31T10:34:56+00:00" }},
		{name: "sent at noncanonical fraction", mutate: func(s *Snapshot) { s.SentAt = "2026-08-31T10:34:56.1200Z" }},
		{name: "sent at zero", mutate: func(s *Snapshot) { s.SentAt = time.Time{}.Format(time.RFC3339Nano) }},
		{name: "blank controller", mutate: func(s *Snapshot) { s.Controller = "" }},
		{name: "controller whitespace", mutate: func(s *Snapshot) { s.Controller = " Customer AB" }},
		{name: "controller control", mutate: func(s *Snapshot) { s.Controller = "Customer\nAB" }},
		{name: "invalid controller contact", mutate: func(s *Snapshot) { s.ControllerContact = "Customer <contracts@customer.example>" }},
		{name: "blank processor", mutate: func(s *Snapshot) { s.Processor = "" }},
		{name: "invalid processor contact", mutate: func(s *Snapshot) { s.ProcessorContact = "not-an-email" }},
		{name: "blank purpose", mutate: func(s *Snapshot) { s.PurposeSummary = "" }},
		{name: "blank legal basis", mutate: func(s *Snapshot) { s.LegalBasisDisclosure = "" }},
		{name: "wrong retention", mutate: func(s *Snapshot) { s.RetentionYears = 8 }},
		{name: "blank authority", mutate: func(s *Snapshot) { s.SupervisoryAuthority = "" }},
		{name: "http policy", mutate: func(s *Snapshot) { s.PolicyURL = "http://operator.example/privacy" }},
		{name: "policy credentials", mutate: func(s *Snapshot) { s.PolicyURL = "https://user@operator.example/privacy" }},
		{name: "policy query", mutate: func(s *Snapshot) { s.PolicyURL = "https://operator.example/privacy?token=secret" }},
		{name: "policy fragment", mutate: func(s *Snapshot) { s.PolicyURL = "https://operator.example/privacy#part" }},
		{name: "magic signer route", mutate: func(s *Snapshot) { s.PolicyURL = "/sign/secret-bearer/dsr" }},
		{name: "encoded magic signer route", mutate: func(s *Snapshot) { s.PolicyURL = "/sign%2Fsecret-bearer%2Fdsr" }},
		{name: "traversal to magic signer route", mutate: func(s *Snapshot) { s.PolicyURL = "/legal/%2e%2e/sign/secret-bearer/dsr" }},
		{name: "double slash magic signer route", mutate: func(s *Snapshot) { s.PolicyURL = "https://operator.example//sign/secret-bearer/dsr" }},
		{name: "backslash magic signer route", mutate: func(s *Snapshot) { s.PolicyURL = "/sign\\secret-bearer\\dsr" }},
		{name: "missing dsr capability", mutate: func(s *Snapshot) { s.DSRCapability = "" }},
		{name: "unknown dsr capability", mutate: func(s *Snapshot) { s.DSRCapability = "url:/sign/secret/dsr" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := base
			tt.mutate(&snapshot)
			if err := snapshot.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Validate() error = %v, want ErrInvalidSnapshot", err)
			}
			if _, err := snapshot.CanonicalJSON(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("CanonicalJSON() error = %v, want ErrInvalidSnapshot", err)
			}
			if _, err := snapshot.Digest(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Digest() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestSnapshotAcceptsRootRelativeDevelopmentPolicy(t *testing.T) {
	in := validInput()
	in.PolicyURL = "/legal/privacy"
	if _, err := NewSnapshot(in); err != nil {
		t.Fatal(err)
	}
}

func TestEveryRenderedCopyFieldIsRequiredAndDigestMaterial(t *testing.T) {
	base := validSnapshot(t)
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	copyType := reflect.TypeOf(base.Copy)
	for index := 0; index < copyType.NumField(); index++ {
		field := copyType.Field(index)
		t.Run(field.Name, func(t *testing.T) {
			blank := base
			reflect.ValueOf(&blank.Copy).Elem().Field(index).SetString("")
			if err := blank.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("blank copy field Validate() error = %v, want ErrInvalidSnapshot", err)
			}

			changed := base
			value := reflect.ValueOf(&changed.Copy).Elem().Field(index)
			value.SetString(value.String() + " changed")
			changedDigest, err := changed.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if changedDigest == baseDigest {
				t.Fatal("copy change did not change snapshot digest")
			}
		})
	}
}

func TestNewSnapshotRejectsZeroTime(t *testing.T) {
	in := validInput()
	in.SentAt = time.Time{}
	if _, err := NewSnapshot(in); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
	}
}

func TestEvidenceValidationRejectsEnvelopeAndDigestTampering(t *testing.T) {
	snapshot := validSnapshot(t)
	evidence, err := NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{name: "empty envelope schema", mutate: func(e *Evidence) { e.Schema = "" }},
		{name: "mismatched envelope schema", mutate: func(e *Evidence) { e.Schema = "hash-a13-future" }},
		{name: "unsupported snapshot schema", mutate: func(e *Evidence) { e.Schema = "hash-a13-future"; e.Snapshot.Schema = e.Schema }},
		{name: "short digest", mutate: func(e *Evidence) { e.Digest = e.Digest[:62] }},
		{name: "uppercase digest", mutate: func(e *Evidence) { e.Digest = strings.ToUpper(e.Digest) }},
		{name: "nonhex digest", mutate: func(e *Evidence) { e.Digest = strings.Repeat("z", 64) }},
		{name: "wrong digest", mutate: func(e *Evidence) { e.Digest = strings.Repeat("0", 64) }},
		{name: "tampered snapshot", mutate: func(e *Evidence) { e.Snapshot.Controller = "Other Customer AB" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := evidence
			tt.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("Validate() error = %v, want ErrInvalidEvidence", err)
			}
		})
	}
}

func TestEvidenceJSONRoundTripIsIndependentOfLaterRuntimeSettings(t *testing.T) {
	original, err := NewEvidence(validSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate every mutable operator/controller disclosure changing after the
	// ceremony. Historical verification consumes only raw, not current config.
	changed := validInput()
	changed.Controller = "Renamed Customer AB"
	changed.ControllerContact = "new-contracts@customer.example"
	changed.Processor = "Replacement Operator AB"
	changed.ProcessorContact = "privacy@replacement.example"
	changed.PurposeSummary = "Different disclosure text."
	changed.LegalBasisDisclosure = "Different supported disclosure text."
	changed.SupervisoryAuthority = "A different applicable authority"
	changed.PolicyURL = "https://replacement.example/privacy"
	if _, err := NewSnapshot(changed); err != nil {
		t.Fatal(err)
	}

	var restored Evidence
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("historical evidence no longer verifies: %v", err)
	}
	if !reflect.DeepEqual(restored, original) {
		t.Fatalf("round trip changed evidence\n got: %#v\nwant: %#v", restored, original)
	}
}

func TestSnapshotWireFormHasNoCredentialOrDSREndpoint(t *testing.T) {
	snapshot := validSnapshot(t)
	raw, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("magic_token"),
		[]byte("dsr_endpoint"),
		[]byte("/sign/"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("canonical snapshot contains forbidden credential-bearing material %q: %s", forbidden, raw)
		}
	}
	if !bytes.Contains(raw, []byte(`"dsr_capability":"signer_request_submission"`)) {
		t.Fatalf("canonical snapshot lacks non-secret DSR capability marker: %s", raw)
	}
}

func TestSchemaV1HistoricalFixtureRemainsVerifiable(t *testing.T) {
	// This literal fixture locks the V1 envelope, canonical field set, and
	// digest. When V2 is added, retain the V1 validator/canonicalizer and add a
	// new dispatch case; never redefine SchemaV1 or this historical fixture.
	const fixture = `{"schema":"hash-a13-2026-08-31","digest":"` + goldenDigest + `","snapshot":` + goldenCanonicalJSON + `}`
	var evidence Evidence
	if err := json.Unmarshal([]byte(fixture), &evidence); err != nil {
		t.Fatal(err)
	}
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
}

func validEvidence(t *testing.T) Evidence {
	t.Helper()
	evidence, err := NewEvidence(validSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func auditPayloadJSON(t *testing.T, evidence Evidence) []byte {
	t.Helper()
	payload := map[string]any{
		"side": "signer",
		"arbitrary_metadata": map[string]any{
			"attempt": 1,
			"flags":   []any{true, "retained"},
		},
	}
	if err := evidence.BindAuditPayload(payload); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEvidenceBindAuditPayloadRequiresValidEvidenceAndEmptyDestinationFields(t *testing.T) {
	evidence := validEvidence(t)
	payload := map[string]any{"side": "signer"}
	if err := evidence.BindAuditPayload(payload); err != nil {
		t.Fatal(err)
	}
	if payload[AuditNoticeSchemaKey] != evidence.Schema || payload[AuditNoticeDigestKey] != evidence.Digest {
		t.Fatalf("bound schema/digest = %#v / %#v", payload[AuditNoticeSchemaKey], payload[AuditNoticeDigestKey])
	}
	if snapshot, ok := payload[AuditNoticeSnapshotKey].(Snapshot); !ok || !reflect.DeepEqual(snapshot, evidence.Snapshot) {
		t.Fatalf("bound snapshot = %#v", payload[AuditNoticeSnapshotKey])
	}

	for _, key := range []string{AuditNoticeSchemaKey, AuditNoticeDigestKey, AuditNoticeSnapshotKey} {
		t.Run("collision "+key, func(t *testing.T) {
			candidate := map[string]any{"side": "signer", key: nil}
			before := len(candidate)
			if err := evidence.BindAuditPayload(candidate); !errors.Is(err, ErrInvalidAuditPayload) {
				t.Fatalf("BindAuditPayload() error = %v, want ErrInvalidAuditPayload", err)
			}
			if len(candidate) != before {
				t.Fatalf("failed bind mutated payload: %#v", candidate)
			}
		})
	}

	invalid := evidence
	invalid.Digest = strings.Repeat("0", 64)
	destination := map[string]any{"side": "signer"}
	if err := invalid.BindAuditPayload(destination); !errors.Is(err, ErrInvalidEvidence) || !errors.Is(err, ErrInvalidAuditPayload) {
		t.Fatalf("invalid evidence bind error = %v", err)
	}
	if len(destination) != 1 {
		t.Fatalf("invalid evidence mutated payload: %#v", destination)
	}
	if err := evidence.BindAuditPayload(nil); !errors.Is(err, ErrInvalidAuditPayload) {
		t.Fatalf("nil bind error = %v, want ErrInvalidAuditPayload", err)
	}
}

func TestValidateAuditPayloadAcceptsValidAndLegacyObjects(t *testing.T) {
	evidence := validEvidence(t)
	raw := auditPayloadJSON(t, evidence)
	if err := ValidateAuditPayload(raw, orgID, documentID, recipientID); err != nil {
		t.Fatal(err)
	}

	for _, legacy := range []string{
		`{}`,
		`{"side":"signer","notice":"old free-form field"}`,
		`{"nested":{"notice_digest":"not an audit evidence field here"},"values":[1,true,null]}`,
	} {
		if err := ValidateAuditPayload([]byte(legacy), uuid.Nil, uuid.Nil, uuid.Nil); err != nil {
			t.Fatalf("legacy payload %s rejected: %v", legacy, err)
		}
	}
}

func TestValidateAuditPayloadRejectsEveryPartialNoticeTriplet(t *testing.T) {
	evidence := validEvidence(t)
	fields := []struct {
		key   string
		value any
	}{
		{key: AuditNoticeSchemaKey, value: evidence.Schema},
		{key: AuditNoticeDigestKey, value: evidence.Digest},
		{key: AuditNoticeSnapshotKey, value: evidence.Snapshot},
	}
	for mask := 1; mask < 1<<len(fields)-1; mask++ {
		payload := map[string]any{"side": "signer"}
		var names []string
		for index, field := range fields {
			if mask&(1<<index) != 0 {
				payload[field.key] = field.value
				names = append(names, field.key)
			}
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			if err := ValidateAuditPayload(raw, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidAuditPayload) {
				t.Fatalf("ValidateAuditPayload() error = %v, want ErrInvalidAuditPayload", err)
			}
		})
	}
}

func TestValidateAuditPayloadRejectsUnknownSnapshotFields(t *testing.T) {
	evidence := validEvidence(t)
	base := auditPayloadJSON(t, evidence)

	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "top-level snapshot", mutate: func(snapshot map[string]any) { snapshot["unexpected"] = true }},
		{name: "nested copy", mutate: func(snapshot map[string]any) {
			copyObject := snapshot["copy"].(map[string]any)
			copyObject["unexpected"] = true
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := mutateAuditSnapshot(t, base, tt.mutate)
			if err := ValidateAuditPayload(raw, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidAuditPayload) {
				t.Fatalf("ValidateAuditPayload() error = %v, want ErrInvalidAuditPayload", err)
			}
		})
	}
}

func mutateAuditSnapshot(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(payload[AuditNoticeSnapshotKey], &snapshot); err != nil {
		t.Fatal(err)
	}
	mutate(snapshot)
	mutatedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payload[AuditNoticeSnapshotKey] = mutatedSnapshot
	mutatedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return mutatedPayload
}

func TestValidateAuditPayloadRejectsSchemaDigestSnapshotAndIdentityMismatch(t *testing.T) {
	evidence := validEvidence(t)
	base := auditPayloadJSON(t, evidence)

	var payload map[string]any
	if err := json.Unmarshal(base, &payload); err != nil {
		t.Fatal(err)
	}
	payload[AuditNoticeSchemaKey] = "hash-a13-future"
	schemaMismatch, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuditPayload(schemaMismatch, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("schema mismatch error = %v, want ErrInvalidEvidence", err)
	}

	if err := json.Unmarshal(base, &payload); err != nil {
		t.Fatal(err)
	}
	payload[AuditNoticeDigestKey] = strings.Repeat("0", 64)
	digestMismatch, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuditPayload(digestMismatch, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("digest mismatch error = %v, want ErrInvalidEvidence", err)
	}

	tampered := mutateAuditSnapshot(t, base, func(snapshot map[string]any) {
		snapshot["controller"] = "Tampered Customer AB"
	})
	if err := ValidateAuditPayload(tampered, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("tampered snapshot error = %v, want ErrInvalidEvidence", err)
	}

	identityTests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{name: "org", mutate: func(snapshot *Snapshot) { snapshot.OrgID = uuid.New() }},
		{name: "document", mutate: func(snapshot *Snapshot) { snapshot.DocumentID = uuid.New() }},
		{name: "recipient", mutate: func(snapshot *Snapshot) { snapshot.RecipientID = uuid.New() }},
	}
	for _, tt := range identityTests {
		t.Run(tt.name+" identity", func(t *testing.T) {
			snapshot := evidence.Snapshot
			tt.mutate(&snapshot)
			crossRowEvidence, err := NewEvidence(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			raw := auditPayloadJSON(t, crossRowEvidence)
			if err := ValidateAuditPayload(raw, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidAuditPayload) {
				t.Fatalf("identity mismatch error = %v, want ErrInvalidAuditPayload", err)
			}
		})
	}

	if err := ValidateAuditPayload(base, uuid.Nil, documentID, recipientID); !errors.Is(err, ErrInvalidAuditPayload) {
		t.Fatalf("nil expected identity error = %v, want ErrInvalidAuditPayload", err)
	}
}

func TestValidateAuditPayloadRejectsMalformedAmbiguousAndTrailingJSON(t *testing.T) {
	evidence := validEvidence(t)
	valid := auditPayloadJSON(t, evidence)
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "null", raw: []byte(`null`)},
		{name: "array", raw: []byte(`[]`)},
		{name: "scalar", raw: []byte(`true`)},
		{name: "malformed", raw: []byte(`{"side":`)},
		{name: "trailing object", raw: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "duplicate top field", raw: []byte(`{"side":"signer","side":"recipient"}`)},
		{name: "wrong schema type", raw: []byte(`{"notice_schema":1,"notice_digest":"x","notice_snapshot":{}}`)},
		{name: "wrong digest type", raw: []byte(`{"notice_schema":"x","notice_digest":null,"notice_snapshot":{}}`)},
		{name: "wrong snapshot type", raw: []byte(`{"notice_schema":"x","notice_digest":"x","notice_snapshot":[]}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAuditPayload(tt.raw, orgID, documentID, recipientID); !errors.Is(err, ErrInvalidAuditPayload) {
				t.Fatalf("ValidateAuditPayload() error = %v, want ErrInvalidAuditPayload", err)
			}
		})
	}
}
