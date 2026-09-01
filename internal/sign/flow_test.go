// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
)

func testCtx() context.Context { return context.Background() }
func testUUID() uuid.UUID      { return uuid.New() }

func TestFindSignatureFieldFor_RoleMatch(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p", Type: blocks.TypeParagraph, Text: "x"},
		{ID: "sig-client", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "client"}},
		{ID: "sig-provider", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "provider"}},
	}}
	got := findSignatureFieldFor(tree, "client")
	if got == nil || got.ID != "sig-client" {
		t.Errorf("client mismatch: %+v", got)
	}
	got = findSignatureFieldFor(tree, "provider")
	if got == nil || got.ID != "sig-provider" {
		t.Errorf("provider mismatch: %+v", got)
	}
}

func TestFindSignatureFieldFor_NoMatch(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p", Type: blocks.TypeParagraph, Text: "no fields here"},
	}}
	if got := findSignatureFieldFor(tree, "client"); got != nil {
		t.Errorf("expected nil; got %+v", got)
	}
}

func TestFindSignatureFieldFor_EmptyLegacyRoleMeansSignerOnly(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "sig-any", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": ""}},
	}}
	got := findSignatureFieldFor(tree, "signer")
	if got == nil || got.ID != "sig-any" {
		t.Errorf("empty legacy role should match signer; got %+v", got)
	}
	if got := findSignatureFieldFor(tree, "approver"); got != nil {
		t.Errorf("empty legacy role must not authorize approver; got %+v", got)
	}
}

func TestBuildHTMLDocument_IncludesSignatureCSS(t *testing.T) {
	out := buildHTMLDocument("", "<p>hi</p>", "<p>cert</p>")
	for _, want := range []string{
		"<!doctype html>",
		"hash-signature",
		"<p>hi</p>",
		"<p>cert</p>",
		"Caveat.woff2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "googleapis.com") || strings.Contains(out, "gstatic.com") {
		t.Error("rendered HTML still references third-party font CDN")
	}
}

func TestHtmlEscape(t *testing.T) {
	if got := htmlEscape(`<a href="x">&amp;</a>`); got != "&lt;a href=&quot;x&quot;&gt;&amp;amp;&lt;/a&gt;" {
		t.Errorf("unexpected escape: %q", got)
	}
}

func TestTextOrNull(t *testing.T) {
	if v := textOrNull(""); v.Valid {
		t.Error("empty should be invalid")
	}
	if v := textOrNull("x"); !v.Valid || v.String != "x" {
		t.Errorf("non-empty wrong: %+v", v)
	}
}

func TestTruncateFieldValueForCert(t *testing.T) {
	short := "hello"
	if got := truncateFieldValueForCert(short); got != short {
		t.Errorf("short value should not be truncated: %q", got)
	}
	long := strings.Repeat("x", 250)
	got := truncateFieldValueForCert(long)
	if !strings.HasSuffix(got, "[truncated, full value in document_fields]") {
		t.Errorf("expected truncation marker, got %q", got)
	}
	if len(got) > 260 {
		t.Errorf("truncated too long: %d chars", len(got))
	}
	international := strings.Repeat("界", 250)
	got = truncateFieldValueForCert(international)
	if !strings.HasPrefix(got, strings.Repeat("界", 200)) {
		t.Fatal("Unicode field value was not truncated on a rune boundary")
	}
	if !utf8.ValidString(got) {
		t.Fatal("Unicode field truncation emitted invalid UTF-8")
	}
}

func TestCommentBodyUnicodeAwareBounds(t *testing.T) {
	validInternational := strings.Repeat("界", maxCommentBodyRunes)
	if err := validateCommentBody(validInternational); err != nil {
		t.Fatalf("maximum-length international comment rejected: %v", err)
	}
	for name, body := range map[string]string{
		"empty":        " \t\n ",
		"invalid UTF8": string([]byte{0xff}),
		"rune limit":   strings.Repeat("x", maxCommentBodyRunes+1),
		"byte limit":   strings.Repeat("😀", maxCommentBodyBytes/4+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCommentBody(body); err == nil {
				t.Fatal("invalid comment body accepted")
			}
		})
	}
}

func TestAllCommentEntrypointsRejectOverlongBodyBeforeDependencies(t *testing.T) {
	body := strings.Repeat("x", maxCommentBodyRunes+1)
	engine := &Engine{}
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Status: "sent",
		SentAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	recipient := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
	rc := &RecipientContext{Document: doc, Recipient: recipient}
	evidence := ParticipantResponseEvidence{Notice: testArticle13NoticeEvidence(t, rc)}
	if _, err := engine.SignerComment(testCtx(), rc, body, evidence); err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatal("SignerComment accepted an overlong body")
	}
	if _, err := engine.SenderComment(testCtx(), uuid.Nil, uuid.Nil, uuid.Nil, "sender", body); err == nil {
		t.Fatal("SenderComment accepted an overlong body")
	}
}

func TestRenderFieldValuesSection_NilQueriesReturnsEmpty(t *testing.T) {
	if got := renderFieldValuesSection(testCtx(), nil, testUUID()); got != "" {
		t.Errorf("nil queries should yield empty; got %q", got)
	}
}

func TestAllRequiredRecipientsSigned_IncludesCounterSignerRoles(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "client-sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
		{ID: "section", Type: blocks.TypeConditional, Attrs: map[string]any{"expression": `var(show)`}, Content: []blocks.Block{
			{ID: "provider-sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "approver"}},
		}},
	}}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{SourceKind: "blocks", BlocksJson: raw, VariablesJson: json.RawMessage(`{"show":"true"}`)}
	recipients := []*generated.Recipient{
		{Role: "signer", Status: "signed"},
		{Role: "approver", Status: "viewed"},
		{Role: "viewer", Status: "pending"},
	}
	if allRequiredRecipientsSigned(doc, recipients) {
		t.Fatal("pending approver/counter-signer must block finalization")
	}
	recipients[1].Status = "signed"
	if !allRequiredRecipientsSigned(doc, recipients) {
		t.Fatal("all required signing roles are signed")
	}
	recipients = recipients[:1]
	if allRequiredRecipientsSigned(doc, recipients) {
		t.Fatal("a missing required role must block finalization")
	}
}

func TestAllRequiredRecipientsSigned_CustomRoleDoesNotInjectSigner(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "client-sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "client"}},
	}}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{SourceKind: "blocks", BlocksJson: raw, VariablesJson: json.RawMessage(`{}`)}
	if !allRequiredRecipientsSigned(doc, []*generated.Recipient{{Role: "client", Status: "signed"}}) {
		t.Fatal("custom-role-only document should complete without an implicit signer recipient")
	}
}

func TestAllRequiredRecipientsSigned_RequiresEveryRecipientInRole(t *testing.T) {
	doc := &generated.Document{SourceKind: "pdf"}
	recipients := []*generated.Recipient{
		{Role: "signer", Status: "signed"},
		{Role: "signer", Status: "viewed"},
		{Role: "approver", Status: "pending"}, // not a PDF signing role
	}
	if allRequiredRecipientsSigned(doc, recipients) {
		t.Fatal("one pending signer among several must block finalization")
	}
	recipients[1].Status = "signed"
	if !allRequiredRecipientsSigned(doc, recipients) {
		t.Fatal("non-required PDF approver must not block all signed signers")
	}
}

func TestReceivesCompletionEmail_IncludesRequiredCounterSigner(t *testing.T) {
	required := map[string]struct{}{"signer": {}, "approver": {}}
	for _, rec := range []*generated.Recipient{
		{Role: "signer", Status: "signed"},
		{Role: "approver", Status: "signed"},
	} {
		if !receivesCompletionEmail(rec, required) {
			t.Fatalf("required signed role %q should receive completion", rec.Role)
		}
	}
	for _, rec := range []*generated.Recipient{
		{Role: "approver", Status: "viewed"},
		{Role: "cc", Status: "signed"},
		{Role: "viewer", Status: "signed"},
	} {
		if receivesCompletionEmail(rec, required) {
			t.Fatalf("ineligible recipient %+v should not receive completion", rec)
		}
	}
}

func TestAllRequiredAcceptorsAccepted(t *testing.T) {
	recipients := []*generated.Recipient{
		{Role: "approver", Status: "accepted"},
		{Role: "cc", Status: "sent"},
	}
	if !allRequiredAcceptorsAccepted(recipients) {
		t.Fatal("accepted non-cc recipient with pending cc should be complete")
	}
	recipients[0].Status = "viewed"
	if allRequiredAcceptorsAccepted(recipients) {
		t.Fatal("pending required acceptor must block completion")
	}
	if allRequiredAcceptorsAccepted([]*generated.Recipient{{Role: "cc", Status: "sent"}}) {
		t.Fatal("cc-only acknowledgement has no accepting party")
	}
}

func TestInformationalRecipientsCannotCreateLegalResponses(t *testing.T) {
	for _, role := range []string{"signer", "approver", "customer_signer"} {
		if !recipients.CanRespond(role) {
			t.Errorf("required response role %q was rejected", role)
		}
	}
	for _, role := range []string{"", "cc", "viewer"} {
		if recipients.CanRespond(role) {
			t.Errorf("informational role %q was allowed to create legal response evidence", role)
		}
	}
}

func TestRecipientCanRequestChanges(t *testing.T) {
	tests := []struct {
		role, status string
		want         bool
	}{
		{"signer", "sent", true},
		{"approver", "viewed", true},
		{"customer_signer", "sent", true},
		{"signer", "signed", false},
		{"approver", "declined", false},
		{"cc", "sent", false},
		{"viewer", "viewed", false},
		{"signer", "bounced", false},
		{"signer", "accepted", false},
	}
	for _, tt := range tests {
		t.Run(tt.role+"_"+tt.status, func(t *testing.T) {
			if got := recipientCanRequestChanges(tt.role, tt.status); got != tt.want {
				t.Fatalf("recipientCanRequestChanges(%q, %q) = %v, want %v", tt.role, tt.status, got, tt.want)
			}
		})
	}
}

func TestSenderCommentNotificationsCoverCustomResponseRolesOnly(t *testing.T) {
	for _, role := range []string{"signer", "approver", "customer_signer", "legal_reviewer"} {
		if !recipientReceivesSenderComment(&generated.Recipient{Role: role}) {
			t.Errorf("response role %q did not receive sender comments", role)
		}
	}
	for _, role := range []string{"", "cc", "viewer", "INVALID ROLE"} {
		if recipientReceivesSenderComment(&generated.Recipient{Role: role}) {
			t.Errorf("unsupported role %q received a sender comment", role)
		}
	}
	if recipientReceivesSenderComment(nil) {
		t.Error("nil recipient received a sender comment")
	}
}

func TestAcceptedParticipantCannotDeclineWhileOtherAcknowledgementIsPending(t *testing.T) {
	participants := []*generated.Recipient{
		{Role: "approver", Status: "accepted"},
		{Role: "customer_reviewer", Status: "viewed"},
	}
	if allRequiredAcceptorsAccepted(participants) {
		t.Fatal("multi-participant acknowledgement completed with one response still pending")
	}
	if err := completedResponseError(participants[0].Status); !errors.Is(err, ErrAlreadyAccepted) {
		t.Fatalf("accepted participant decline guard = %v, want ErrAlreadyAccepted", err)
	}
	if participants[0].Status != "accepted" {
		t.Fatalf("accepted evidence was mutated to %q", participants[0].Status)
	}
}

func TestResponseAuditPayloadBindsNoticeDigest(t *testing.T) {
	snapshot, err := article13.NewSnapshot(article13.Input{
		DocumentID: uuid.New(), OrgID: uuid.New(), RecipientID: uuid.New(), SentAt: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		Controller: "Customer AB", ControllerContact: "legal@customer.example",
		Processor: "Operator AB", ProcessorContact: "privacy@operator.example", PurposeSummary: "Administer response",
		LegalBasisDisclosure: "Article 6(1)(b)", RetentionYears: article13.RetentionYearsV1,
		SupervisoryAuthority: "Applicable DPA", PolicyURL: "https://operator.example/privacy",
		DSRCapability: article13.DSRCapabilitySignerRequest,
		Copy: Article13NoticeCopy{
			Title: "Title", Intro: "Intro", ControllerLabel: "Controller", ControllerContactLabel: "Contact",
			ProcessorLabel: "Processor", PurposeLabel: "Purpose", LegalBasisLabel: "Legal basis",
			RetentionLabel: "Retention", RetentionValue: "Seven years", AuthorityLabel: "Authority",
			RightsSummary: "Rights", RightsBody: "Rights body", SubmitRequestLabel: "Submit request",
			KindLabel: "Kind", DSRAccessLabel: "Access", DSRRectificationLabel: "Rectification",
			DSRErasureLabel: "Erasure", DSRRestrictionLabel: "Restriction", DSRPortabilityLabel: "Portability",
			DSRObjectionLabel: "Objection", NoteLabel: "Note", NotePlaceholder: "Scope the request",
			SendRequestLabel: "Send request", RequestReceived: "Request received", ReadPolicyLabel: "Policy",
			AcknowledgementLabel: "I understand", FinePrint: "Fine print",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	notice, err := article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := responseAuditPayload(map[string]any{"side": "signer"}, notice)
	if err != nil {
		t.Fatal(err)
	}
	if payload[article13.AuditNoticeDigestKey] != notice.Digest || payload[article13.AuditNoticeSchemaKey] != Article13NoticeSchema || payload["side"] != "signer" {
		t.Fatalf("response evidence payload = %#v", payload)
	}
	boundSnapshot, ok := payload[article13.AuditNoticeSnapshotKey].(article13.Snapshot)
	if !ok || boundSnapshot != snapshot {
		t.Fatalf("durable notice snapshot = %#v, want %#v", payload[article13.AuditNoticeSnapshotKey], snapshot)
	}
	changed := snapshot
	changed.Copy.RequestReceived = "Updated receipt copy"
	changedEvidence, err := article13.NewEvidence(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedEvidence.Digest == notice.Digest {
		t.Fatal("server-authored DSR copy change did not invalidate the digest")
	}
	missing := snapshot
	missing.Copy.SendRequestLabel = ""
	if _, err := article13.NewEvidence(missing); err == nil {
		t.Fatal("incomplete server-authored DSR copy produced evidence")
	}
}

func TestTypedSignatureFailsClosedForHigherAssuranceTiers(t *testing.T) {
	for _, tier := range []string{"AES", "QES", "", "unknown"} {
		t.Run(tier, func(t *testing.T) {
			if err := requireSESTypedSignature(&generated.Document{RoutingTier: tier}); !errors.Is(err, ErrSignatureTierUnavailable) {
				t.Fatalf("tier %q got %v, want ErrSignatureTierUnavailable", tier, err)
			}
		})
	}
	if err := requireSESTypedSignature(&generated.Document{RoutingTier: "ses"}); err != nil {
		t.Fatalf("SES typed signing rejected: %v", err)
	}
	if err := requireSESTypedSignature(nil); !errors.Is(err, ErrSignatureTierUnavailable) {
		t.Fatalf("nil document got %v, want ErrSignatureTierUnavailable", err)
	}

	// The public /sign/{token}/sign handler delegates directly to Engine.Sign.
	// The tier check runs before any storage, DB, or audit dependency, proving a
	// direct higher-tier POST cannot fall through to typed SES signing.
	for _, tier := range []string{"AES", "QES"} {
		doc := &generated.Document{
			ID: uuid.New(), OrgID: uuid.New(), RoutingTier: tier,
			SentAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		}
		recipient := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
		rc := &RecipientContext{Document: doc, Recipient: recipient}
		_, err := (&Engine{}).Sign(testCtx(), rc, SignInput{
			TypedName: "Bypass Attempt", Font: "Caveat", Notice: testArticle13NoticeEvidence(t, rc),
		})
		if !errors.Is(err, ErrSignatureTierUnavailable) {
			t.Fatalf("direct %s Sign got %v, want ErrSignatureTierUnavailable", tier, err)
		}
	}
}

func TestSignRejectsOverlongTypedNameBeforeDependencies(t *testing.T) {
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), RoutingTier: "SES",
		SentAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	recipient := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
	rc := &RecipientContext{Document: doc, Recipient: recipient}

	if _, err := (&Engine{}).Sign(testCtx(), rc, SignInput{
		TypedName: strings.Repeat("界", render.MaxSignatureNameRunes+1),
		Font:      "Caveat",
		Notice:    testArticle13NoticeEvidence(t, rc),
	}); err == nil || !strings.Contains(err.Error(), "signature name") {
		t.Fatalf("overlong typed name got %v, want validation error", err)
	}

	validInternational := strings.Repeat("界", render.MaxSignatureNameRunes)
	if err := render.ValidateSignatureName(validInternational); err != nil {
		t.Fatalf("maximum-length international name rejected: %v", err)
	}
}

func TestCommentNotificationUsesTransactionalOutbox(t *testing.T) {
	store := &completionStoreStub{}
	engine := &Engine{Mailer: dispatch.QueueingMailer{}, OrgName: "Hash"}
	messages, err := engine.prepareNotificationTx(context.Background(), store, dispatch.KindNewComment, "sender@example.test", dispatch.TemplateContext{
		DocumentName:  "International agreement",
		RecipientName: "Åsa Öberg",
		OrgName:       "Hash",
		DeclineReason: "A durable comment",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || len(store.enqueued) != 1 {
		t.Fatalf("messages=%d outbox rows=%d, want one of each", len(messages), len(store.enqueued))
	}
	if store.enqueued[0].ToEmail != "sender@example.test" || store.enqueued[0].HtmlBody == "" || store.enqueued[0].TextBody == "" {
		t.Fatalf("incomplete durable comment delivery: %+v", store.enqueued[0])
	}

	wantErr := errors.New("forced outbox failure")
	failingStore := &completionStoreStub{enqueueAt: 1, enqueueErr: wantErr}
	if _, err := engine.prepareNotificationTx(context.Background(), failingStore, dispatch.KindNewComment, "sender@example.test", dispatch.TemplateContext{
		DocumentName: "Agreement", RecipientName: "Signer", OrgName: "Hash", DeclineReason: "Comment",
	}); !errors.Is(err, wantErr) {
		t.Fatalf("enqueue failure = %v, want %v", err, wantErr)
	}
}

func TestSignatureFieldMaterializationIsBlocksOnly(t *testing.T) {
	if !canMaterializeSignatureField(&generated.Document{SourceKind: "blocks"}) {
		t.Fatal("blocks documents need a ceremony field row materialized from their signature block")
	}
	for _, doc := range []*generated.Document{nil, {SourceKind: "pdf"}, {SourceKind: ""}} {
		if canMaterializeSignatureField(doc) {
			t.Fatalf("PDF/unknown source unexpectedly allowed invisible signature-field fallback: %+v", doc)
		}
	}
}

func TestEnvelopeNegotiationAndDeclineFailClosed(t *testing.T) {
	envelope := &generated.Document{IsEnvelope: true}
	for _, transition := range []string{"request changes", "revise", "decline"} {
		t.Run(transition, func(t *testing.T) {
			err := rejectUnsupportedEnvelopeTransition(envelope, transition)
			if !errors.Is(err, ErrEnvelopeTransitionUnsupported) {
				t.Fatalf("got %v, want ErrEnvelopeTransitionUnsupported", err)
			}
		})
	}
	if err := rejectUnsupportedEnvelopeTransition(&generated.Document{}, "revise"); err != nil {
		t.Fatalf("standalone document unexpectedly rejected: %v", err)
	}
}

func TestChangeRequestCanResolve_RejectsReplays(t *testing.T) {
	if !changeRequestCanResolve("open") {
		t.Fatal("open request should be claimable")
	}
	for _, status := range []string{"resolved", "", "approved", "denied"} {
		if changeRequestCanResolve(status) {
			t.Fatalf("status %q must not be claimable for a replay", status)
		}
	}
}

func TestReplaceBlockQuote_NestedAndSingleOccurrence(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{{
		ID: "section", Type: blocks.TypeCallout, Content: []blocks.Block{{
			ID: "price", Type: blocks.TypeParagraph, Text: "Price 100, then Price 100",
		}},
	}}}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	updated, changed, err := replaceBlockQuote(raw, "price", "Price 100", "Price 90")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected quote replacement")
	}
	if got := string(updated); !strings.Contains(got, "Price 90, then Price 100") {
		t.Fatalf("expected exactly the first occurrence replaced, got %s", got)
	}

	unchanged, changed, err := replaceBlockQuote(updated, "missing", "Price 100", "Price 80")
	if err != nil {
		t.Fatal(err)
	}
	if changed || string(unchanged) != string(updated) {
		t.Fatal("missing block should be an exact no-op")
	}
	if _, _, err := replaceBlockQuote(json.RawMessage(`not-json`), "price", "x", "y"); err == nil {
		t.Fatal("malformed blocks must propagate an error instead of resolving silently")
	}
}

func TestRevisionHasCapturedEvidenceFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		recipients []*generated.Recipient
		signatures []*generated.Signature
		fields     []*generated.DocumentField
		want       bool
	}{
		{name: "no response yet", recipients: []*generated.Recipient{{Status: "viewed"}}, want: false},
		{name: "signature row", signatures: []*generated.Signature{{ID: uuid.New()}}, want: true},
		{name: "signed status", recipients: []*generated.Recipient{{Status: "signed"}}, want: true},
		{name: "accepted status", recipients: []*generated.Recipient{{Status: "accepted"}}, want: true},
		{name: "signed timestamp", recipients: []*generated.Recipient{{Status: "pending", SignedAt: pgtype.Timestamptz{Valid: true}}}, want: true},
		{name: "field value", fields: []*generated.DocumentField{{Value: pgtype.Text{String: "accepted terms", Valid: true}}}, want: true},
		{name: "field completion", fields: []*generated.DocumentField{{CompletedAt: pgtype.Timestamptz{Valid: true}}}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := revisionHasCapturedEvidence(tt.recipients, tt.signatures, tt.fields); got != tt.want {
				t.Fatalf("revisionHasCapturedEvidence = %v, want %v", got, tt.want)
			}
		})
	}
}

type recordingEvidenceStorage struct {
	keys        []string
	retainUntil []time.Time
}

func (r *recordingEvidenceStorage) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (r *recordingEvidenceStorage) GetVerified(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}
func (r *recordingEvidenceStorage) GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error) {
	return nil, nil
}
func (r *recordingEvidenceStorage) ResolveVerifiedLegacy(_ context.Context, _ string, expected []byte) ([]byte, storage.StoredObject, error) {
	ref := storage.StoredObject{VersionID: "version-legacy"}
	copy(ref.SHA256[:], expected)
	return nil, ref, nil
}
func (r *recordingEvidenceStorage) Put(_ context.Context, key, _ string, body []byte) ([32]byte, error) {
	return r.PutEvidence(context.Background(), key, "", body)
}
func (r *recordingEvidenceStorage) PutEvidence(_ context.Context, key, _ string, body []byte) ([32]byte, error) {
	r.keys = append(r.keys, key)
	return sha256.Sum256(body), nil
}
func (r *recordingEvidenceStorage) PutVersioned(ctx context.Context, key, contentType string, body []byte) (storage.StoredObject, error) {
	sum, err := r.Put(ctx, key, contentType, body)
	return storage.StoredObject{SHA256: sum, VersionID: "version-" + key}, err
}
func (r *recordingEvidenceStorage) PutEvidenceVersioned(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) (storage.StoredObject, error) {
	r.retainUntil = append(r.retainUntil, retainUntil)
	sum, err := r.PutEvidence(ctx, key, contentType, body)
	return storage.StoredObject{SHA256: sum, VersionID: "version-" + key}, err
}
func (r *recordingEvidenceStorage) RetainEvidenceVerified(context.Context, string, []byte) error {
	return nil
}
func (r *recordingEvidenceStorage) RetainEvidenceVersion(context.Context, string, string, []byte, time.Time) error {
	return nil
}

func TestPrepareSignatureDoesNotWriteBeforeAuthoritativeChecks(t *testing.T) {
	store := &recordingEvidenceStorage{}
	engine := &Engine{Storage: store}
	sentAt := time.Date(2026, time.August, 31, 10, 11, 12, 345678000, time.UTC)
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf",
		SentAt: pgtype.Timestamptz{Time: sentAt, Valid: true},
	}
	rec := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
	prep, err := engine.prepareSignature(context.Background(), doc, rec, SignInput{TypedName: "Jane Signer", Font: "Caveat"})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.keys) != 0 || prep.imgKey != "" {
		t.Fatalf("pre-validation prepare retained evidence: keys=%v key=%q", store.keys, prep.imgKey)
	}
	if err := engine.storePreparedSignature(context.Background(), doc, rec.ID, prep); err != nil {
		t.Fatal(err)
	}
	if len(store.keys) != 1 {
		t.Fatalf("validated storage writes = %d, want 1", len(store.keys))
	}
	wantRetainUntil := storage.EvidenceRetentionDeadline(sentAt, article13.RetentionYearsV1)
	if len(store.retainUntil) != 1 || !store.retainUntil[0].Equal(wantRetainUntil) {
		t.Fatalf("signature retention deadline = %v, want sent-epoch %s", store.retainUntil, wantRetainUntil)
	}
	wantPrefix := "/documents/" + doc.ID.String() + "/signatures/" + rec.ID.String() + "-"
	if !strings.Contains(store.keys[0], wantPrefix) ||
		!strings.HasSuffix(store.keys[0], ".html") {
		t.Fatalf("signature key is not document/recipient content-addressed: %q", store.keys[0])
	}
	firstKey := store.keys[0]
	if err := engine.storePreparedSignature(context.Background(), doc, rec.ID, prep); err != nil {
		t.Fatal(err)
	}
	if store.keys[1] != firstKey {
		t.Fatalf("replay changed immutable key: %q != %q", store.keys[1], firstKey)
	}
	if !store.retainUntil[1].Equal(wantRetainUntil) {
		t.Fatalf("signature replay deadline = %s, want stable %s", store.retainUntil[1], wantRetainUntil)
	}
}

func TestStorePreparedSignatureRequiresAuthoritativeSentEpoch(t *testing.T) {
	store := &recordingEvidenceStorage{}
	engine := &Engine{Storage: store}
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf"}
	prep := &preparedSignature{span: []byte("<span>Jane Signer</span>"), sum: sha256.Sum256([]byte("<span>Jane Signer</span>"))}
	if err := engine.storePreparedSignature(context.Background(), doc, uuid.New(), prep); err == nil {
		t.Fatal("signature storage accepted a document without authoritative sent_at")
	}
	if len(store.keys) != 0 {
		t.Fatalf("missing sent epoch wrote immutable signature evidence: %v", store.keys)
	}
}
