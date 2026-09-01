// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

func sentAtValue(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func boundArticle13TestDocument(id, orgID uuid.UUID, name string, sentAt time.Time) *generated.Document {
	return &generated.Document{
		ID: id, OrgID: orgID, Name: name, LawfulBasis: "contract",
		SentAt: sentAtValue(sentAt), Article13NoticeEpochAt: sentAtValue(sentAt),
		Article13NoticeSchema: article13.CurrentSchema,
	}
}

func TestSignerPrivacyNoticeUsesEachDocumentControllerNotInstanceOperator(t *testing.T) {
	server := &Server{
		OrgName: "Configured Operator AB", OperatorName: "Configured Operator AB",
		PrivacyContact: "privacy@operator.example", SupervisoryAuthority: "Applicable DPA",
		PrivacyPolicyURL: "https://operator.example/privacy",
	}
	for _, controllerName := range []string{"Customer Alpha AB", "Customer Beta Oy"} {
		t.Run(controllerName, func(t *testing.T) {
			orgID := uuid.New()
			documentID := uuid.New()
			rc := &sign.RecipientContext{
				Recipient:     &generated.GetRecipientByTokenHashRow{ID: uuid.New(), Locale: "en"},
				Document:      boundArticle13TestDocument(documentID, orgID, "Customer agreement", time.Now()),
				ControllerOrg: &generated.Org{ID: orgID, Name: controllerName},
				LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
					DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
					ConfirmedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
					ControllerName: controllerName, ControllerContact: "sender@customer.example",
				},
			}
			req := httptest.NewRequest(http.MethodGet, "/sign/signer-token", nil)
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add("token", "signer-token")
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

			notice, err := server.signerPrivacyNotice(req, rc)
			if err != nil {
				t.Fatal(err)
			}
			if notice.Controller != controllerName {
				t.Fatalf("controller = %q, want %q", notice.Controller, controllerName)
			}
			if notice.ControllerContact != "sender@customer.example" {
				t.Fatalf("controller contact = %q", notice.ControllerContact)
			}
			if notice.Controller == server.OrgName {
				t.Fatalf("controller incorrectly fell back to instance operator %q", server.OrgName)
			}
			if notice.Processor != server.OperatorName || notice.ProcessorEmail != server.PrivacyContact || notice.JurisdictionDP != server.SupervisoryAuthority {
				t.Fatalf("notice used hard-coded instance identity: %#v", notice)
			}
			if notice.RetentionYears != 7 {
				t.Fatalf("retention years = %d, want fixed evidentiary policy 7", notice.RetentionYears)
			}
			if !strings.Contains(notice.PurposeSummary, rc.Document.Name) || strings.Contains(strings.ToLower(notice.PurposeSummary), "legally-binding") {
				t.Fatalf("purpose summary is not neutral and document-specific: %q", notice.PurposeSummary)
			}
			wantBasis, err := article13.LegalBasisDisclosureV1(rc.Document.LawfulBasis)
			if err != nil {
				t.Fatal(err)
			}
			if notice.PurposeSummary != article13.PurposeSummaryV1(rc.Document.Name) ||
				notice.LegalBasis != wantBasis || notice.Copy != article13.RenderedCopyV1(rc.Document.Name) {
				t.Fatalf("handler disclosure drifted from shared V1 material: %#v", notice)
			}
			if notice.PolicyURL != server.PrivacyPolicyURL || len(notice.NoticeDigest) != sha256.Size*2 {
				t.Fatalf("policy/digest missing from notice: %#v", notice)
			}
			if notice.DSREndpoint != "/sign/signer-token/dsr" {
				t.Fatalf("DSR endpoint = %q", notice.DSREndpoint)
			}
		})
	}
}

func TestSignerPrivacyNoticeDigestIsStableAndChangesWithResendMaterial(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	sentAt := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	rc := &sign.RecipientContext{
		Recipient: &generated.GetRecipientByTokenHashRow{ID: recipientID, Locale: "en"},
		Document: &generated.Document{
			ID: documentID, OrgID: orgID, Name: "Customer agreement", LawfulBasis: "contract",
			SentAt: sentAtValue(sentAt), Article13NoticeEpochAt: sentAtValue(sentAt), Article13NoticeSchema: article13.CurrentSchema,
		},
		ControllerOrg: &generated.Org{ID: orgID, Name: "Current mutable name"},
		LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
			DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
			ConfirmedAt:    pgtype.Timestamptz{Time: sentAt, Valid: true},
			ControllerName: "Frozen Customer AB", ControllerContact: "sender@customer.example",
		},
	}
	server := &Server{
		OperatorName: "Operator AB", PrivacyContact: "privacy@operator.example",
		SupervisoryAuthority: "Applicable DPA", PrivacyPolicyURL: "https://operator.example/privacy",
	}
	req := httptest.NewRequest(http.MethodGet, "/sign/token", nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("token", "token")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

	first, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	if first.NoticeDigest == "" || first.NoticeDigest != second.NoticeDigest {
		t.Fatalf("same notice produced unstable digests %q / %q", first.NoticeDigest, second.NoticeDigest)
	}
	if first.Controller != "Frozen Customer AB" {
		t.Fatalf("notice used mutable controller name: %q", first.Controller)
	}

	rc.Document.SentAt.Time = sentAt.Add(time.Hour)
	resent, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	if resent.NoticeDigest == first.NoticeDigest {
		t.Fatal("resend timestamp did not invalidate the prior Article 13 acknowledgement")
	}
	rc.LawfulBasisConfirmation.ControllerContact = "privacy@customer.example"
	changedContact, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	if changedContact.NoticeDigest == resent.NoticeDigest {
		t.Fatal("changed controller contact did not invalidate the prior Article 13 acknowledgement")
	}
}

func TestSignerResponseRequiresExactCurrentNoticeDigest(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	sentAt := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	rc := &sign.RecipientContext{
		Recipient: &generated.GetRecipientByTokenHashRow{ID: recipientID, Locale: "en"},
		Document: &generated.Document{
			ID: documentID, OrgID: orgID, Name: "Customer agreement", LawfulBasis: "contract",
			SentAt: sentAtValue(sentAt), Article13NoticeEpochAt: sentAtValue(sentAt), Article13NoticeSchema: article13.CurrentSchema,
		},
		ControllerOrg: &generated.Org{ID: orgID, Name: "Customer AB"},
		LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
			DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
			ConfirmedAt:    pgtype.Timestamptz{Time: sentAt, Valid: true},
			ControllerName: "Customer AB", ControllerContact: "sender@customer.example",
		},
	}
	server := &Server{
		OperatorName: "Operator AB", PrivacyContact: "privacy@operator.example",
		SupervisoryAuthority: "Applicable DPA", PrivacyPolicyURL: "https://operator.example/privacy",
	}
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/sign/token/sign", strings.NewReader(`{}`))
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("token", "token")
		return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
	}
	current, err := server.signerPrivacyNotice(request(), rc)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		headers []string
		wantOK  bool
	}{
		{name: "missing"},
		{name: "stale", headers: []string{strings.Repeat("00", sha256.Size)}},
		{name: "malformed", headers: []string{"not-a-digest"}},
		{name: "duplicate", headers: []string{current.NoticeDigest, current.NoticeDigest}},
		{name: "current", headers: []string{current.NoticeDigest}, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request()
			for _, value := range tt.headers {
				req.Header.Add(signerNoticeDigestHeader, value)
			}
			recorder := httptest.NewRecorder()
			got, ok := server.requireSignerNoticeAcknowledgement(recorder, req, rc)
			if ok != tt.wantOK {
				t.Fatalf("acknowledgement = %#v/%v, want ok=%v (status %d)", got, ok, tt.wantOK, recorder.Code)
			}
			if tt.wantOK {
				if got.Digest != current.NoticeDigest {
					t.Fatalf("canonical digest = %q, want %q", got.Digest, current.NoticeDigest)
				}
				return
			}
			if recorder.Code != http.StatusPreconditionRequired {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusPreconditionRequired)
			}
		})
	}

	// A resend changes sent_at, making a formerly exact digest stale.
	rc.Document.SentAt.Time = sentAt.Add(time.Minute)
	req := request()
	req.Header.Set(signerNoticeDigestHeader, current.NoticeDigest)
	recorder := httptest.NewRecorder()
	if _, ok := server.requireSignerNoticeAcknowledgement(recorder, req, rc); ok || recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("pre-resend digest survived resend: ok=%v status=%d", ok, recorder.Code)
	}
}

func TestSignerNoticeEvidenceFreezesRuntimeDisclosureMaterial(t *testing.T) {
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	sentAt := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	rc := &sign.RecipientContext{
		Recipient: &generated.GetRecipientByTokenHashRow{ID: recipientID, Locale: "en"},
		Document: &generated.Document{
			ID: documentID, OrgID: orgID, Name: "Evidence agreement", LawfulBasis: "contract",
			SentAt: sentAtValue(sentAt), Article13NoticeEpochAt: sentAtValue(sentAt), Article13NoticeSchema: article13.CurrentSchema,
		},
		ControllerOrg: &generated.Org{ID: orgID, Name: "Customer AB"},
		LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
			DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
			ConfirmedAt:    pgtype.Timestamptz{Time: sentAt, Valid: true},
			ControllerName: "Customer AB", ControllerContact: "legal@customer.example",
		},
	}
	server := &Server{
		OperatorName: "Original Operator AB", PrivacyContact: "original-privacy@operator.example",
		SupervisoryAuthority: "Original DPA", PrivacyPolicyURL: "https://operator.example/privacy-v1",
	}
	req := httptest.NewRequest(http.MethodGet, "/sign/token", nil)
	notice, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Digest != notice.NoticeDigest || frozen.Snapshot.Processor != "Original Operator AB" || frozen.Snapshot.PolicyURL != server.PrivacyPolicyURL {
		t.Fatalf("frozen notice evidence = %#v", frozen)
	}

	server.OperatorName = "Replacement Operator AB"
	server.PrivacyContact = "new-privacy@operator.example"
	server.SupervisoryAuthority = "Replacement DPA"
	server.PrivacyPolicyURL = "https://operator.example/privacy-v2"
	changed, err := server.signerPrivacyNotice(req, rc)
	if err != nil {
		t.Fatal(err)
	}
	if changed.NoticeDigest == frozen.Digest {
		t.Fatal("runtime disclosure change did not create a new notice commitment")
	}
	if frozen.Snapshot.Processor != "Original Operator AB" || frozen.Snapshot.ProcessorContact != "original-privacy@operator.example" ||
		frozen.Snapshot.SupervisoryAuthority != "Original DPA" || frozen.Snapshot.PolicyURL != "https://operator.example/privacy-v1" {
		t.Fatalf("captured evidence changed with runtime configuration: %#v", frozen)
	}
}

func TestSignerPrivacyNoticeFailsClosedWithoutConfiguredInstanceIdentity(t *testing.T) {
	orgID := uuid.New()
	documentID := uuid.New()
	rc := &sign.RecipientContext{
		Recipient:     &generated.GetRecipientByTokenHashRow{ID: uuid.New(), Locale: "en"},
		Document:      boundArticle13TestDocument(documentID, orgID, "Agreement", time.Now()),
		ControllerOrg: &generated.Org{ID: orgID, Name: "Customer AB"},
		LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
			DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
			ConfirmedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
			ControllerName: "Customer AB", ControllerContact: "sender@customer.example",
		},
	}
	base := Server{OperatorName: "Operator AB", PrivacyContact: "privacy@operator.example", SupervisoryAuthority: "Applicable DPA", PrivacyPolicyURL: "https://operator.example/privacy"}
	for _, mutate := range []func(*Server){
		func(s *Server) { s.OperatorName = "" },
		func(s *Server) { s.PrivacyContact = "" },
		func(s *Server) { s.SupervisoryAuthority = "" },
		func(s *Server) { s.PrivacyPolicyURL = "" },
	} {
		server := base
		mutate(&server)
		if _, err := server.signerPrivacyNotice(httptest.NewRequest(http.MethodGet, "/", nil), rc); err == nil {
			t.Fatal("incomplete instance disclosure identity was accepted")
		}
	}
}

func TestSignerPrivacyNoticeFailsClosedWithoutMatchingDocumentController(t *testing.T) {
	orgID := uuid.New()
	documentID := uuid.New()
	valid := func() *sign.RecipientContext {
		return &sign.RecipientContext{
			Recipient:     &generated.GetRecipientByTokenHashRow{ID: uuid.New(), Locale: "en"},
			Document:      boundArticle13TestDocument(documentID, orgID, "Customer agreement", time.Now()),
			ControllerOrg: &generated.Org{ID: orgID, Name: "Customer Alpha AB"},
			LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{
				DocumentID: documentID, OrgID: orgID, LawfulBasis: "contract",
				ConfirmedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
				ControllerName: "Customer Alpha AB", ControllerContact: "sender@customer.example",
			},
		}
	}
	tests := []struct {
		name      string
		configure func(*sign.RecipientContext)
	}{
		{"missing controller", func(rc *sign.RecipientContext) { rc.ControllerOrg = nil }},
		{"wrong controller organization", func(rc *sign.RecipientContext) { rc.ControllerOrg.ID = uuid.New() }},
		{"missing recipient", func(rc *sign.RecipientContext) { rc.Recipient = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rc := valid()
			test.configure(rc)
			if _, err := (&Server{}).signerPrivacyNotice(httptest.NewRequest(http.MethodGet, "/", nil), rc); !errors.Is(err, sign.ErrSignerControllerUnavailable) {
				t.Fatalf("signerPrivacyNotice error = %v, want ErrSignerControllerUnavailable", err)
			}
		})
	}
	rc := valid()
	rc.LawfulBasisConfirmation = nil
	if _, err := (&Server{}).signerPrivacyNotice(httptest.NewRequest(http.MethodGet, "/", nil), rc); !errors.Is(err, sign.ErrSignerLawfulBasisUnavailable) {
		t.Fatalf("unconfirmed lawful basis error = %v, want ErrSignerLawfulBasisUnavailable", err)
	}
	rc = valid()
	rc.LawfulBasisConfirmation.ControllerContact = " "
	if _, err := (&Server{}).signerPrivacyNotice(httptest.NewRequest(http.MethodGet, "/", nil), rc); !errors.Is(err, sign.ErrSignerLawfulBasisUnavailable) {
		t.Fatalf("blank frozen controller contact error = %v, want ErrSignerLawfulBasisUnavailable", err)
	}
}

func TestSignerLawfulBasisDisclosureMapsOnlySupportedDocumentValues(t *testing.T) {
	disclosure, err := article13.LegalBasisDisclosureV1("contract")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(disclosure, "Controller confirmed:") || !strings.Contains(disclosure, "6(1)(b)") {
		t.Errorf("contract disclosure = %q", disclosure)
	}
	for _, value := range []string{"", "unknown", "contract,legal_obligation", "consent", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"} {
		if disclosure, err := article13.LegalBasisDisclosureV1(value); err == nil || disclosure != "" {
			t.Errorf("unsupported %q produced %q, %v", value, disclosure, err)
		}
	}
}
