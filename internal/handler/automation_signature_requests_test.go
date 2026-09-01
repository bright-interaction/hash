// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

type fakeAutomationSignatureRequestProcessor struct {
	response automationSignatureRequestResponse
	err      error
	inputs   []automationSignatureRequestProcessInput
}

func (f *fakeAutomationSignatureRequestProcessor) processAutomationSignatureRequest(_ context.Context, input automationSignatureRequestProcessInput) (automationSignatureRequestResponse, error) {
	f.inputs = append(f.inputs, input)
	return f.response, f.err
}

type automationAPIKeyVerifier struct {
	id, userID, orgID uuid.UUID
	role, email       string
	hash              []byte
	docScope          uuid.UUID
	scopes            []string
}

func (v automationAPIKeyVerifier) LookupByPrefix(context.Context, string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	return v.id, v.userID, v.orgID, v.role, v.email, v.hash, v.docScope, v.scopes, nil
}

func (v automationAPIKeyVerifier) Claim(context.Context, uuid.UUID, uuid.UUID) error { return nil }

func validAutomationRequestBody(templateID uuid.UUID) string {
	return `{"template_id":"` + templateID.String() + `","name":"Partner agreement","variables":{"customer.name":"Ada"},"recipients":[{"email":"ada@example.test","name":"Ada"}],"lawful_basis":"contract"}`
}

func TestPrepareAutomationSignatureRequestCanonicalizesDefaultsAndSemanticEquivalents(t *testing.T) {
	templateID := uuid.New()
	first, firstHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: templateID.String(), Name: " Partner agreement ", LawfulBasis: " contract ",
		Variables: map[string]string{"customer.name": "Ada", "customer.id": "00042"},
		Recipients: []automationSignatureRecipientInput{{
			Email: " ada@example.test ", Name: " Ada Lovelace ",
		}},
		ExpiresAt: "2030-01-02T04:04:05+01:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, secondHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: templateID.String(), Name: "Partner agreement", LawfulBasis: "contract",
		Variables: map[string]string{"customer.id": "00042", "customer.name": "Ada"},
		Recipients: []automationSignatureRecipientInput{{
			Role: "signer", Email: "ada@example.test", Name: "Ada Lovelace", Locale: "en-GB",
		}},
		ExpiresAt: "2030-01-02T03:04:05Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("semantic equivalents produced different hashes: %x != %x", firstHash, secondHash)
	}
	if first.Name != second.Name || first.ExpiresAt != "2030-01-02T03:04:05Z" ||
		first.Recipients[0].Role != "signer" || first.Recipients[0].Locale != "en" {
		t.Fatalf("request was not normalized: %#v", first)
	}
	second.Variables["customer.id"] = "42"
	_, changedHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: second.TemplateID.String(), Name: second.Name, LawfulBasis: second.LawfulBasis,
		Variables: second.Variables,
		Recipients: []automationSignatureRecipientInput{{
			Role: "signer", Email: "ada@example.test", Name: "Ada Lovelace", Locale: "en",
		}},
		ExpiresAt: second.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changedHash == firstHash {
		t.Fatal("different contractual variable value reused the same request hash")
	}
}

func TestPrepareAutomationSignatureRequestCanonicalizesCRMRegionalLocale(t *testing.T) {
	prepared, _, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: uuid.NewString(), Name: "Partner agreement", LawfulBasis: "contract",
		Recipients: []automationSignatureRecipientInput{{
			Role: "signer", Email: "ada@example.test", Name: "Ada Lovelace", Locale: "sv-SE",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.Recipients[0].Locale; got != "sv" {
		t.Fatalf("regional CRM locale = %q, want Hash catalog locale sv", got)
	}
}

func TestPrepareAutomationSignatureRequestRejectsUnsafeOrUnsupportedInput(t *testing.T) {
	base := automationSignatureRequestInput{
		TemplateID: uuid.NewString(), Name: "Agreement", LawfulBasis: "contract",
		Variables:  map[string]string{"customer.name": "Ada"},
		Recipients: []automationSignatureRecipientInput{{Email: "ada@example.test", Name: "Ada"}},
	}
	tests := []struct {
		name   string
		mutate func(*automationSignatureRequestInput)
	}{
		{name: "missing template", mutate: func(in *automationSignatureRequestInput) { in.TemplateID = "" }},
		{name: "control in name", mutate: func(in *automationSignatureRequestInput) { in.Name = "Agreement\nInjected" }},
		{name: "unsupported lawful basis", mutate: func(in *automationSignatureRequestInput) { in.LawfulBasis = "consent" }},
		{name: "invalid variable name", mutate: func(in *automationSignatureRequestInput) { in.Variables = map[string]string{"bad key": "Ada"} }},
		{name: "no recipients", mutate: func(in *automationSignatureRequestInput) { in.Recipients = nil }},
		{name: "display-name email", mutate: func(in *automationSignatureRequestInput) { in.Recipients[0].Email = "Ada <ada@example.test>" }},
		{name: "duplicate recipient", mutate: func(in *automationSignatureRequestInput) { in.Recipients = append(in.Recipients, in.Recipients[0]) }},
		{name: "informational role", mutate: func(in *automationSignatureRequestInput) { in.Recipients[0].Role = "cc" }},
		{name: "unknown locale", mutate: func(in *automationSignatureRequestInput) { in.Recipients[0].Locale = "xx" }},
		{name: "bad expiry", mutate: func(in *automationSignatureRequestInput) { in.ExpiresAt = "tomorrow" }},
		{name: "comma expiry", mutate: func(in *automationSignatureRequestInput) { in.ExpiresAt = "2030-01-02T03:04:05,1Z" }},
		{name: "ten digit expiry", mutate: func(in *automationSignatureRequestInput) { in.ExpiresAt = "2030-01-02T03:04:05.1234567890Z" }},
		{name: "24 hour offset expiry", mutate: func(in *automationSignatureRequestInput) { in.ExpiresAt = "2030-01-02T03:04:05+24:00" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.Variables = map[string]string{"customer.name": "Ada"}
			input.Recipients = append([]automationSignatureRecipientInput(nil), base.Recipients...)
			test.mutate(&input)
			if _, _, err := prepareAutomationSignatureRequest(input); err == nil {
				t.Fatal("invalid automation request was accepted")
			}
		})
	}
}

func TestPrepareAutomationSignatureRequestAcceptsStrictRFC3339Boundaries(t *testing.T) {
	t.Parallel()
	for _, expiry := range []string{
		"2030-01-02T03:04:05Z",
		"2030-01-02T03:04:05.123456789+23:59",
	} {
		_, _, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
			TemplateID: uuid.NewString(), Name: "Agreement", LawfulBasis: "contract", ExpiresAt: expiry,
			Recipients: []automationSignatureRecipientInput{{Email: "ada@example.test", Name: "Ada"}},
		})
		if err != nil {
			t.Errorf("valid strict RFC3339 expiry %q rejected: %v", expiry, err)
		}
	}
}

func TestAutomationIdempotencyKeyIsStrictAndDomainSeparated(t *testing.T) {
	valid, err := automationIdempotencyKey([]string{"crm-delivery-42"})
	if err != nil || valid != "crm-delivery-42" {
		t.Fatalf("valid key = %q/%v", valid, err)
	}
	for _, values := range [][]string{nil, {""}, {" one"}, {"one\n"}, {"one", "two"}, {strings.Repeat("x", automationMaxKeyBytes+1)}} {
		if _, err := automationIdempotencyKey(values); err == nil {
			t.Fatalf("invalid key values %#v were accepted", values)
		}
	}
	if got := automationIdempotencyKeyHash(valid); got == sha256.Sum256([]byte(valid)) {
		t.Fatal("stored key correlation omitted its domain separation")
	}
}

func TestAutomationJSONContentTypeIsStrict(t *testing.T) {
	t.Parallel()
	for _, values := range [][]string{{"application/json"}, {"application/json; charset=utf-8"}, {"Application/JSON; charset=UTF-8"}} {
		if err := requireAutomationJSONContentType(values); err != nil {
			t.Fatalf("valid content type %#v rejected: %v", values, err)
		}
	}
	for _, values := range [][]string{nil, {""}, {"text/plain"}, {"application/json; charset=iso-8859-1"}, {"application/json; profile=v1"}, {"application/json", "text/plain"}} {
		if err := requireAutomationJSONContentType(values); err == nil {
			t.Fatalf("invalid content type %#v accepted", values)
		}
	}
}

func TestDecodeAutomationSignatureRequestRejectsNullVariableValue(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "string", body: `{"variables":{"amount":""}}`},
		{name: "null", body: `{"variables":{"amount":null}}`, wantErr: true},
		{name: "null map", body: `{"variables":null}`, wantErr: true},
		{name: "invalid UTF-8", body: `{"variables":{"amount":"` + string([]byte{0xff}) + `"}}`, wantErr: true},
		{name: "paired surrogate", body: `{"variables":{"amount":"\uD83D\uDCA1"}}`},
		{name: "escaped backslash", body: `{"variables":{"amount":"\\uD800"}}`},
		{name: "lone high surrogate", body: `{"variables":{"amount":"\uD800"}}`, wantErr: true},
		{name: "lone low surrogate", body: `{"variables":{"amount":"\uDFFF"}}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, "/api/automation/v1/signature-requests", strings.NewReader(test.body))
			var input automationSignatureRequestInput
			err := decodeAutomationSignatureRequestJSON(httptest.NewRecorder(), request, &input)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestAutomationRateLimitIsScopedByAuthenticatedOrganization(t *testing.T) {
	t.Parallel()
	limited := automationOrgRateLimit(1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	requestForOrg := func(orgID uuid.UUID) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
		ctx = context.WithValue(ctx, auth.OrgIDKey, orgID)
		return req.WithContext(ctx)
	}
	firstOrg := uuid.New()
	for index, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		res := httptest.NewRecorder()
		limited.ServeHTTP(res, requestForOrg(firstOrg))
		if res.Code != want {
			t.Fatalf("first org request %d status=%d, want %d", index+1, res.Code, want)
		}
	}
	res := httptest.NewRecorder()
	limited.ServeHTTP(res, requestForOrg(uuid.New()))
	if res.Code != http.StatusNoContent {
		t.Fatalf("independent org status=%d, want %d", res.Code, http.StatusNoContent)
	}
}

func TestAutomationSignatureRequestRouteRequiresMachineAuthorization(t *testing.T) {
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	requestID, documentID := uuid.New(), uuid.New()
	templateID := uuid.New()
	tests := []struct {
		name          string
		role          string
		scopes        []string
		docScope      uuid.UUID
		includeKey    bool
		wantStatus    int
		wantProcessed bool
	}{
		{name: "missing API key", role: "sender", scopes: []string{"write:authoring", "write:workflow"}, wantStatus: http.StatusUnauthorized},
		{name: "viewer role", role: "viewer", scopes: []string{"write:authoring", "write:workflow"}, includeKey: true, wantStatus: http.StatusForbidden},
		{name: "missing workflow scope", role: "sender", scopes: []string{"write:authoring"}, includeKey: true, wantStatus: http.StatusForbidden},
		{name: "missing authoring scope", role: "sender", scopes: []string{"write:workflow"}, includeKey: true, wantStatus: http.StatusForbidden},
		{name: "document token", role: "sender", scopes: []string{"write:authoring", "write:workflow"}, docScope: uuid.New(), includeKey: true, wantStatus: http.StatusForbidden},
		{name: "sender with both scopes", role: "sender", scopes: []string{"write:authoring", "write:workflow"}, includeKey: true, wantStatus: http.StatusCreated, wantProcessed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			processor := &fakeAutomationSignatureRequestProcessor{response: automationSignatureRequestResponse{
				AutomationRequestID: requestID, DocumentID: documentID, Status: "sent",
			}}
			server := &Server{
				APIKeys: automationAPIKeyVerifier{
					id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), role: test.role,
					email: "sender@example.test", hash: key.Hash, docScope: test.docScope, scopes: test.scopes,
				},
				automationSignatureRequestProcessorOverride: processor,
			}
			req := httptest.NewRequest(http.MethodPost, "/api/automation/v1/signature-requests", strings.NewReader(validAutomationRequestBody(templateID)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(automationIdempotencyHeader, "crm-delivery-42")
			if test.includeKey {
				req.Header.Set("Authorization", "Bearer "+key.Plaintext)
			}
			res := httptest.NewRecorder()
			server.Routes().ServeHTTP(res, req)
			if res.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", res.Code, test.wantStatus, res.Body.String())
			}
			if got := len(processor.inputs); (got == 1) != test.wantProcessed {
				t.Fatalf("processor calls = %d, wantProcessed=%v", got, test.wantProcessed)
			}
			if test.wantProcessed {
				if strings.Contains(res.Body.String(), "/sign/") || strings.Contains(res.Body.String(), "links") {
					t.Fatalf("machine response exposed a signer bearer link: %s", res.Body.String())
				}
				var response automationSignatureRequestResponse
				if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.AutomationRequestID != requestID || response.DocumentID != documentID || response.Replayed {
					t.Fatalf("response = %#v", response)
				}
			}
		})
	}
}

func TestAutomationSignatureRequestHandlerMapsReplayAndCollision(t *testing.T) {
	templateID := uuid.New()
	requestID, documentID := uuid.New(), uuid.New()
	for _, test := range []struct {
		name       string
		processor  *fakeAutomationSignatureRequestProcessor
		wantStatus int
	}{
		{
			name: "replay",
			processor: &fakeAutomationSignatureRequestProcessor{response: automationSignatureRequestResponse{
				AutomationRequestID: requestID, DocumentID: documentID, Status: "completed", Replayed: true,
			}},
			wantStatus: http.StatusOK,
		},
		{
			name: "key collision", processor: &fakeAutomationSignatureRequestProcessor{err: errAutomationIdempotencyConflict},
			wantStatus: http.StatusConflict,
		},
		{
			name: "revised ceremony replay", processor: &fakeAutomationSignatureRequestProcessor{err: errAutomationCeremonySuperseded},
			wantStatus: http.StatusConflict,
		},
		{
			name: "purged draft tombstone", processor: &fakeAutomationSignatureRequestProcessor{err: errAutomationRequestGone},
			wantStatus: http.StatusGone,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{automationSignatureRequestProcessorOverride: test.processor}
			req := httptest.NewRequest(http.MethodPost, "/api/automation/v1/signature-requests", strings.NewReader(validAutomationRequestBody(templateID)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(automationIdempotencyHeader, "crm-delivery-42")
			ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
			ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
			ctx = context.WithValue(ctx, auth.RoleKey, "sender")
			ctx = context.WithValue(ctx, auth.EmailKey, "sender@example.test")
			res := httptest.NewRecorder()
			server.handleAutomationSignatureRequest(res, req.WithContext(ctx))
			if res.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", res.Code, test.wantStatus, res.Body.String())
			}
		})
	}
}

func TestAutomationSignatureRequestHandlerRejectsMissingContentType(t *testing.T) {
	processor := &fakeAutomationSignatureRequestProcessor{}
	server := &Server{automationSignatureRequestProcessorOverride: processor}
	req := httptest.NewRequest(http.MethodPost, "/api/automation/v1/signature-requests", strings.NewReader(validAutomationRequestBody(uuid.New())))
	req.Header.Set(automationIdempotencyHeader, "crm-delivery-42")
	ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "sender")
	ctx = context.WithValue(ctx, auth.EmailKey, "sender@example.test")
	res := httptest.NewRecorder()
	server.handleAutomationSignatureRequest(res, req.WithContext(ctx))
	if res.Code != http.StatusUnsupportedMediaType || len(processor.inputs) != 0 {
		t.Fatalf("missing content type status=%d processor calls=%d body=%s", res.Code, len(processor.inputs), res.Body.String())
	}
}

func TestRejectSupersededAutomationCeremony(t *testing.T) {
	t.Parallel()
	ceremonyEpoch := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	tests := []struct {
		name         string
		requestState string
		document     *generated.Document
		wantConflict bool
	}{
		{name: "initial ready draft", requestState: "ready", document: &generated.Document{Status: "draft"}},
		{name: "sent state reopened draft", requestState: "sent", document: &generated.Document{Status: "draft"}, wantConflict: true},
		{name: "crash before sent marker then revised", requestState: "ready", document: &generated.Document{Status: "draft", Article13NoticeEpochAt: ceremonyEpoch}, wantConflict: true},
		{name: "sealing resume", requestState: "ready", document: &generated.Document{Status: "sealing", Article13NoticeEpochAt: ceremonyEpoch}},
		{name: "already sent replay", requestState: "sent", document: &generated.Document{Status: "sent", Article13NoticeEpochAt: ceremonyEpoch}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := rejectSupersededAutomationCeremony(test.requestState, test.document)
			if errors.Is(err, errAutomationCeremonySuperseded) != test.wantConflict {
				t.Fatalf("got %v, want conflict=%v", err, test.wantConflict)
			}
		})
	}
}

func TestValidateFreshAutomationExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	for _, value := range []string{
		now.Add(-time.Minute).Format(time.RFC3339),
		now.Format(time.RFC3339),
		now.Add(automationMinimumExpiryLead).Format(time.RFC3339),
	} {
		if err := validateFreshAutomationExpiry(value, now); !errors.Is(err, errAutomationExpiryTooSoon) {
			t.Fatalf("expiry %q: got %v, want too-soon error", value, err)
		}
	}
	if err := validateFreshAutomationExpiry(now.Add(automationMinimumExpiryLead+time.Second).Format(time.RFC3339), now); err != nil {
		t.Fatalf("future expiry rejected: %v", err)
	}
	if err := validateFreshAutomationExpiry("", now); err != nil {
		t.Fatalf("optional expiry rejected: %v", err)
	}
}

func TestDecodeAutomationSignatureRequestRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{} {}`))
	var target automationSignatureRequestInput
	if err := decodeAutomationSignatureRequestJSON(httptest.NewRecorder(), req, &target); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestDecodeAutomationSignatureRequestRejectsDuplicateFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{
		"template_id":"first",
		"template_id":"second",
		"name":"Agreement",
		"variables":{},
		"recipients":[],
		"lawful_basis":"contract"
	}`))
	var target automationSignatureRequestInput
	if err := decodeAutomationSignatureRequestJSON(httptest.NewRecorder(), req, &target); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("got %v, want duplicate-field rejection", err)
	}
}

func TestDecodeAutomationSignatureRequestRejectsCaseVariantAliases(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"TEMPLATE_ID":"first","name":"Agreement","variables":{},"recipients":[],"lawful_basis":"contract"}`,
		`{"template_id":"first","TEMPLATE_ID":"second","name":"Agreement","variables":{},"recipients":[],"lawful_basis":"contract"}`,
		`{"template_id":"first","name":"Agreement","variables":{},"recipients":[{"EMAIL":"ada@example.com"}],"lawful_basis":"contract"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		var target automationSignatureRequestInput
		if err := decodeAutomationSignatureRequestJSON(httptest.NewRecorder(), req, &target); err == nil {
			t.Fatalf("case-variant JSON field was accepted: %s", body)
		}
	}
}

func TestAutomationSignatureRequestProcessorErrorsDoNotEchoInternalDetails(t *testing.T) {
	server := &Server{automationSignatureRequestProcessorOverride: &fakeAutomationSignatureRequestProcessor{err: errors.New("dial tcp database.internal:5432")}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validAutomationRequestBody(uuid.New())))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(automationIdempotencyHeader, "crm-delivery-42")
	ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "sender")
	ctx = context.WithValue(ctx, auth.EmailKey, "sender@example.test")
	res := httptest.NewRecorder()
	server.handleAutomationSignatureRequest(res, req.WithContext(ctx))
	if res.Code != http.StatusInternalServerError || strings.Contains(res.Body.String(), "database.internal") {
		t.Fatalf("internal error leaked: status=%d body=%s", res.Code, res.Body.String())
	}
}
