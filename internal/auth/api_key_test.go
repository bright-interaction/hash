// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialMintsUseDisjointHighEntropyPrefixes(t *testing.T) {
	orgKey, err := MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	docKey, err := MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 1 + credentialPrefixEntropyLen*2
	if len(orgKey.Prefix) != wantLen || !strings.HasPrefix(orgKey.Prefix, apiKeyPrefixNamespace) {
		t.Fatalf("org prefix = %q, want %q + %d hex chars", orgKey.Prefix, apiKeyPrefixNamespace, credentialPrefixEntropyLen*2)
	}
	if len(docKey.Prefix) != wantLen || !strings.HasPrefix(docKey.Prefix, documentTokenNamespace) {
		t.Fatalf("document prefix = %q, want %q + %d hex chars", docKey.Prefix, documentTokenNamespace, credentialPrefixEntropyLen*2)
	}
	if orgKey.Prefix == docKey.Prefix {
		t.Fatal("org and document credential namespaces overlapped")
	}
	for _, key := range []*MintedKey{orgKey, docKey} {
		prefix, full, err := ParseAPIKey(key.Plaintext)
		if err != nil || prefix != key.Prefix || string(full) != key.Plaintext {
			t.Fatalf("parse minted key = %q/%q/%v", prefix, full, err)
		}
	}
}

func TestParseAPIKeyKeepsLegacyPrefixCompatibility(t *testing.T) {
	prefix, _, err := ParseAPIKey("mth_deadbeef_legacy-secret")
	if err != nil || prefix != "deadbeef" {
		t.Fatalf("legacy parse = %q/%v", prefix, err)
	}
	if namespace := credentialNamespace(prefix); namespace != "" {
		t.Fatalf("legacy prefix was mistaken for namespace %q", namespace)
	}
	for _, malformed := range []string{
		strings.Join([]string{"mth", "deadbeeG", "secret"}, "_"),
		strings.Join([]string{"mth", "a1234", "secret"}, "_"),
		strings.Join([]string{"mth", "x0123456789abcdef0123456789abcdef", "secret"}, "_"),
	} {
		if _, _, err := ParseAPIKey(malformed); err == nil {
			t.Fatalf("ParseAPIKey(%q) accepted malformed routing prefix", malformed)
		}
	}
}

type apiKeyVerifierStub struct {
	id, userID, orgID uuid.UUID
	role, email       string
	hash              []byte
	docScope          uuid.UUID
	scopes            []string
	claim             func(context.Context, uuid.UUID, uuid.UUID) error
}

func (s apiKeyVerifierStub) LookupByPrefix(context.Context, string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	return s.id, s.userID, s.orgID, s.role, s.email, s.hash, s.docScope, s.scopes, nil
}

func (s apiKeyVerifierStub) Claim(ctx context.Context, id, docScopeID uuid.UUID) error {
	if s.claim != nil {
		return s.claim(ctx, id, docScopeID)
	}
	return nil
}

func TestRequireAPIKeyMarksEmptyScopeSetAsTokenAndFailsWritesClosed(t *testing.T) {
	key, err := MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	verifier := apiKeyVerifierStub{
		id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), role: "sender",
		email: "agent@example.test", hash: key.Hash, scopes: []string{},
	}
	called := false
	h := RequireAPIKey(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		scopes, present := TokenScopesFromContext(r.Context())
		if !present || len(scopes) != 0 {
			t.Fatalf("token scope marker = %v/%v, want present empty set", present, scopes)
		}
		if HasWriteScope(r.Context()) {
			t.Fatal("empty API-token scope set inherited full write access")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+key.Plaintext)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called || rr.Code != http.StatusNoContent {
		t.Fatalf("middleware result called/status = %v/%d", called, rr.Code)
	}
}

func TestRequireAPIKeyAtomicallyClaimsCappedDocumentToken(t *testing.T) {
	key, err := MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}

	var remaining int32 = 1
	var handled int32
	verifier := apiKeyVerifierStub{
		id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), role: "sender",
		email: "agent@example.test", hash: key.Hash, docScope: uuid.New(),
		scopes: []string{"read"},
		claim: func(_ context.Context, _, _ uuid.UUID) error {
			if atomic.CompareAndSwapInt32(&remaining, 1, 0) {
				return nil
			}
			return errors.New("usage cap exhausted")
		},
	}
	h := RequireAPIKey(verifier)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&handled, 1)
		w.WriteHeader(http.StatusNoContent)
	}))

	const requests = 2
	statuses := make(chan int, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+key.Plaintext)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			statuses <- rr.Code
		}()
	}
	wg.Wait()
	close(statuses)

	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if got := atomic.LoadInt32(&handled); got != 1 {
		t.Fatalf("handler calls = %d, want exactly 1", got)
	}
	if counts[http.StatusNoContent] != 1 || counts[http.StatusUnauthorized] != 1 {
		t.Fatalf("statuses = %#v, want one 204 and one 401", counts)
	}
}
