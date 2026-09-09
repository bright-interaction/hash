// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestRenderForSignerFailsClosedOnBrandingLookupFailure(t *testing.T) {
	sentinel := errors.New("frozen branding lookup failed")
	calls := 0
	engine := &Engine{BrandingCSS: func(context.Context, *generated.Document) (string, error) {
		calls++
		return "", sentinel
	}}
	rc := &RecipientContext{
		Document: &generated.Document{
			ID:            uuid.New(),
			SourceKind:    "blocks",
			BlocksJson:    []byte(`{"version":1,"blocks":[]}`),
			VariablesJson: []byte(`{}`),
		},
		Recipient: &generated.GetRecipientByTokenHashRow{Locale: "en"},
	}

	html, err := engine.RenderForSigner(context.Background(), rc)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "resolve branding") {
		t.Fatalf("RenderForSigner error = %v, want wrapped branding failure", err)
	}
	if html != "" {
		t.Fatalf("RenderForSigner returned HTML after branding failure: %q", html)
	}
	if calls != 1 {
		t.Fatalf("branding resolver calls = %d, want 1", calls)
	}
}

func TestFinalizationResolvesBrandingBeforeRenderingOrStorage(t *testing.T) {
	raw, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	assertBrandingGateBefore(t, source,
		"func (e *Engine) completeAcknowledgedDocument(",
		"func acknowledgedFinalKey(",
		"e.Storage.PutEvidenceVersioned",
	)
	assertBrandingGateBefore(t, source,
		"func (e *Engine) finalize(",
		"func verifyCompletedEnvelopeChildren(",
		"e.PDF.HTMLToPDF",
	)
}

func assertBrandingGateBefore(t *testing.T, source, startMarker, endMarker, sideEffectMarker string) {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing function marker %q", startMarker)
	}
	endOffset := strings.Index(source[start:], endMarker)
	if endOffset < 0 {
		t.Fatalf("missing function end marker %q", endMarker)
	}
	body := source[start : start+endOffset]
	gate := strings.Index(body, "brandCSS, err := e.resolveBrandingCSS")
	sideEffect := strings.Index(body, sideEffectMarker)
	if gate < 0 || sideEffect < 0 || gate > sideEffect {
		t.Fatalf("branding error gate must precede %q in %q", sideEffectMarker, startMarker)
	}
	errorBranch := body[gate:]
	if len(errorBranch) > 320 {
		errorBranch = errorBranch[:320]
	}
	if !strings.Contains(errorBranch, "if err != nil") || !strings.Contains(errorBranch, "resolve branding") {
		t.Fatalf("branding lookup in %q does not fail closed: %s", startMarker, errorBranch)
	}
}
