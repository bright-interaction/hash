package sign

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// TestEnvelopeBodyConcatenatesChildren exercises renderEnvelopeBody
// without standing up a sql backend. EnvelopeChildren is the only
// callback we need; renderSignedHTML walks the block tree directly
// from BlocksJson.
func TestRenderEnvelopeBody_ConcatenatesChildrenWithPageBreaks(t *testing.T) {
	envelope := &generated.Document{
		ID:         uuid.New(),
		Name:       "Acme Acquisition Package",
		IsEnvelope: true,
		BlocksJson: []byte(`{"version":1,"blocks":[]}`),
		VariablesJson: []byte(`{}`),
	}
	child1 := &generated.Document{
		ID:            uuid.New(),
		Name:          "Master Services Agreement",
		BlocksJson:    []byte(`{"version":1,"blocks":[{"id":"h","type":"heading","attrs":{"level":1},"text":"MSA"},{"id":"p","type":"paragraph","text":"This is the MSA body."}]}`),
		VariablesJson: []byte(`{}`),
	}
	child2 := &generated.Document{
		ID:            uuid.New(),
		Name:          "Data Processing Addendum",
		BlocksJson:    []byte(`{"version":1,"blocks":[{"id":"d","type":"paragraph","text":"DPA body content."}]}`),
		VariablesJson: []byte(`{}`),
	}

	engine := &Engine{
		Queries: nil, // renderEnvelopeBody only reaches the queries via renderSignedHTML, which we keep block-tree-only here
		EnvelopeChildren: func(_ context.Context, _ *generated.Document) ([]*generated.Document, error) {
			return []*generated.Document{child1, child2}, nil
		},
	}

	body, err := engine.renderEnvelopeBody(context.Background(), envelope, "en")
	if err != nil {
		t.Fatalf("renderEnvelopeBody: %v", err)
	}
	for _, want := range []string{
		"Acme Acquisition Package",
		"This envelope bundles 2 documents",
		"Master Services Agreement",
		"This is the MSA body.",
		"Data Processing Addendum",
		"DPA body content.",
		`page-break-before:always`,
		`hash-envelope-child`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestRenderEnvelopeBody_NoChildrenIsEmptyButSafe(t *testing.T) {
	envelope := &generated.Document{
		ID:            uuid.New(),
		Name:          "Empty envelope",
		IsEnvelope:    true,
		BlocksJson:    []byte(`{"version":1,"blocks":[]}`),
		VariablesJson: []byte(`{}`),
	}
	engine := &Engine{
		EnvelopeChildren: func(_ context.Context, _ *generated.Document) ([]*generated.Document, error) {
			return nil, nil
		},
	}
	body, err := engine.renderEnvelopeBody(context.Background(), envelope, "en")
	if err != nil {
		t.Fatalf("renderEnvelopeBody empty: %v", err)
	}
	if !strings.Contains(body, "Empty envelope") {
		t.Errorf("empty envelope should still emit the banner heading, got: %s", body)
	}
}
