// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

// TestEnvelopeBodyConcatenatesChildren exercises renderEnvelopeBody
// without standing up a sql backend. EnvelopeChildren is the only
// callback we need; renderSignedHTML walks the block tree directly
// from BlocksJson.
func TestRenderEnvelopeBody_ConcatenatesChildrenWithPageBreaks(t *testing.T) {
	envelope := &generated.Document{
		ID:            uuid.New(),
		Name:          "Acme Acquisition Package",
		IsEnvelope:    true,
		Status:        "sent",
		BlocksJson:    []byte(`{"version":1,"blocks":[]}`),
		VariablesJson: []byte(`{}`),
	}
	child1 := &generated.Document{
		ID: uuid.New(), Name: "Master Services Agreement", Status: "sent", SourceKind: "blocks",
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"h","type":"heading","attrs":{"level":1},"text":"MSA"},{"id":"p","type":"paragraph","text":"This is the MSA body."}]}`),
		VariablesJson:    []byte(`{}`),
	}
	child2 := &generated.Document{
		ID: uuid.New(), Name: "Data Processing Addendum", Status: "sent", SourceKind: "blocks",
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"d","type":"paragraph","text":"DPA body content."}]}`),
		VariablesJson:    []byte(`{}`),
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

func TestRenderEnvelopeBody_NoChildrenFailsClosed(t *testing.T) {
	envelope := &generated.Document{
		ID:            uuid.New(),
		Name:          "Empty envelope",
		IsEnvelope:    true,
		Status:        "sent",
		BlocksJson:    []byte(`{"version":1,"blocks":[]}`),
		VariablesJson: []byte(`{}`),
	}
	engine := &Engine{
		EnvelopeChildren: func(_ context.Context, _ *generated.Document) ([]*generated.Document, error) {
			return nil, nil
		},
	}
	if _, err := engine.renderEnvelopeBody(context.Background(), envelope, "en"); err == nil {
		t.Fatal("empty envelope must fail closed instead of rendering a signable shell")
	}
}

func TestRenderEnvelopeBody_ChildErrorFailsWholeBundle(t *testing.T) {
	envelope := &generated.Document{ID: uuid.New(), Name: "Bundle", IsEnvelope: true, Status: "sent"}
	engine := &Engine{
		EnvelopeChildren: func(_ context.Context, _ *generated.Document) ([]*generated.Document, error) {
			return []*generated.Document{
				{ID: uuid.New(), Name: "valid", Status: "sent", SourceKind: "blocks", ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true}, BlocksJson: []byte(`{"version":1,"blocks":[]}`)},
				nil,
			}, nil
		},
	}
	if _, err := engine.renderEnvelopeBody(context.Background(), envelope, "en"); err == nil {
		t.Fatal("nil child must fail the whole legal bundle instead of being skipped")
	}
}

func TestRenderForSigner_EnvelopeFailsClosedWithoutChildrenProvider(t *testing.T) {
	envelope := &generated.Document{
		ID: uuid.New(), Name: "Unwired", IsEnvelope: true,
		BlocksJson: []byte(`{"version":1,"blocks":[]}`),
	}
	rc := &RecipientContext{
		Document:  envelope,
		Recipient: &generated.GetRecipientByTokenHashRow{Locale: "en"},
	}
	if _, err := (&Engine{}).RenderForSigner(context.Background(), rc); err == nil {
		t.Fatal("unwired envelope signer view must not fall back to the empty shell")
	}
}

func TestRenderFinalBlocksBody_EnvelopeUsesChildContent(t *testing.T) {
	envelope := &generated.Document{
		ID:            uuid.New(),
		Name:          "Final acquisition envelope",
		SourceKind:    "blocks",
		IsEnvelope:    true,
		Status:        "finalizing",
		BlocksJson:    []byte(`{"version":1,"blocks":[{"id":"shell-only","type":"paragraph","text":"SHELL MUST NOT REPLACE CHILDREN"}]}`),
		VariablesJson: []byte(`{}`),
	}
	child := &generated.Document{
		ID: uuid.New(), Name: "Child agreement", Status: "finalizing", SourceKind: "blocks",
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"proof","type":"paragraph","text":"ENVELOPE CHILD CONTENT PROOF 7F3A"}]}`),
		VariablesJson:    []byte(`{}`),
	}
	engine := &Engine{
		EnvelopeChildren: func(context.Context, *generated.Document) ([]*generated.Document, error) {
			return []*generated.Document{child}, nil
		},
	}
	body, err := engine.renderFinalBlocksBody(context.Background(), envelope, "en")
	if err != nil {
		t.Fatalf("render final envelope body: %v", err)
	}
	if !strings.Contains(body, "ENVELOPE CHILD CONTENT PROOF 7F3A") {
		t.Fatalf("final envelope body omitted child content: %s", body)
	}
	if strings.Contains(body, "SHELL MUST NOT REPLACE CHILDREN") {
		t.Fatalf("final envelope body rendered the shell instead of children: %s", body)
	}
}

func TestRenderFinalBlocksBody_EnvelopeFailsClosedWithoutChildrenProvider(t *testing.T) {
	envelope := &generated.Document{
		ID:         uuid.New(),
		Name:       "Unwired envelope",
		SourceKind: "blocks",
		IsEnvelope: true,
		BlocksJson: []byte(`{"version":1,"blocks":[]}`),
	}
	if _, err := (&Engine{}).renderFinalBlocksBody(context.Background(), envelope, "en"); err == nil {
		t.Fatal("unwired envelope finalization should fail instead of emitting an empty PDF")
	}
}

func TestEnvelopeRolesAndFieldsComeFromAllChildTrees(t *testing.T) {
	envelope := &generated.Document{ID: uuid.New(), IsEnvelope: true, SourceKind: "blocks", Status: "sent"}
	childA := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks", Status: "sent",
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"signer-field","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`),
	}
	childB := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks", Status: "sent",
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"outer","type":"callout","attrs":{"tone":"info"},"content":[{"id":"approver-field","type":"signature_field","attrs":{"recipient_role":"approver"}}]}]}`),
	}
	engine := &Engine{EnvelopeChildren: func(context.Context, *generated.Document) ([]*generated.Document, error) {
		return []*generated.Document{childA, childB}, nil
	}}

	roles, err := engine.signerRolesForDocument(context.Background(), envelope)
	if err != nil {
		t.Fatalf("signerRolesForDocument: %v", err)
	}
	if got, want := strings.Join(roles, ","), "approver,signer"; got != want {
		t.Fatalf("roles = %q, want %q", got, want)
	}
	fieldID, err := engine.signatureFieldBlockID(context.Background(), envelope, "approver")
	if err != nil {
		t.Fatalf("signatureFieldBlockID approver: %v", err)
	}
	if want := childB.ID.String() + ":approver-field"; fieldID != want {
		t.Fatalf("field id = %q, want %q", fieldID, want)
	}
}

func TestSignerRolesForDocument_FinalizingEnvelopeRequiresExactFamilyCommitments(t *testing.T) {
	effectiveAt := pgtype.Timestamptz{
		Time:  time.Date(2026, 8, 31, 12, 0, 0, 123456000, time.UTC),
		Valid: true,
	}
	retainUntil := pgtype.Timestamptz{
		Time:  storage.EvidenceRetentionDeadline(effectiveAt.Time, article13.RetentionYearsV1),
		Valid: true,
	}
	parentID := uuid.New()
	baseParent := generated.Document{
		ID: parentID, IsEnvelope: true, SourceKind: "blocks", Status: "finalizing",
		CompletionEffectiveAtBound: true, CompletionEffectiveAt: effectiveAt,
		FinalizationRetainUntil: retainUntil,
	}
	baseChild := generated.Document{
		ID: uuid.New(), SourceKind: "blocks", Status: "finalizing",
		ParentEnvelopeID:           pgtype.UUID{Bytes: parentID, Valid: true},
		BlocksJson:                 []byte(`{"version":1,"blocks":[{"id":"signer-field","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`),
		CompletionEffectiveAtBound: true, CompletionEffectiveAt: effectiveAt,
		FinalizationRetainUntil: retainUntil,
	}

	tests := []struct {
		name    string
		mutate  func(*generated.Document, *generated.Document)
		wantErr bool
	}{
		{name: "exact family commitment"},
		{name: "sent child", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) { child.Status = "sent" }},
		{name: "in progress child", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) { child.Status = "in_progress" }},
		{name: "completed child", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) { child.Status = "completed" }},
		{name: "unbound parent", wantErr: true, mutate: func(parent, _ *generated.Document) { parent.CompletionEffectiveAtBound = false }},
		{name: "unbound child", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) { child.CompletionEffectiveAtBound = false }},
		{name: "missing parent completion", wantErr: true, mutate: func(parent, _ *generated.Document) { parent.CompletionEffectiveAt = pgtype.Timestamptz{} }},
		{name: "missing child completion", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) {
			child.CompletionEffectiveAt = pgtype.Timestamptz{}
		}},
		{name: "different child completion", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) {
			child.CompletionEffectiveAt.Time = child.CompletionEffectiveAt.Time.Add(time.Microsecond)
			child.FinalizationRetainUntil.Time = storage.EvidenceRetentionDeadline(child.CompletionEffectiveAt.Time, article13.RetentionYearsV1)
		}},
		{name: "missing parent retention", wantErr: true, mutate: func(parent, _ *generated.Document) { parent.FinalizationRetainUntil = pgtype.Timestamptz{} }},
		{name: "missing child retention", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) {
			child.FinalizationRetainUntil = pgtype.Timestamptz{}
		}},
		{name: "different child retention", wantErr: true, mutate: func(_ *generated.Document, child *generated.Document) {
			child.FinalizationRetainUntil.Time = child.FinalizationRetainUntil.Time.Add(time.Second)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := baseParent
			child := baseChild
			if tc.mutate != nil {
				tc.mutate(&parent, &child)
			}
			engine := &Engine{EnvelopeChildren: func(context.Context, *generated.Document) ([]*generated.Document, error) {
				return []*generated.Document{&child}, nil
			}}
			roles, err := engine.signerRolesForDocument(context.Background(), &parent)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("roles = %v, want commitment rejection", roles)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact family commitment rejected: %v", err)
			}
			if got := strings.Join(roles, ","); got != "signer" {
				t.Fatalf("roles = %q, want signer", got)
			}
		})
	}
}

func TestFindSignatureFieldFor_DefaultSignerAndNested(t *testing.T) {
	// Construct directly to cover legacy stored trees from before validation
	// required recipient_role; current ParseTree correctly rejects new ones.
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{{
		ID: "outer", Type: blocks.TypeCallout,
		Content: []blocks.Block{{ID: "default-signer", Type: blocks.TypeSignatureField}},
	}}}
	if got := findSignatureFieldFor(tree, "signer"); got == nil || got.ID != "default-signer" {
		t.Fatalf("default nested signer field not found: %#v", got)
	}
	if got := findSignatureFieldFor(tree, "approver"); got != nil {
		t.Fatalf("default signer field must not match approver: %#v", got)
	}
}

func TestVerifyCompletedEnvelopeChildren_AllOrNoneAndArtifactsMatch(t *testing.T) {
	completionEffectiveAt := pgtype.Timestamptz{Time: time.Date(2026, 8, 31, 12, 0, 0, 123456000, time.UTC), Valid: true}
	retainUntil := pgtype.Timestamptz{Time: storage.EvidenceRetentionDeadline(completionEffectiveAt.Time, article13.RetentionYearsV1), Valid: true}
	finalKey, certKey := "org/acme/envelope/final.pdf", "org/acme/envelope/audit.pdf"
	finalSHA := []byte("01234567890123456789012345678901")
	finalVersionID := "version-final"
	cert := storedAuditCertificate{
		CertKey: certKey, CertSHA256: sha256.Sum256([]byte("cert")), CertVersionID: "version-cert",
		PayloadKey: "org/acme/envelope/audit-payload.txt", PayloadSHA256: sha256.Sum256([]byte("payload")), PayloadVersionID: "version-payload",
		SignatureKey: "org/acme/envelope/audit-signature.txt", SignatureSHA256: sha256.Sum256([]byte("signature")), SignatureVersionID: "version-signature",
	}
	expected := []*generated.Document{
		{ID: uuid.New(), Status: "finalizing", CompletionEffectiveAtBound: true, CompletionEffectiveAt: completionEffectiveAt, FinalizationRetainUntil: retainUntil, BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{"a":"1"}`)},
		{ID: uuid.New(), Status: "finalizing", CompletionEffectiveAtBound: true, CompletionEffectiveAt: completionEffectiveAt, FinalizationRetainUntil: retainUntil, BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{"b":"2"}`)},
	}
	completed := make([]*generated.Document, 0, len(expected))
	for _, original := range expected {
		completed = append(completed, &generated.Document{
			ID: original.ID, Status: "completed",
			CompletionEffectiveAtBound: true,
			CompletionEffectiveAt:      completionEffectiveAt, CompletedAt: completionEffectiveAt,
			FinalizationRetainUntil: retainUntil,
			BlocksJson:              original.BlocksJson, VariablesJson: original.VariablesJson,
			FinalPdfKey: pgtype.Text{String: finalKey, Valid: true}, FinalPdfSha: finalSHA, FinalPdfVersionID: pgtype.Text{String: finalVersionID, Valid: true},
			AuditCertKey: pgtype.Text{String: cert.CertKey, Valid: true}, AuditCertSha256: cert.CertSHA256[:], AuditCertVersionID: pgtype.Text{String: cert.CertVersionID, Valid: true},
			AuditPayloadKey: pgtype.Text{String: cert.PayloadKey, Valid: true}, AuditPayloadSha256: cert.PayloadSHA256[:], AuditPayloadVersionID: pgtype.Text{String: cert.PayloadVersionID, Valid: true},
			AuditSignatureKey: pgtype.Text{String: cert.SignatureKey, Valid: true}, AuditSignatureSha256: cert.SignatureSHA256[:], AuditSignatureVersionID: pgtype.Text{String: cert.SignatureVersionID, Valid: true},
			EvidenceVersionPinsRequired: true,
		})
	}
	if err := verifyCompletedEnvelopeChildren(expected, completed, completionEffectiveAt, retainUntil, finalKey, finalSHA, finalVersionID, cert); err != nil {
		t.Fatalf("matching propagation rejected: %v", err)
	}
	if err := verifyCompletedEnvelopeChildren(expected, completed[:1], completionEffectiveAt, retainUntil, finalKey, finalSHA, finalVersionID, cert); err == nil {
		t.Fatal("partial child completion must roll back parent completion")
	}
	completed[1].FinalPdfSha = []byte("different")
	if err := verifyCompletedEnvelopeChildren(expected, completed, completionEffectiveAt, retainUntil, finalKey, finalSHA, finalVersionID, cert); err == nil {
		t.Fatal("mismatched child artifact must roll back parent completion")
	}
}

func TestValidateEnvelopeChildrenFinalizationFreeze_AllOrNoneAndExact(t *testing.T) {
	parentID, orgID := uuid.New(), uuid.New()
	effective := pgtype.Timestamptz{Time: time.Date(2026, 8, 31, 12, 0, 0, 123456000, time.UTC), Valid: true}
	retainUntil := pgtype.Timestamptz{Time: storage.EvidenceRetentionDeadline(effective.Time, article13.RetentionYearsV1), Valid: true}
	parent := &generated.Document{
		ID: parentID, OrgID: orgID, IsEnvelope: true, Status: "finalizing",
		CompletionEffectiveAtBound: true, CompletionEffectiveAt: effective,
		FinalizationRetainUntil: retainUntil,
	}
	expected := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent", ParentEnvelopeID: pgtype.UUID{Bytes: parentID, Valid: true}},
		{ID: uuid.New(), OrgID: orgID, Status: "in_progress", ParentEnvelopeID: pgtype.UUID{Bytes: parentID, Valid: true}},
	}
	frozen := make([]*generated.Document, 0, len(expected))
	for _, child := range expected {
		frozen = append(frozen, &generated.Document{
			ID: child.ID, OrgID: orgID, Status: "finalizing",
			ParentEnvelopeID: child.ParentEnvelopeID, CompletionEffectiveAtBound: true,
			CompletionEffectiveAt: effective, FinalizationRetainUntil: retainUntil,
		})
	}
	if err := validateEnvelopeChildrenFinalizationFreeze(parent, expected, frozen); err != nil {
		t.Fatalf("exact family freeze rejected: %v", err)
	}
	if err := validateEnvelopeChildrenFinalizationFreeze(parent, expected, frozen[:1]); err == nil {
		t.Fatal("partial family freeze accepted")
	}
	wrong := *frozen[1]
	wrong.CompletionEffectiveAt = pgtype.Timestamptz{Time: effective.Time.Add(time.Microsecond), Valid: true}
	if err := validateEnvelopeChildrenFinalizationFreeze(parent, expected, []*generated.Document{frozen[0], &wrong}); err == nil {
		t.Fatal("child with a divergent completion commitment accepted")
	}
}

func TestEnvelopeChildStatusMatchesParent_FinalizationIsFamilyWide(t *testing.T) {
	if !envelopeChildStatusMatchesParent("finalizing", "finalizing") {
		t.Fatal("finalizing envelope rejected a frozen child")
	}
	for _, childStatus := range []string{"sent", "in_progress", "completed"} {
		if envelopeChildStatusMatchesParent("finalizing", childStatus) {
			t.Fatalf("finalizing envelope accepted child status %q", childStatus)
		}
	}
	if !envelopeChildStatusMatchesParent("in_progress", "sent") ||
		!envelopeChildStatusMatchesParent("in_progress", "in_progress") {
		t.Fatal("active envelope rejected an active child")
	}
}
