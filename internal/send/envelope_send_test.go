// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
)

func TestValidateEnvelopeChildrenUnionsRolesAcrossTrees(t *testing.T) {
	envelopeID := uuid.New()
	children := []*generated.Document{
		testEnvelopeChild(t, envelopeID, "signer"),
		testEnvelopeChild(t, envelopeID, "approver", "signer"),
	}

	got, err := validateEnvelopeChildren(envelopeID, children)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"approver", "signer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("roles = %#v, want %#v", got, want)
	}
	if err := validateRequiredRoles(got, []*generated.Recipient{
		{Role: "signer"},
		{Role: "approver"},
	}); err != nil {
		t.Fatalf("assigned union rejected: %v", err)
	}
}

func TestValidateRequiredRolesRejectsMissingEnvelopeChildRole(t *testing.T) {
	err := validateRequiredRoles(
		[]string{"signer", "approver"},
		[]*generated.Recipient{{Role: "signer"}},
	)
	if !errors.Is(err, ErrMissingSignerForRole) {
		t.Fatalf("error = %v, want ErrMissingSignerForRole", err)
	}
	if !strings.Contains(err.Error(), "approver") {
		t.Fatalf("error %q does not identify missing role", err)
	}
}

func TestValidateRequiredRolesRejectsDuplicateRecipientsForSigningRole(t *testing.T) {
	err := validateRequiredRoles(
		[]string{"signer"},
		[]*generated.Recipient{{Role: "signer"}, {Role: "signer"}},
	)
	if !errors.Is(err, ErrAmbiguousSignerForRole) {
		t.Fatalf("error = %v, want ErrAmbiguousSignerForRole", err)
	}
	if !strings.Contains(err.Error(), "signer") || !strings.Contains(err.Error(), "2 recipients") {
		t.Fatalf("error %q does not identify ambiguous role", err)
	}
}

func TestValidateSendRecipientsRejectsMalformedAndFieldlessStandaloneBlocks(t *testing.T) {
	recs := []*generated.Recipient{validSendRecipient("signer")}
	malformed := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks", RequiresSignature: true,
		BlocksJson: json.RawMessage(`{"version":`),
	}
	if err := validateSendRecipients(malformed, nil, recs); err == nil || !strings.Contains(err.Error(), "parse blocks") {
		t.Fatalf("malformed blocks error = %v, want parse failure", err)
	}

	emptyRaw, err := json.Marshal(blocks.Tree{Version: blocks.SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	fieldless := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks", RequiresSignature: true, BlocksJson: emptyRaw,
	}
	if err := validateSendRecipients(fieldless, nil, recs); !errors.Is(err, ErrNoSignatureFields) {
		t.Fatalf("fieldless blocks error = %v, want ErrNoSignatureFields", err)
	}
}

func TestValidateSendRecipientsRejectsUnboundLegalBlockTypes(t *testing.T) {
	recs := []*generated.Recipient{validSendRecipient("signer")}
	for _, blockType := range []blocks.Type{
		blocks.TypeImage,
		blocks.TypeInitialField,
		blocks.TypeTextField,
		blocks.TypeDateField,
		blocks.TypeCheckbox,
	} {
		t.Run(string(blockType), func(t *testing.T) {
			attrs := map[string]any{"recipient_role": "signer"}
			if blockType == blocks.TypeImage {
				attrs = map[string]any{"storage_key": "org/assets/material.png"}
			}
			tree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
				{ID: "sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
				{ID: "nested", Type: blocks.TypeCallout, Content: []blocks.Block{{ID: "unsupported", Type: blockType, Attrs: attrs}}},
			}}
			raw, err := json.Marshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			doc := &generated.Document{ID: uuid.New(), SourceKind: "blocks", RequiresSignature: true, BlocksJson: raw}
			err = validateSendRecipients(doc, nil, recs)
			if !errors.Is(err, ErrUnsupportedBlockEvidence) || !strings.Contains(err.Error(), string(blockType)) {
				t.Fatalf("%s error = %v, want unsupported block rejection", blockType, err)
			}
		})
	}
}

func TestValidateSendRecipientsRejectsInvalidPersistedRecipientBeforeCeremony(t *testing.T) {
	tree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "sig", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{ID: uuid.New(), SourceKind: "blocks", RequiresSignature: true, BlocksJson: raw}
	rec := validSendRecipient("signer")
	rec.Email = "Signer <signer@example.test>"
	if err := validateSendRecipients(doc, nil, []*generated.Recipient{rec}); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("error = %v, want ErrInvalidRecipient", err)
	}
}

func TestValidateSendRecipientsRejectsUnsupportedInformationalRoles(t *testing.T) {
	for _, role := range []string{"cc", "viewer"} {
		doc := &generated.Document{ID: uuid.New(), SourceKind: "pdf", RequiresSignature: false}
		if err := validateSendRecipients(doc, nil, []*generated.Recipient{validSendRecipient(role)}); !errors.Is(err, ErrUnsupportedRecipientRole) {
			t.Fatalf("role %s error = %v, want ErrUnsupportedRecipientRole", role, err)
		}
	}
}

func validSendRecipient(role string) *generated.Recipient {
	return &generated.Recipient{
		ID: uuid.New(), Role: role, Status: "pending",
		Email: "signer@example.test", Name: "Signer", Locale: "en",
	}
}

func TestVerifyPreparedSendDocumentRejectsRacingStandaloneEdit(t *testing.T) {
	prepared := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Name: "Prepared", Status: "draft",
		SourceKind: "blocks", RoutingTier: "SES", RequiresSignature: true,
		BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{"amount":"1"}`),
	}
	locked := *prepared
	locked.VariablesJson = json.RawMessage(`{"amount":"1000000"}`)

	err := verifyPreparedSendDocument(prepared, &locked)
	if !errors.Is(err, ErrDraftChangedDuringSend) {
		t.Fatalf("error = %v, want ErrDraftChangedDuringSend", err)
	}
}

func TestValidateEnvelopeChildrenFailsClosed(t *testing.T) {
	envelopeID := uuid.New()

	t.Run("empty", func(t *testing.T) {
		if _, err := validateEnvelopeChildren(envelopeID, nil); err == nil {
			t.Fatal("empty envelope should be rejected")
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*generated.Document)
		want   string
	}{
		{"detached", func(d *generated.Document) { d.ParentEnvelopeID.Valid = false }, "no longer attached"},
		{"nested envelope", func(d *generated.Document) { d.IsEnvelope = true }, "itself an envelope"},
		{"sent child", func(d *generated.Document) { d.Status = "sent" }, "not draft"},
		{"pdf child", func(d *generated.Document) { d.SourceKind = "pdf" }, "blocks-source"},
		{"malformed blocks", func(d *generated.Document) { d.BlocksJson = json.RawMessage(`{"version":`) }, "parse child"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := testEnvelopeChild(t, envelopeID, "signer")
			tc.mutate(child)
			_, err := validateEnvelopeChildren(envelopeID, []*generated.Document{child})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestFreezeEnvelopeChildrenPersistsEveryChild(t *testing.T) {
	envelopeID := uuid.New()
	children := []*generated.Document{
		testEnvelopeChild(t, envelopeID, "signer"),
		testEnvelopeChild(t, envelopeID, "approver"),
	}
	freezer := &fakeEnvelopeFreezer{}
	updater := &fakeBlocksUpdater{}

	got, err := freezeEnvelopeChildren(context.Background(), freezer, updater, children)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(freezer.calls) != 2 || len(updater.calls) != 2 {
		t.Fatalf("frozen=%d resolver_calls=%d update_calls=%d, want 2 each", len(got), len(freezer.calls), len(updater.calls))
	}
	for i := range children {
		if freezer.calls[i] != children[i].ID || updater.calls[i].ID != children[i].ID {
			t.Fatalf("child %d was not frozen and persisted in order", i)
		}
		if string(got[i].VariablesJson) != `{"frozen":"true"}` {
			t.Fatalf("child %d variables = %s", i, got[i].VariablesJson)
		}
	}
}

func TestFreezeEnvelopeChildrenPropagatesUpdateFailure(t *testing.T) {
	envelopeID := uuid.New()
	wantErr := errors.New("update unavailable")
	children := []*generated.Document{
		testEnvelopeChild(t, envelopeID, "signer"),
		testEnvelopeChild(t, envelopeID, "approver"),
	}
	updater := &fakeBlocksUpdater{failAt: 2, err: wantErr}

	_, err := freezeEnvelopeChildren(context.Background(), &fakeEnvelopeFreezer{}, updater, children)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped update failure", err)
	}
	if len(updater.calls) != 2 {
		t.Fatalf("update calls = %d, want 2 (stop at failure)", len(updater.calls))
	}
}

func TestVerifyPreparedEnvelopeChildrenRejectsRacingEdit(t *testing.T) {
	envelopeID := uuid.New()
	prepared := testEnvelopeChild(t, envelopeID, "signer")
	locked := *prepared
	locked.BlocksJson = append(json.RawMessage(nil), prepared.BlocksJson...)
	locked.BlocksJson[len(locked.BlocksJson)-1] = ' '

	err := verifyPreparedEnvelopeChildren(
		[]*generated.Document{prepared},
		[]*generated.Document{&locked},
	)
	if err == nil || !strings.Contains(err.Error(), "changed while preparing") {
		t.Fatalf("error = %v, want racing edit rejection", err)
	}
}

func testEnvelopeChild(t *testing.T, envelopeID uuid.UUID, roles ...string) *generated.Document {
	t.Helper()
	tree := blocks.Tree{Version: blocks.SchemaVersion}
	for i, role := range roles {
		tree.Blocks = append(tree.Blocks, blocks.Block{
			ID:    uuid.NewString(),
			Type:  blocks.TypeSignatureField,
			Attrs: map[string]any{"recipient_role": role, "label": "Signature " + string(rune('A'+i))},
		})
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	return &generated.Document{
		ID:               uuid.New(),
		OrgID:            uuid.New(),
		Name:             "Envelope child",
		Status:           "draft",
		SourceKind:       "blocks",
		BlocksJson:       raw,
		VariablesJson:    json.RawMessage(`{"before":"true"}`),
		ParentEnvelopeID: pgtype.UUID{Bytes: envelopeID, Valid: true},
	}
}

type fakeEnvelopeFreezer struct {
	calls  []uuid.UUID
	failAt int
	err    error
}

func (f *fakeEnvelopeFreezer) FreezeForSend(_ context.Context, doc *generated.Document) (json.RawMessage, []resolver.ResolveReport, error) {
	f.calls = append(f.calls, doc.ID)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return nil, nil, f.err
	}
	return json.RawMessage(`{"frozen":"true"}`), nil, nil
}

type fakeBlocksUpdater struct {
	calls  []generated.UpdateDocumentBlocksParams
	failAt int
	err    error
}

func (f *fakeBlocksUpdater) UpdateDocumentBlocks(_ context.Context, arg generated.UpdateDocumentBlocksParams) (*generated.Document, error) {
	f.calls = append(f.calls, arg)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return nil, f.err
	}
	return &generated.Document{
		ID:            arg.ID,
		OrgID:         arg.OrgID,
		Name:          "Envelope child",
		Status:        "draft",
		SourceKind:    "blocks",
		BlocksJson:    arg.BlocksJson,
		VariablesJson: arg.VariablesJson,
	}, nil
}

type fakeStatusSetter struct {
	calls  []generated.SetDocumentStatusParams
	failAt int
	err    error
}

func (f *fakeStatusSetter) SetDocumentStatus(_ context.Context, arg generated.SetDocumentStatusParams) (*generated.Document, error) {
	f.calls = append(f.calls, arg)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return nil, f.err
	}
	return &generated.Document{ID: arg.ID, OrgID: arg.OrgID, Status: arg.Status}, nil
}
