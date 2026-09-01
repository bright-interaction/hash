// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestRequireLifecycleRootRejectsEnvelopeChildID(t *testing.T) {
	child := &generated.Document{
		ID:               uuid.New(),
		ParentEnvelopeID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
	}
	if err := requireLifecycleRoot(child); !errors.Is(err, ErrEnvelopeChildLifecycle) {
		t.Fatalf("error = %v, want ErrEnvelopeChildLifecycle", err)
	}
	if err := requireLifecycleRoot(&generated.Document{ID: uuid.New()}); err != nil {
		t.Fatalf("standalone/root document rejected: %v", err)
	}
}

func TestVoidLockedDocumentFamilyTransitionsEveryActiveChildAndParent(t *testing.T) {
	orgID := uuid.New()
	parent := &generated.Document{ID: uuid.New(), OrgID: orgID, Status: "in_progress", IsEnvelope: true}
	children := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent"},
		{ID: uuid.New(), OrgID: orgID, Status: "in_progress"},
	}
	store := &fakeDocumentVoider{}

	got, err := voidLockedDocumentFamily(context.Background(), store, parent, children)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != children[0].ID || got[1] != children[1].ID {
		t.Fatalf("voided child IDs = %#v, want the two active children", got)
	}
	if len(store.calls) != 3 {
		t.Fatalf("void calls = %d, want two active children plus parent", len(store.calls))
	}
	if store.calls[0].ID != children[0].ID || store.calls[1].ID != children[1].ID || store.calls[2].ID != parent.ID {
		t.Fatalf("void order = %#v, want children before parent", store.calls)
	}
}

func TestVoidLockedDocumentFamilyPropagatesChildFailureBeforeParent(t *testing.T) {
	orgID := uuid.New()
	parent := &generated.Document{ID: uuid.New(), OrgID: orgID, Status: "sent", IsEnvelope: true}
	children := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent"},
		{ID: uuid.New(), OrgID: orgID, Status: "in_progress"},
	}
	wantErr := errors.New("child update failed")
	store := &fakeDocumentVoider{failAt: 2, err: wantErr}

	got, err := voidLockedDocumentFamily(context.Background(), store, parent, children)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped child failure", err)
	}
	if got != nil {
		t.Fatalf("voided child IDs = %#v, want nil on rollback path", got)
	}
	if len(store.calls) != 2 {
		t.Fatalf("void calls = %d, want stop at failed child before parent", len(store.calls))
	}
	for _, call := range store.calls {
		if call.ID == parent.ID {
			t.Fatal("parent was transitioned after a child failure")
		}
	}
}

func TestVoidLockedDocumentFamilyRejectsEveryNonActiveStateWithoutWrites(t *testing.T) {
	for _, status := range []string{"draft", "changes_requested", "declined", "expired", "completed", "voided"} {
		t.Run(status+" parent", func(t *testing.T) {
			orgID := uuid.New()
			store := &fakeDocumentVoider{}
			_, err := voidLockedDocumentFamily(context.Background(), store, &generated.Document{ID: uuid.New(), OrgID: orgID, Status: status}, nil)
			if !errors.Is(err, ErrNotVoidable) || len(store.calls) != 0 {
				t.Fatalf("status %s: error=%v calls=%v", status, err, store.calls)
			}
		})
		t.Run(status+" child", func(t *testing.T) {
			orgID := uuid.New()
			store := &fakeDocumentVoider{}
			parent := &generated.Document{ID: uuid.New(), OrgID: orgID, Status: "sent", IsEnvelope: true}
			children := []*generated.Document{{ID: uuid.New(), OrgID: orgID, Status: "sent"}, {ID: uuid.New(), OrgID: orgID, Status: status}}
			_, err := voidLockedDocumentFamily(context.Background(), store, parent, children)
			if !errors.Is(err, ErrNotVoidable) || len(store.calls) != 0 {
				t.Fatalf("status %s: error=%v calls=%v", status, err, store.calls)
			}
		})
	}
}

type fakeDocumentVoider struct {
	calls  []generated.VoidDocumentIfActiveParams
	failAt int
	err    error
}

func (f *fakeDocumentVoider) VoidDocumentIfActive(_ context.Context, arg generated.VoidDocumentIfActiveParams) (*generated.Document, error) {
	f.calls = append(f.calls, arg)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return nil, f.err
	}
	return &generated.Document{ID: arg.ID, OrgID: arg.OrgID, Status: "voided"}, nil
}
