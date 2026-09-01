// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestExpireLockedEnvelopeChildrenTransitionsEveryActiveChild(t *testing.T) {
	orgID := uuid.New()
	children := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent"},
		{ID: uuid.New(), OrgID: orgID, Status: "in_progress"},
		{ID: uuid.New(), OrgID: orgID, Status: "expired"},
	}
	store := &fakeStatusSetter{}

	got, err := expireLockedEnvelopeChildren(context.Background(), store, children)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != children[0].ID || got[1] != children[1].ID {
		t.Fatalf("expired child IDs = %#v, want the two active children", got)
	}
	if len(store.calls) != 2 {
		t.Fatalf("status calls = %d, want two active children", len(store.calls))
	}
	for _, call := range store.calls {
		if call.Status != "expired" || call.OrgID != orgID {
			t.Fatalf("unexpected expiration transition: %#v", call)
		}
	}
}

func TestExpireLockedEnvelopeChildrenRejectsDivergentTerminalChildBeforeWrites(t *testing.T) {
	orgID := uuid.New()
	children := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent"},
		{ID: uuid.New(), OrgID: orgID, Status: "completed"},
	}
	store := &fakeStatusSetter{}

	got, err := expireLockedEnvelopeChildren(context.Background(), store, children)
	if err == nil || !strings.Contains(err.Error(), "incompatible status completed") {
		t.Fatalf("error = %v, want completed-child conflict", err)
	}
	if got != nil {
		t.Fatalf("expired child IDs = %#v, want nil", got)
	}
	if len(store.calls) != 0 {
		t.Fatalf("status calls = %#v, want preflight failure before writes", store.calls)
	}
}

func TestExpireLockedEnvelopeChildrenPropagatesTransitionFailure(t *testing.T) {
	orgID := uuid.New()
	wantErr := errors.New("status update failed")
	children := []*generated.Document{
		{ID: uuid.New(), OrgID: orgID, Status: "sent"},
		{ID: uuid.New(), OrgID: orgID, Status: "in_progress"},
	}
	store := &fakeStatusSetter{failAt: 2, err: wantErr}

	got, err := expireLockedEnvelopeChildren(context.Background(), store, children)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped transition failure", err)
	}
	if got != nil {
		t.Fatalf("expired child IDs = %#v, want nil on transaction rollback path", got)
	}
	if len(store.calls) != 2 {
		t.Fatalf("status calls = %d, want stop at failed child", len(store.calls))
	}
}
