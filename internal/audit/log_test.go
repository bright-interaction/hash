// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestLogRequiresOrgID(t *testing.T) {
	l := New(nil, nil) // queries nil ,  Log must reject before reaching the DB
	_, err := l.Log(context.Background(), Entry{Kind: "x"})
	if err == nil {
		t.Fatal("expected error for missing org_id, got nil")
	}
}

func TestLogRequiresKind(t *testing.T) {
	l := New(nil, nil)
	_, err := l.Log(context.Background(), Entry{OrgID: uuid.New()})
	if err == nil {
		t.Fatal("expected error for missing kind, got nil")
	}
}

func TestUUIDToPg_Nil(t *testing.T) {
	v := uuidToPg(nil)
	if v.Valid {
		t.Error("nil pointer should yield invalid pgtype.UUID")
	}
}

func TestUUIDToPg_Set(t *testing.T) {
	id := uuid.New()
	v := uuidToPg(&id)
	if !v.Valid {
		t.Error("non-nil pointer should yield valid pgtype.UUID")
	}
	if uuid.UUID(v.Bytes) != id {
		t.Errorf("bytes mismatch")
	}
}

func TestTextOrNull(t *testing.T) {
	if v := textOrNull(""); v.Valid {
		t.Error("empty string should be invalid pgtype.Text")
	}
	if v := textOrNull("x"); !v.Valid || v.String != "x" {
		t.Errorf("non-empty wrong: %+v", v)
	}
}

func TestEventKindsConst(t *testing.T) {
	// Cheap regression: if a refactor renames a kind, this fails loudly.
	wants := []string{
		KindDocumentCreated, KindDocumentSent, KindDocumentSigned,
		KindDocumentCompleted, KindDocumentDeclined, KindDocumentVoided,
	}
	for _, k := range wants {
		if k == "" {
			t.Errorf("event kind unexpectedly empty")
		}
	}
}

func TestSubscribe_NilIsNoop(t *testing.T) {
	l := New(nil, nil)
	l.Subscribe(nil)
	if len(l.hooks) != 0 {
		t.Errorf("nil hook should not be appended, got %d", len(l.hooks))
	}
}

func TestSubscribe_StoresHooks(t *testing.T) {
	l := New(nil, nil)
	l.Subscribe(func(_ context.Context, _ uuid.UUID, _ Entry) {})
	l.Subscribe(func(_ context.Context, _ uuid.UUID, _ Entry) {})
	if len(l.hooks) != 2 {
		t.Errorf("expected 2 hooks, got %d", len(l.hooks))
	}
}

// guard: errors package is referenced so future test additions can use
// errors.Is helpers without re-importing.
var _ = errors.New
