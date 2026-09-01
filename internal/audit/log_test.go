// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestPublish_ReleasesDeferredHooks(t *testing.T) {
	l := New(nil, nil)
	called := make(chan PendingEvent, 1)
	l.Subscribe(func(_ context.Context, id uuid.UUID, e Entry) {
		called <- PendingEvent{ID: id, Entry: e}
	})
	pending := PendingEvent{ID: uuid.New(), Entry: Entry{OrgID: uuid.New(), Kind: KindDocumentSigned}}
	l.Publish(pending)
	select {
	case got := <-called:
		if got.ID != pending.ID || got.Entry.Kind != pending.Entry.Kind {
			t.Fatalf("published hook = %+v, want %+v", got, pending)
		}
	case <-time.After(time.Second):
		t.Fatal("deferred hook was not published")
	}
}

func TestPrepareEntry_ValidatesBeforeDatabaseWork(t *testing.T) {
	if _, err := prepareEntry(Entry{Kind: "x"}); err == nil {
		t.Fatal("missing org must fail")
	}
	if _, err := prepareEntry(Entry{OrgID: uuid.New()}); err == nil {
		t.Fatal("missing kind must fail")
	}
	p, err := prepareEntry(Entry{OrgID: uuid.New(), Kind: "x", IP: "2001:0db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ipString != "2001:db8::1" || len(p.raw) == 0 || p.createdAt.IsZero() {
		t.Fatalf("prepared entry not canonical: %+v", p)
	}
}

func TestNextAuditTimestamp_IsStrictlyMonotonic(t *testing.T) {
	previous := time.Date(2026, 8, 30, 12, 0, 0, int(500*time.Microsecond), time.UTC)
	for _, candidate := range []time.Time{
		previous.Add(-time.Second),
		previous,
		previous.Add(500 * time.Nanosecond), // same persisted microsecond
	} {
		got := nextAuditTimestamp(candidate, previous)
		if !got.After(previous) || got.Sub(previous) != time.Microsecond {
			t.Fatalf("nextAuditTimestamp(%s, %s) = %s", candidate, previous, got)
		}
	}
	future := previous.Add(3 * time.Microsecond)
	if got := nextAuditTimestamp(future, previous); !got.Equal(future) {
		t.Fatalf("future timestamp changed: %s", got)
	}
}

// guard: errors package is referenced so future test additions can use
// errors.Is helpers without re-importing.
var _ = errors.New
