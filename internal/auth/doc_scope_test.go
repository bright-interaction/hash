package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestDocumentScopeFromContext_Unset(t *testing.T) {
	_, ok := DocumentScopeFromContext(context.Background())
	if ok {
		t.Fatal("empty context should report no scope")
	}
}

func TestDocumentScopeFromContext_Set(t *testing.T) {
	docID := uuid.New()
	ctx := context.WithValue(context.Background(), DocumentScopeKey, docID)
	got, ok := DocumentScopeFromContext(ctx)
	if !ok {
		t.Fatal("scope should be present")
	}
	if got != docID {
		t.Fatalf("scope mismatch: got %s want %s", got, docID)
	}
}

func TestDocumentScopeFromContext_NilUUIDIsAbsent(t *testing.T) {
	ctx := context.WithValue(context.Background(), DocumentScopeKey, uuid.Nil)
	_, ok := DocumentScopeFromContext(ctx)
	if ok {
		t.Fatal("uuid.Nil should not register as a scope")
	}
}

func TestEnforceDocScope_NoScopeAlwaysOK(t *testing.T) {
	if err := EnforceDocScope(context.Background(), uuid.New()); err != nil {
		t.Fatalf("no-scope ctx should pass for any target, got %v", err)
	}
}

func TestEnforceDocScope_Match(t *testing.T) {
	docID := uuid.New()
	ctx := context.WithValue(context.Background(), DocumentScopeKey, docID)
	if err := EnforceDocScope(ctx, docID); err != nil {
		t.Fatalf("matching target should pass, got %v", err)
	}
}

func TestEnforceDocScope_Mismatch(t *testing.T) {
	docID := uuid.New()
	other := uuid.New()
	ctx := context.WithValue(context.Background(), DocumentScopeKey, docID)
	err := EnforceDocScope(ctx, other)
	if err == nil {
		t.Fatal("mismatched target should fail")
	}
	if !errors.Is(err, ErrDocScopeMismatch) {
		t.Fatalf("expected ErrDocScopeMismatch, got %v", err)
	}
}
