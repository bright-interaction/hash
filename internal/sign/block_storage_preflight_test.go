// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestValidateFrozenDocumentFamilyRejectsUnpinnedStorageReferences(t *testing.T) {
	imageTree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{{
		ID: "nested", Type: blocks.TypeCallout, Content: []blocks.Block{{
			ID: "image", Type: blocks.TypeImage, Attrs: map[string]any{"storage_key": "org/o/image.png"},
		}},
	}}}
	imageJSON, err := json.Marshal(imageTree)
	if err != nil {
		t.Fatal(err)
	}
	standalone := &generated.Document{ID: uuid.New(), SourceKind: "blocks", Status: "in_progress", BlocksJson: imageJSON, VariablesJson: []byte(`{}`)}
	if err := (&Engine{}).validateFrozenDocumentFamily(context.Background(), standalone); !errors.Is(err, blocks.ErrUnpinnedStorageReference) {
		t.Fatalf("standalone finalization preflight error = %v", err)
	}
	interactiveTree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{{
		ID: "nested", Type: blocks.TypeCallout, Content: []blocks.Block{{
			ID: "initial", Type: blocks.TypeInitialField, Attrs: map[string]any{"recipient_role": "signer"},
		}},
	}}}
	interactiveJSON, err := json.Marshal(interactiveTree)
	if err != nil {
		t.Fatal(err)
	}
	interactive := &generated.Document{ID: uuid.New(), SourceKind: "blocks", Status: "in_progress", BlocksJson: interactiveJSON, VariablesJson: []byte(`{}`)}
	if err := (&Engine{}).validateFrozenDocumentFamily(context.Background(), interactive); err == nil || !strings.Contains(err.Error(), string(blocks.TypeInitialField)) {
		t.Fatalf("unsupported interactive field passed finalization preflight: %v", err)
	}

	parent := &generated.Document{ID: uuid.New(), IsEnvelope: true, SourceKind: "blocks", Status: "finalizing"}
	rawTree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{{
		ID: "raw", Type: blocks.TypeRawHTML, Text: `<img src="/api/v1/storage/org/o/image.png">`,
	}}}
	rawJSON, err := json.Marshal(rawTree)
	if err != nil {
		t.Fatal(err)
	}
	child := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks", Status: "finalizing", BlocksJson: rawJSON, VariablesJson: []byte(`{}`),
		ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true},
	}
	engine := &Engine{EnvelopeChildren: func(context.Context, *generated.Document) ([]*generated.Document, error) {
		return []*generated.Document{child}, nil
	}}
	if err := engine.validateFrozenDocumentFamily(context.Background(), parent); !errors.Is(err, blocks.ErrUnpinnedStorageReference) {
		t.Fatalf("envelope finalization preflight error = %v", err)
	}
}

func TestFinalizeChecksBlockStorageBeforeClaimOrResume(t *testing.T) {
	raw, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (e *Engine) finalize(")
	if start < 0 {
		t.Fatal("finalize implementation is absent")
	}
	source = source[start:]
	gate := strings.Index(source, "e.validateFrozenDocumentFamily(ctx, doc)")
	resumeOrClaim := strings.Index(source, `if doc.Status == "finalizing"`)
	if gate < 0 || resumeOrClaim < 0 || gate > resumeOrClaim {
		t.Fatal("block storage evidence gate must run before finalizing resume or claim")
	}
}
