// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package blocks defines the canonical document block tree, validators,
// renderers, and parsers. The block tree is the source of truth for any
// block-authored Hash document. The TipTap editor in the frontend
// translates to/from this shape via a thin transformer; agents author the
// canonical tree directly via MCP write tools.
//
// Schema is versioned at the document level so we can evolve without
// breaking existing documents.
package blocks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// SchemaVersion is the current canonical schema version. Documents stamped
// with a newer version than this are rejected; older versions can be
// upgraded by future migration code (none required at v1).
const SchemaVersion = 1

// Type is the strict enum of block types Hash understands.
type Type string

const (
	TypeHeading        Type = "heading"
	TypeParagraph      Type = "paragraph"
	TypeBulletList     Type = "bullet_list"
	TypeOrderedList    Type = "ordered_list"
	TypeListItem       Type = "list_item"
	TypeTable          Type = "table"
	TypeImage          Type = "image"
	TypeDivider        Type = "divider"
	TypePageBreak      Type = "page_break"
	TypeSignatureField Type = "signature_field"
	TypeInitialField   Type = "initial_field"
	TypeTextField      Type = "text_field"
	TypeDateField      Type = "date_field"
	TypeCheckbox       Type = "checkbox"
	TypeDynamicVar     Type = "dynamic_variable"
	TypeConditional    Type = "conditional"
	TypeCode           Type = "code"
	TypeQuote          Type = "quote"
	TypeCallout        Type = "callout"
	TypeRawHTML        Type = "raw_html"
)

// AllTypes returns the full set of valid block types. Order is stable; safe
// for use in generated docs and JSON schema output.
func AllTypes() []Type {
	return []Type{
		TypeHeading, TypeParagraph,
		TypeBulletList, TypeOrderedList, TypeListItem,
		TypeTable, TypeImage, TypeDivider, TypePageBreak,
		TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox,
		TypeDynamicVar, TypeConditional,
		TypeCode, TypeQuote, TypeCallout, TypeRawHTML,
	}
}

// Tree is the document-level wrapper.
type Tree struct {
	Version int     `json:"version"`
	Blocks  []Block `json:"blocks"`
}

// Block is the universal block. Different types use different subsets of
// fields. Validate() enforces the per-type rules.
type Block struct {
	ID      string         `json:"id"`
	Type    Type           `json:"type"`
	Attrs   map[string]any `json:"attrs,omitempty"`
	Text    string         `json:"text,omitempty"`
	Content []Block        `json:"content,omitempty"`
	Rows    [][]string     `json:"rows,omitempty"` // table rows; only used by TypeTable
}

// HeadingLevel returns the heading level (1..6), defaulting to 1.
func (b Block) HeadingLevel() int {
	if v, ok := b.Attrs["level"]; ok {
		switch n := v.(type) {
		case float64:
			lvl := int(n)
			if lvl < 1 {
				return 1
			}
			if lvl > 6 {
				return 6
			}
			return lvl
		case int:
			if n < 1 {
				return 1
			}
			if n > 6 {
				return 6
			}
			return n
		}
	}
	return 1
}

// AttrString returns a string-typed attr or fallback.
func (b Block) AttrString(name, fallback string) string {
	v, ok := b.Attrs[name]
	if !ok {
		return fallback
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fallback
}

// AttrBool returns a bool-typed attr or fallback.
func (b Block) AttrBool(name string, fallback bool) bool {
	v, ok := b.Attrs[name]
	if !ok {
		return fallback
	}
	if s, ok := v.(bool); ok {
		return s
	}
	return fallback
}

// ParseTree decodes JSON into a Tree and validates it.
func ParseTree(raw []byte) (*Tree, error) {
	if len(raw) == 0 {
		return &Tree{Version: SchemaVersion}, nil
	}
	t, err := decodeTree(raw)
	if err != nil {
		return nil, err
	}
	if t.Version == 0 {
		t.Version = SchemaVersion
	}
	if err := Validate(t); err != nil {
		return nil, err
	}
	return t, nil
}

// ParseCanonicalTree is the immutable-evidence parser. Unlike the authoring
// parser it refuses omitted IDs, because generating one while rendering a
// sent row would make field and audit identity process-dependent.
func ParseCanonicalTree(raw []byte) (*Tree, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("decode tree: empty canonical tree")
	}
	tree, err := decodeTree(raw)
	if err != nil {
		return nil, err
	}
	if tree.Version == 0 {
		return nil, fmt.Errorf("canonical tree requires an explicit schema version")
	}
	var missingID bool
	walkTree(tree, func(block *Block) {
		if block.ID == "" {
			missingID = true
		}
	})
	if missingID {
		return nil, ErrMissingID
	}
	if err := Validate(tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func decodeTree(raw []byte) (*Tree, error) {
	var tree Tree
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tree); err != nil {
		return nil, fmt.Errorf("decode tree: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode tree: trailing JSON content")
	}
	return &tree, nil
}

// NormalizeTreeJSON parses, validates, assigns any omitted block IDs, and
// serializes the resulting canonical tree. Authoring endpoints must persist
// this output—not the original request bytes—otherwise an omitted ID would be
// regenerated differently on every read and break field/audit correlation.
func NormalizeTreeJSON(raw []byte) (json.RawMessage, error) {
	tree, err := ParseTree(raw)
	if err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("encode canonical tree: %w", err)
	}
	return normalized, nil
}

// RequiredSignerRoles returns the distinct recipient roles that have at least
// one signature field in the tree. An empty recipient_role on a signature field
// counts as "signer" (the default signing party). These are the roles a document
// needs a signed recipient for before it can complete. Returned order is not
// stable; callers that need determinism should sort.
func RequiredSignerRoles(t *Tree) []string {
	seen := map[string]struct{}{}
	walkTree(t, func(b *Block) {
		if b.Type != TypeSignatureField {
			return
		}
		role := b.AttrString("recipient_role", "")
		if role == "" {
			role = "signer"
		}
		seen[role] = struct{}{}
	})
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	return out
}

// RequiredSignerRolesForVariables projects conditional branches using the
// exact frozen variable map, then returns the signature roles that are
// actually present in the signer/PDF artifact. Invalid conditional evaluation
// is an error, never an implicit false branch.
func RequiredSignerRolesForVariables(t *Tree, vars map[string]string) ([]string, error) {
	if t == nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var visit func([]Block) error
	visit = func(items []Block) error {
		for i := range items {
			block := &items[i]
			if block.Type == TypeConditional {
				included, err := EvalConditionStrict(block.AttrString("expression", ""), vars)
				if err != nil {
					return fmt.Errorf("block %q condition: %w", block.ID, err)
				}
				if !included {
					continue
				}
			}
			if block.Type == TypeSignatureField {
				role := block.AttrString("recipient_role", "")
				if role == "" {
					role = "signer"
				}
				seen[role] = struct{}{}
			}
			if err := visit(block.Content); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(t.Blocks); err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(seen))
	for role := range seen {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

// MustEmptyTree returns a fresh empty document at the current schema.
func MustEmptyTree() *Tree {
	return &Tree{Version: SchemaVersion, Blocks: []Block{}}
}

// IsContainer returns true if a block type holds nested content.
func (t Type) IsContainer() bool {
	switch t {
	case TypeBulletList, TypeOrderedList, TypeListItem, TypeConditional, TypeCallout, TypeQuote:
		return true
	}
	return false
}

// IsField returns true if a block represents a fillable field bound to a
// signer recipient.
func (t Type) IsField() bool {
	switch t {
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		return true
	}
	return false
}

// Errors surfaced by the validator. Wrapped so callers can do errors.Is()
// against ErrInvalidBlock for any structural issue.
var (
	ErrInvalidBlock  = errors.New("invalid block")
	ErrUnknownType   = errors.New("unknown block type")
	ErrSchemaVersion = errors.New("unsupported schema version")
	ErrMissingID     = errors.New("block missing id")
	ErrDuplicateID   = errors.New("duplicate block id")
)
