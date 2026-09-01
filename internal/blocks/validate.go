// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var signingRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Validate enforces the structural rules every block tree must satisfy
// before we render or persist it. Errors include the offending block id
// when available so agents can self-correct.
func Validate(t *Tree) error {
	if t == nil {
		return fmt.Errorf("%w: tree is nil", ErrInvalidBlock)
	}
	if t.Version > SchemaVersion {
		return fmt.Errorf("%w: tree at v%d, server speaks v%d", ErrSchemaVersion, t.Version, SchemaVersion)
	}
	if t.Version == 0 {
		t.Version = SchemaVersion
	}

	seen := make(map[string]struct{})
	return validateBlocks(t.Blocks, seen, "")
}

func validateBlocks(blocks []Block, seen map[string]struct{}, parentPath string) error {
	for i := range blocks {
		b := &blocks[i]
		path := fmt.Sprintf("%s[%d]", parentPath, i)

		if b.ID == "" {
			b.ID = generateBlockID()
		}
		if _, dup := seen[b.ID]; dup {
			return fmt.Errorf("%w: id=%q at %s", ErrDuplicateID, b.ID, path)
		}
		seen[b.ID] = struct{}{}

		if !isKnownType(b.Type) {
			return fmt.Errorf("%w: type=%q at %s (id=%s)", ErrUnknownType, b.Type, path, b.ID)
		}

		if err := validateForType(b); err != nil {
			return fmt.Errorf("%w at %s (id=%s): %v", ErrInvalidBlock, path, b.ID, err)
		}

		if len(b.Content) > 0 {
			if !b.Type.IsContainer() {
				return fmt.Errorf("%w: type=%q at %s carries content but is not a container", ErrInvalidBlock, b.Type, path)
			}
			if err := validateBlocks(b.Content, seen, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateForType(b *Block) error {
	if err := validateCanonicalPayload(b); err != nil {
		return err
	}
	switch b.Type {
	case TypeHeading:
		lvl, ok := canonicalHeadingLevel(b.Attrs["level"])
		if !ok || lvl < 1 || lvl > 6 {
			return errors.New("heading level must be 1..6")
		}
	case TypeTable:
		columns, ok := b.Attrs["columns"].([]any)
		if !ok || len(columns) == 0 {
			return errors.New("table requires attrs.columns: string[] with at least one column")
		}
		for _, row := range b.Rows {
			if len(row) != len(columns) {
				return fmt.Errorf("table row width %d != columns %d", len(row), len(columns))
			}
		}
	case TypeImage:
		key := b.AttrString("storage_key", "")
		if key == "" {
			return errors.New("image requires attrs.storage_key")
		}
		if width := b.AttrString("width_pct", ""); width != "" {
			parsed, err := strconv.ParseUint(width, 10, 8)
			if err != nil || parsed < 1 || parsed > 100 {
				return errors.New("image attrs.width_pct must be an integer string from 1 to 100")
			}
		}
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		role := b.AttrString("recipient_role", "")
		if role == "" {
			return errors.New("field block requires attrs.recipient_role")
		}
		if !signingRolePattern.MatchString(role) {
			return errors.New("field attrs.recipient_role must be a canonical lowercase role")
		}
		if b.Type == TypeSignatureField && (role == "cc" || role == "viewer") {
			return errors.New("signature_field recipient_role cannot be cc or viewer")
		}
		if b.Type == TypeSignatureField && !b.AttrBool("required", true) {
			return errors.New("signature_field attrs.required must be true")
		}
	case TypeDynamicVar:
		if b.AttrString("name", "") == "" {
			return errors.New("dynamic_variable requires attrs.name")
		}
	case TypeConditional:
		expression := b.AttrString("expression", "")
		if expression == "" {
			return errors.New("conditional requires attrs.expression")
		}
		if b.Text != "" || len(b.Rows) != 0 {
			return errors.New("conditional content must use content blocks only")
		}
		if len(b.Content) == 0 {
			return errors.New("conditional requires at least one content block")
		}
		if _, err := ConditionVariableNames(expression); err != nil {
			return fmt.Errorf("conditional expression: %w", err)
		}
	case TypeRawHTML:
		if b.Text == "" {
			return errors.New("raw_html requires text")
		}
	}
	return nil
}

func validateCanonicalPayload(b *Block) error {
	if b.Type != TypeTable && len(b.Rows) != 0 {
		return errors.New("rows are only valid on table blocks")
	}
	switch b.Type {
	case TypeHeading, TypeParagraph, TypeCode, TypeRawHTML:
		// Text is the canonical payload.
	case TypeListItem, TypeQuote, TypeCallout:
		if b.Text != "" && len(b.Content) != 0 {
			return errors.New("block must use either text or content, not both")
		}
	default:
		if b.Text != "" {
			return errors.New("text is not used by this block type")
		}
	}
	if b.Type == TypeBulletList || b.Type == TypeOrderedList {
		for _, child := range b.Content {
			if child.Type != TypeListItem {
				return errors.New("list content must contain list_item blocks only")
			}
		}
	}

	allowed := allowedAttributes(b.Type)
	for name, value := range b.Attrs {
		kind, ok := allowed[name]
		if !ok {
			return fmt.Errorf("attribute %q is not used by this block type", name)
		}
		switch kind {
		case "string":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("attribute %q must be a string", name)
			}
		case "bool":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("attribute %q must be a boolean", name)
			}
		case "level":
			if _, ok := canonicalHeadingLevel(value); !ok {
				return fmt.Errorf("attribute %q must be an integer", name)
			}
		case "strings":
			items, ok := value.([]any)
			if !ok {
				return fmt.Errorf("attribute %q must be a string array", name)
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("attribute %q must be a string array", name)
				}
			}
		}
	}
	return nil
}

func allowedAttributes(blockType Type) map[string]string {
	switch blockType {
	case TypeHeading:
		return map[string]string{"level": "level"}
	case TypeTable:
		return map[string]string{"columns": "strings"}
	case TypeImage:
		return map[string]string{"storage_key": "string", "alt": "string", "width_pct": "string"}
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		return map[string]string{"recipient_role": "string", "label": "string", "required": "bool"}
	case TypeDynamicVar:
		return map[string]string{"name": "string", "default": "string"}
	case TypeConditional:
		return map[string]string{"expression": "string"}
	case TypeCode:
		return map[string]string{"language": "string"}
	case TypeCallout:
		return map[string]string{"tone": "string"}
	default:
		return map[string]string{}
	}
}

func canonicalHeadingLevel(value any) (int, bool) {
	switch level := value.(type) {
	case int:
		return level, true
	case float64:
		integer := int(level)
		return integer, level == float64(integer)
	default:
		return 0, false
	}
}

func isKnownType(t Type) bool {
	for _, k := range AllTypes() {
		if k == t {
			return true
		}
	}
	return false
}

func generateBlockID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Should never happen on a working system. Fallback ensures we still
		// produce a unique-ish id rather than panic.
		return "blk_" + hex.EncodeToString([]byte("fallback-id"))
	}
	return "blk_" + hex.EncodeToString(b[:])
}

// SchemaJSON returns a JSON-serialised description of the block schema. The
// MCP resource `hash://schema/blocks` exposes this so agents can read the
// rules once at session start and produce valid output.
func SchemaJSON() map[string]any {
	out := map[string]any{
		"version": SchemaVersion,
		"types":   make([]map[string]any, 0, len(AllTypes())),
	}
	for _, t := range AllTypes() {
		entry := map[string]any{
			"type":           string(t),
			"is_container":   t.IsContainer(),
			"is_field":       t.IsField(),
			"required_attrs": typeRequiredAttrs(t),
			"optional_attrs": typeOptionalAttrs(t),
			"description":    typeDescription(t),
		}
		out["types"] = append(out["types"].([]map[string]any), entry)
	}
	return out
}

func typeRequiredAttrs(t Type) []string {
	switch t {
	case TypeHeading:
		return []string{"level"}
	case TypeTable:
		return []string{"columns"}
	case TypeImage:
		return []string{"storage_key"}
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		return []string{"recipient_role"}
	case TypeDynamicVar:
		return []string{"name"}
	case TypeConditional:
		return []string{"expression"}
	}
	return []string{}
}

func typeOptionalAttrs(t Type) []string {
	switch t {
	case TypeImage:
		return []string{"alt", "width_pct"}
	case TypeSignatureField, TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
		return []string{"label", "required"}
	case TypeDynamicVar:
		return []string{"default"}
	case TypeCallout:
		return []string{"tone"}
	case TypeCode:
		return []string{"language"}
	}
	return []string{}
}

func typeDescription(t Type) string {
	switch t {
	case TypeHeading:
		return "Section heading h1-h6, controlled by attrs.level"
	case TypeParagraph:
		return "Paragraph text. Supports {{variable}} substitution"
	case TypeBulletList:
		return "Unordered list; content[] must be list_item blocks"
	case TypeOrderedList:
		return "Ordered list; content[] must be list_item blocks"
	case TypeListItem:
		return "Single list item. Use text or content[] of paragraphs"
	case TypeTable:
		return "Tabular data; attrs.columns:string[], rows:string[][]"
	case TypeImage:
		return "Inline image; attrs.storage_key references a previously uploaded asset"
	case TypeDivider:
		return "Horizontal rule"
	case TypePageBreak:
		return "Forces a page break in the rendered PDF"
	case TypeSignatureField:
		return "Signature placeholder bound to a signer recipient"
	case TypeInitialField:
		return "Initials placeholder bound to a signer recipient"
	case TypeTextField:
		return "Inline fillable text field bound to a signer"
	case TypeDateField:
		return "Inline fillable date field bound to a signer"
	case TypeCheckbox:
		return "Inline checkbox bound to a signer"
	case TypeDynamicVar:
		return "Reference to a document variable; resolved at render time"
	case TypeConditional:
		return "Conditional region; content[] rendered only if expression evaluates truthy"
	case TypeCode:
		return "Monospace code block; attrs.language optional"
	case TypeQuote:
		return "Indented blockquote"
	case TypeCallout:
		return "Highlighted callout box; attrs.tone in (info,warn,note)"
	case TypeRawHTML:
		return "Sanitised raw HTML for power users; passes through bluemonday allowlist"
	}
	return ""
}
