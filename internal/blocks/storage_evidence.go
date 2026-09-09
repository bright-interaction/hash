// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"errors"
	"fmt"
	stdhtml "html"
	"net/url"
	"path"
	"strings"

	xhtml "golang.org/x/net/html"
)

// ErrUnpinnedStorageReference marks block content whose rendered bytes depend
// on an object that is identified only by a mutable key. Drafts may keep these
// authoring references, but a send/finalization boundary must reject them until
// the block schema persists an exact VersionId, SHA-256, and retention proof.
var ErrUnpinnedStorageReference = errors.New("block content contains an external storage reference without immutable version, digest, and retention binding")

// ValidateImmutableSigningEvidence is the canonical release/send/finalization
// gate for a frozen block tree. Besides rejecting mutable storage references,
// it rejects interactive field types whose values are not yet persisted and
// rebound to their block IDs in the immutable signer/final-PDF artifact.
//
// Keep every lifecycle boundary on this one function. A narrower recovery or
// finalization check could otherwise admit a pre-gate document that the current
// send path correctly refuses.
func ValidateImmutableSigningEvidence(tree *Tree) error {
	if err := ValidateNoUnpinnedStorageReferences(tree); err != nil {
		return err
	}
	var validate func([]Block) error
	validate = func(items []Block) error {
		for i := range items {
			block := &items[i]
			switch block.Type {
			case TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox:
				return fmt.Errorf("immutable signing evidence contains unsupported block type %s", block.Type)
			}
			if err := validate(block.Content); err != nil {
				return err
			}
		}
		return nil
	}
	return validate(tree.Blocks)
}

// ValidateNoUnpinnedStorageReferences recursively checks the complete block
// tree. Image blocks always dereference attrs.storage_key. raw_html is checked
// after HTML tokenization so quoted, unquoted, case-varied, and entity-encoded
// URL attributes cannot hide Hash's storage route.
func ValidateNoUnpinnedStorageReferences(tree *Tree) error {
	if tree == nil {
		return errors.New("nil block tree")
	}
	var validate func([]Block) error
	validate = func(items []Block) error {
		for i := range items {
			block := &items[i]
			if block.Type == TypeImage {
				return fmt.Errorf("%w: %s", ErrUnpinnedStorageReference, TypeImage)
			}
			if block.Type == TypeRawHTML && rawHTMLReferencesHashStorage(block.Text) {
				return fmt.Errorf("%w: %s", ErrUnpinnedStorageReference, TypeRawHTML)
			}
			if err := validate(block.Content); err != nil {
				return err
			}
		}
		return nil
	}
	return validate(tree.Blocks)
}

var rawHTMLResourceAttributes = map[string]bool{
	"src": true, "href": true, "srcset": true, "poster": true,
	"background": true, "cite": true, "data": true, "formaction": true,
	"action": true, "style": true,
}

func rawHTMLReferencesHashStorage(raw string) bool {
	doc, err := xhtml.Parse(strings.NewReader("<html><body>" + raw + "</body></html>"))
	if err != nil {
		// A malformed fragment has no production-safe immutable interpretation.
		return true
	}
	var found bool
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node == nil || found {
			return
		}
		if node.Type == xhtml.ElementNode {
			for _, attr := range node.Attr {
				if !rawHTMLResourceAttributes[strings.ToLower(attr.Key)] {
					continue
				}
				if normalizedStorageReference(attr.Val) {
					found = true
					return
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return found
}

func normalizedStorageReference(value string) bool {
	value = stdhtml.UnescapeString(value)
	for i := 0; i < 8; i++ {
		decoded, err := url.PathUnescape(value)
		if err != nil {
			// Browsers, reverse proxies, and Go's HTTP routing can disagree on a
			// malformed escape. It has no safe immutable interpretation here.
			return true
		}
		if decoded == value {
			break
		}
		value = stdhtml.UnescapeString(decoded)
	}
	value = strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	value = strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if hashStoragePath(value) {
		return true
	}
	// Chromium resolves RFC-style dot segments before issuing a request. Split
	// resource-set and CSS-url punctuation conservatively, parse each candidate,
	// and clean its path so `/api/v1/x/../storage/key` cannot bypass the gate.
	for _, candidate := range strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', '(', ')', '\'', '"', ';':
			return true
		default:
			return r <= ' '
		}
	}) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err == nil && hashStoragePath(path.Clean(parsed.Path)) {
			return true
		}
		if hashStoragePath(path.Clean(candidate)) {
			return true
		}
	}
	return false
}

func hashStoragePath(value string) bool {
	return strings.Contains(value, "api/v1/storage/") || strings.HasSuffix(value, "api/v1/storage")
}
