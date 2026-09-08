// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package templatepin defines the canonical content commitment used to bind
// automation commands to an operator-reviewed block-template snapshot.
package templatepin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bright-interaction/hash/internal/blocks"
)

// DigestDomain separates template commitments from every other SHA-256 value
// in Hash. The NUL terminator is part of the hashed byte sequence.
const DigestDomain = "hash:template-content:v1\x00"

// Content is a validated, deterministic view of a persisted blocks template.
// Callers must materialize BlocksJSON and DefaultVariables from this value so
// the bytes they use are the same content whose digest they checked.
type Content struct {
	BlocksJSON       json.RawMessage
	DefaultVariables map[string]string
	VariablesJSON    json.RawMessage
	SHA256           [sha256.Size]byte
}

// Canonicalize validates that block IDs are already persisted, normalizes the
// typed block tree, sorts default-variable object keys through encoding/json,
// and commits to the canonical JSON envelope:
//
//	{"blocks":<canonical-block-tree>,"variables":<canonical-defaults>}
//
// Templates are normalized when authored. Refusing a legacy tree with missing
// IDs here is important: assigning random IDs while calculating a pin would
// make the advertised commitment change between otherwise identical reads.
func Canonicalize(blocksJSON, variablesJSON []byte) (Content, error) {
	tree, err := blocks.ParseCanonicalTree(blocksJSON)
	if err != nil {
		return Content{}, fmt.Errorf("canonical block tree: %w", err)
	}
	canonicalBlocks, err := json.Marshal(tree)
	if err != nil {
		return Content{}, fmt.Errorf("encode canonical block tree: %w", err)
	}
	defaultVariables, err := blocks.ParseVariableValues(variablesJSON)
	if err != nil {
		return Content{}, fmt.Errorf("canonical default variables: %w", err)
	}
	canonicalVariables, err := json.Marshal(defaultVariables)
	if err != nil {
		return Content{}, fmt.Errorf("encode canonical default variables: %w", err)
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(DigestDomain))
	_, _ = hasher.Write([]byte(`{"blocks":`))
	_, _ = hasher.Write(canonicalBlocks)
	_, _ = hasher.Write([]byte(`,"variables":`))
	_, _ = hasher.Write(canonicalVariables)
	_, _ = hasher.Write([]byte(`}`))
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))

	return Content{
		BlocksJSON:       canonicalBlocks,
		DefaultVariables: defaultVariables,
		VariablesJSON:    canonicalVariables,
		SHA256:           digest,
	}, nil
}

// SHA256Hex returns the lowercase, fixed-width request/response representation
// of the content commitment.
func (c Content) SHA256Hex() string {
	return hex.EncodeToString(c.SHA256[:])
}
