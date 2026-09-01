// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package qes

import (
	"context"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/qes/trustlist"
)

// Engine retains the legacy provider/database wiring for source compatibility.
// It is not wired into the HTTP or MCP servers in this release, and every
// lifecycle method below fails closed before touching either dependency.
type Engine struct {
	Queries  *generated.Queries
	Provider Provider
	// PublicBaseURL and TrustList are retained for migration compatibility;
	// neither activates a ceremony.
	PublicBaseURL string
	TrustList     *trustlist.Validator
}

// New constructs an Engine. If provider is nil, falls back to
// NoopProvider so callers always get a non-nil Engine.
func New(q *generated.Queries, provider Provider, publicBaseURL string) *Engine {
	if provider == nil {
		provider = NoopProvider{}
	}
	return &Engine{Queries: q, Provider: provider, PublicBaseURL: publicBaseURL}
}

// StartSession is retained only as a source-compatible fail-closed boundary.
// No current Hash release may create or advance a QES session. A future QES
// implementation must replace this method with digest verification and atomic
// proof consumption rather than reactivating the legacy provider flow.
func (e *Engine) StartSession(context.Context, StartInput, uuid.UUID) (*Session, error) {
	return nil, ErrCeremonyUnavailable
}

// CompleteCallback cannot consume provider callbacks in this release.
func (e *Engine) CompleteCallback(context.Context, string, []byte, map[string]string) (*Session, *CallbackResult, error) {
	return nil, nil, ErrCeremonyUnavailable
}

// MostRecentForRecipient cannot be used to poll or resume a legacy ceremony.
func (e *Engine) MostRecentForRecipient(context.Context, uuid.UUID) (*Session, error) {
	return nil, ErrCeremonyUnavailable
}
