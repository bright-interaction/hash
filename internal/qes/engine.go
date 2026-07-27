// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package qes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/qes/trustlist"
)

// Engine wires the Provider + database. Hold one process-wide; pass via
// handler/server.Server. Engine is nil-safe at the handler boundary so
// a missing Provider config doesn't blow up routing.
type Engine struct {
	Queries  *generated.Queries
	Provider Provider
	// PublicBaseURL is the externally-reachable Hash URL, used to
	// build the callback URL handed to the QTSP. Required because the
	// QTSP's hosted UI can't reach localhost.
	PublicBaseURL string
	// TrustList is the QTSP root cert allow-list. nil disables the
	// gate (acceptance with a warning); non-nil rejects any chain
	// whose root is not on the list with ErrRootNotTrusted.
	TrustList *trustlist.Validator
}

// New constructs an Engine. If provider is nil, falls back to
// NoopProvider so callers always get a non-nil Engine.
func New(q *generated.Queries, provider Provider, publicBaseURL string) *Engine {
	if provider == nil {
		provider = NoopProvider{}
	}
	return &Engine{Queries: q, Provider: provider, PublicBaseURL: publicBaseURL}
}

// StartSession kicks off a QES signing challenge for the given
// recipient. Persists a qes_signing_sessions row + returns the
// caller-facing redirect URL. The caller is the /sign/{token}/qes/start
// handler.
func (e *Engine) StartSession(ctx context.Context, in StartInput, orgID uuid.UUID) (*Session, error) {
	if e == nil || e.Provider == nil {
		return nil, ErrDisabled
	}
	if e.Provider.Name() == "noop" {
		return nil, ErrDisabled
	}
	res, err := e.Provider.Start(ctx, in)
	if err != nil {
		return nil, err
	}
	row, err := e.Queries.CreateQESSession(ctx, generated.CreateQESSessionParams{
		DocumentID:        in.DocumentID,
		RecipientID:       in.RecipientID,
		OrgID:             orgID,
		Provider:          e.Provider.Name(),
		ProviderSessionID: res.ProviderSessionID,
		RedirectUrl:       pgtype.Text{String: res.RedirectURL, Valid: res.RedirectURL != ""},
		CallbackSecret:    res.CallbackSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("qes: persist session: %w", err)
	}
	// Optimistically flip to redirected; the caller is about to send a
	// 303 to the signer.
	_ = e.Queries.MarkQESSessionRedirected(ctx, row.ID)
	return toSession(row), nil
}

// CompleteCallback validates the QTSP callback + persists the
// resulting identity assertion + signature. Returns the completed
// Session so the caller can drive the existing sign engine's "Sign()"
// path to flip status + render the final PDF.
func (e *Engine) CompleteCallback(ctx context.Context, providerSessionID string, raw []byte, headers map[string]string) (*Session, *CallbackResult, error) {
	if e == nil || e.Provider == nil {
		return nil, nil, ErrDisabled
	}
	row, err := e.Queries.GetQESSessionByProvider(ctx, generated.GetQESSessionByProviderParams{
		Provider:          e.Provider.Name(),
		ProviderSessionID: providerSessionID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errors.New("qes: session not found")
		}
		return nil, nil, err
	}
	if row.Status == "completed" {
		// Idempotent: the QTSP retried a callback we already processed.
		return toSession(row), &CallbackResult{
			SignatureB64: row.SignatureB64.String,
			CertChainPEM: row.CertChainPem.String,
		}, nil
	}
	if row.ExpiresAt.Time.Before(time.Now()) {
		_ = e.Queries.FailQESSession(ctx, generated.FailQESSessionParams{
			ID:            row.ID,
			FailureReason: pgtype.Text{String: "expired", Valid: true},
		})
		return nil, nil, ErrSessionExpired
	}
	result, err := e.Provider.Callback(ctx, CallbackInput{
		ProviderSessionID: providerSessionID,
		CallbackSecret:    row.CallbackSecret,
		RawBody:           raw,
		Headers:           headers,
	})
	if err != nil {
		_ = e.Queries.FailQESSession(ctx, generated.FailQESSessionParams{
			ID:            row.ID,
			FailureReason: pgtype.Text{String: err.Error(), Valid: true},
		})
		return nil, nil, err
	}
	if !json.Valid(result.IdentityAssertion) {
		// Wrap raw bytes into a JSON string so the column always holds
		// valid JSON, never a half-parsed assertion we'd lose later.
		wrapped, _ := json.Marshal(map[string]string{"raw": string(result.IdentityAssertion)})
		result.IdentityAssertion = wrapped
	}

	// EU Trust List gate (carryover #19). When a curated allow-list is
	// configured, the chain's root must be on it. An unconfigured
	// validator (nil) logs a warning and accepts so dev + e2e against
	// the MockProvider keep working without a real Idura cert.
	if e.TrustList != nil {
		// The mock provider is dev/e2e only (production refuses to boot on
		// it - see config boot guard), and emits a non-x509 sentinel chain.
		// Reaching here with the mock provider means local dev with a trust
		// list set; skip validation rather than reject the sentinel.
		if e.Provider.Name() == "mock" {
			slog.Warn("qes: mock provider chain skipped trust-list validation (dev only)", "session_id", row.ID)
		} else {
			// A real QTSP MUST present a cert chain. An empty/absent chain is
			// a hard failure, never a silent skip: otherwise an attacker who
			// satisfies the callback HMAC could complete a "Qualified
			// Electronic Signature" with no chain at all.
			if result.CertChainPEM == "" {
				_ = e.Queries.FailQESSession(ctx, generated.FailQESSessionParams{
					ID:            row.ID,
					FailureReason: pgtype.Text{String: "trustlist: empty cert chain on QES completion", Valid: true},
				})
				return nil, nil, errors.New("qes: cert chain required when trust list is enforced")
			}
			matched, vErr := e.TrustList.ValidateChain(result.CertChainPEM)
			if vErr != nil {
				_ = e.Queries.FailQESSession(ctx, generated.FailQESSessionParams{
					ID:            row.ID,
					FailureReason: pgtype.Text{String: "trustlist: " + vErr.Error(), Valid: true},
				})
				return nil, nil, fmt.Errorf("qes: cert chain rejected: %w", vErr)
			}
			if matched != nil {
				slog.Info("qes: cert chain accepted against trust list",
					"qtsp", matched.QTSP, "country", matched.Country, "session_id", row.ID)
			}
		}
	} else if result.CertChainPEM != "" {
		slog.Warn("qes: cert chain accepted WITHOUT trust list validation",
			"session_id", row.ID,
			"hint", "set HASH_QES_TRUST_LIST_PATH to enforce")
	}

	completed, err := e.Queries.CompleteQESSession(ctx, generated.CompleteQESSessionParams{
		ID:                    row.ID,
		IdentityAssertionJson: result.IdentityAssertion,
		SignatureB64:          pgtype.Text{String: result.SignatureB64, Valid: true},
		CertChainPem:          pgtype.Text{String: result.CertChainPEM, Valid: result.CertChainPEM != ""},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("qes: persist completion: %w", err)
	}
	return toSession(completed), result, nil
}

// GetSession returns the current state of a session for status-poll
// endpoints + MCP observability tools.
func (e *Engine) GetSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	row, err := e.Queries.GetQESSession(ctx, id)
	if err != nil {
		return nil, err
	}
	return toSession(row), nil
}

// MostRecentForRecipient returns the latest pending/redirected session
// for the recipient, used so the signer page can resume in-progress
// challenges after a tab reload.
func (e *Engine) MostRecentForRecipient(ctx context.Context, recipientID uuid.UUID) (*Session, error) {
	rows, err := e.Queries.ListPendingQESSessionsForRecipient(ctx, recipientID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, pgx.ErrNoRows
	}
	return toSession(rows[0]), nil
}

func toSession(r *generated.QesSigningSession) *Session {
	s := &Session{
		ID:                r.ID,
		DocumentID:        r.DocumentID,
		RecipientID:       r.RecipientID,
		OrgID:             r.OrgID,
		Provider:          r.Provider,
		ProviderSessionID: r.ProviderSessionID,
		Status:            r.Status,
		RedirectURL:       r.RedirectUrl.String,
		CallbackSecret:    r.CallbackSecret,
		ExpiresAt:         r.ExpiresAt.Time,
	}
	if r.CompletedAt.Valid {
		t := r.CompletedAt.Time
		s.CompletedAt = &t
	}
	return s
}
