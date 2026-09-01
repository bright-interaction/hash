// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
)

// byoaiDefaultHost is the host a blank per-org base_url resolves to for each
// provider (both are NON-EU defaults, so a blank base_url is rejected in prod by
// the EU allow-list check).
func byoaiDefaultHost(provider string) string {
	switch provider {
	case "mistral":
		return "openrouter.ai"
	default:
		return "api.anthropic.com"
	}
}

// validateBYOAIBaseURL enforces, at the write boundary, that a per-org BYOAI
// endpoint (1) is on the EU allow-list (sovereignty: tokenized-but-identifying
// document text must not cross to a non-EU jurisdiction) and (2) is not an SSRF
// target (no private/loopback/link-local, https in prod). The instance-default
// endpoints are validated at boot; the per-org row was never checked. Skipped in
// local dev so localhost LLMs work.
func (s *Server) validateBYOAIBaseURL(provider, baseURL string) error {
	dev := config.IsLocalDevelopment(s.PublicURL)
	host := byoaiDefaultHost(provider)
	if strings.TrimSpace(baseURL) != "" {
		u, err := url.Parse(strings.TrimSpace(baseURL))
		if err != nil || u.Hostname() == "" {
			return errors.New("base_url is not a valid URL")
		}
		host = strings.ToLower(u.Hostname())
		// SSRF guard (reuse the webhook validator: https-in-prod + no private IPs).
		if err := dispatch.ValidateWebhookURL(baseURL, dev); err != nil {
			return fmt.Errorf("base_url rejected: %w", err)
		}
	}
	if !dev && !config.IsEUEndpoint(host, s.AIEUHosts) {
		return fmt.Errorf("base_url host %q is not on the EU allow-list; per-org AI must use an EU endpoint so document text never leaves the EU", host)
	}
	return nil
}

// Per-org "bring your own AI" provider config.
//
//   GET    /api/v1/ai/provider   read the org's config (key never returned)
//   PUT    /api/v1/ai/provider   set/update provider + key (key sealed at rest)
//   DELETE /api/v1/ai/provider   remove it (org falls back to instance default)
//
// The plaintext key is accepted once on PUT, AES-256-GCM sealed under the
// instance shield key, and never read back out: GET returns only the last
// four characters as a hint. A blank api_key on PUT keeps the current key so
// the org can flip enabled / change model without re-entering the secret.

type orgAIProviderResponse struct {
	Configured     bool   `json:"configured"`
	ByoaiAvailable bool   `json:"byoai_available"`
	Provider       string `json:"provider,omitempty"`
	BaseURL        string `json:"base_url,omitempty"`
	Model          string `json:"model,omitempty"`
	Enabled        bool   `json:"enabled"`
	KeyLast4       string `json:"key_last4,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

func (s *Server) handleGetOrgAIProvider(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	avail := len(s.AISealKey) == 32
	row, err := s.Queries.GetOrgAISettings(r.Context(), u.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, orgAIProviderResponse{Configured: false, ByoaiAvailable: avail})
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orgAIProviderResponse{
		Configured:     true,
		ByoaiAvailable: avail,
		Provider:       row.Provider,
		BaseURL:        row.BaseUrl,
		Model:          row.Model,
		Enabled:        row.Enabled,
		KeyLast4:       row.KeyLast4,
		UpdatedAt:      row.UpdatedAt.Time.UTC().Format(time.RFC3339),
	})
}

type setOrgAIProviderInput struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"`
	Enabled  *bool  `json:"enabled"`
}

func (s *Server) handleSetOrgAIProvider(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if len(s.AISealKey) != 32 {
		writeError(w, http.StatusServiceUnavailable,
			"BYOAI unavailable: this instance has no AI shield key configured to encrypt your key at rest")
		return
	}
	var in setOrgAIProviderInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch in.Provider {
	case "anthropic", "mistral":
	default:
		writeError(w, http.StatusBadRequest, "provider must be 'anthropic' or 'mistral'")
		return
	}
	if err := s.validateBYOAIBaseURL(in.Provider, in.BaseURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	// Resolve the ciphertext: a new key is sealed now; a blank key reuses the
	// stored one (so edits that don't touch the secret are possible).
	var ct []byte
	var last4 string
	if in.APIKey != "" {
		sealed, err := ai.AESEncrypt(s.AISealKey, []byte(in.APIKey))
		if err != nil {
			writeInternalErrorMsg(w, "seal key", err)
			return
		}
		ct = sealed
		last4 = lastN(in.APIKey, 4)
	} else {
		existing, err := s.Queries.GetOrgAISettings(r.Context(), u.OrgID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "api_key required for a new provider config")
			return
		}
		if err != nil {
			writeInternalError(w, err)
			return
		}
		ct = existing.ApiKeyCt
		last4 = existing.KeyLast4
	}

	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.OrgAiSetting, error) {
			return q.UpsertOrgAISettings(r.Context(), generated.UpsertOrgAISettingsParams{
				OrgID:    u.OrgID,
				Provider: in.Provider,
				BaseUrl:  in.BaseURL,
				Model:    in.Model,
				ApiKeyCt: ct,
				KeyLast4: last4,
				Enabled:  enabled,
			})
		},
		func(row *generated.OrgAiSetting) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind: "ai_provider.updated",
				IP:   clientIP(r),
				// Never log key material; provider + model + enabled only.
				Payload: map[string]any{"provider": row.Provider, "model": row.Model, "enabled": row.Enabled},
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orgAIProviderResponse{
		Configured:     true,
		ByoaiAvailable: true,
		Provider:       row.Provider,
		BaseURL:        row.BaseUrl,
		Model:          row.Model,
		Enabled:        row.Enabled,
		KeyLast4:       row.KeyLast4,
		UpdatedAt:      row.UpdatedAt.Time.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleDeleteOrgAIProvider(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	_, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (uuid.UUID, error) {
			return u.OrgID, q.DeleteOrgAISettings(r.Context(), u.OrgID)
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind: "ai_provider.deleted",
				IP:   clientIP(r),
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// lastN returns the last n characters of s (or all of s if shorter).
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
