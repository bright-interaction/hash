package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/config"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/sign"
)

// signerPEM returns the ed25519 public key in PEM form for the evidence
// bundle. Returns "" if no signer is configured so the bundle still
// produces but the public-key.pem attachment is empty.
func signerPEM(s *sign.CertSigner) string {
	if s == nil {
		return ""
	}
	return s.PublicKeyPEM()
}

// aiSealKey returns the decoded 32-byte shield key used to seal per-org
// BYOAI provider keys at rest, or nil when none is configured. The hex was
// already validated by buildAIRuntime, so a decode error here just yields a
// nil key (BYOAI stays disabled).
func aiSealKey(cfg *config.Config) []byte {
	if cfg.AIShieldKey == "" {
		return nil
	}
	raw, _ := hex.DecodeString(cfg.AIShieldKey)
	return raw
}

// buildAIRuntime assembles the Phase 8.4 ai.Runtime from config. It is
// deliberately permissive: missing creds, missing shield key, missing
// providers, all degrade to a runtime that boots but reports them in
// Status() so operators can spot the gap.
func buildAIRuntime(cfg *config.Config, q *generated.Queries) (*ai.Runtime, error) {
	// Shield: 64 hex chars (32 bytes) decoded; empty key disables shield
	// and falls through to NoopShield (audit log shows shield_active=false).
	var shield ai.Shield = ai.NoopShield{}
	if cfg.AIShieldKey != "" {
		raw, err := hex.DecodeString(cfg.AIShieldKey)
		if err != nil {
			return nil, fmt.Errorf("HASH_AI_SHIELD_KEY must be hex: %w", err)
		}
		s, err := ai.NewLocalShield(raw)
		if err != nil {
			return nil, err
		}
		shield = s
	}

	// Providers: register everything we can; default is plan-recommended
	// 'mistral' unless overridden by config.
	providers := []ai.Provider{}
	// allowPrivate gates the SSRF guard on outbound AI calls: false in prod so a
	// (rebound) BYOAI base_url can't reach an internal IP; true only in local dev.
	allowPrivate := config.IsLocalDevelopment(cfg.PublicURL)
	if cfg.MistralAPIKey != "" || cfg.MistralBaseURL != "" {
		providers = append(providers, ai.NewMistralProvider(
			cfg.MistralBaseURL, cfg.MistralAPIKey, cfg.MistralModel, allowPrivate,
		))
	}
	if cfg.AnthropicAPIKey != "" || cfg.AnthropicBaseURL != "" {
		providers = append(providers, ai.NewAnthropicProvider(
			cfg.AnthropicBaseURL, cfg.AnthropicAPIKey, cfg.AnthropicModel, allowPrivate,
		))
	}

	// Embedder: HashEmbedder ships as the default deterministic stand-in
	// so block-embedding storage + retrieval can be exercised end-to-end
	// without a model server. Phase 11.1 swaps in BGE-M3.
	rt := ai.New(q, shield, ai.HashEmbedder{Dim: 64}, providers...)

	// Honour the default-provider override (plan-recommended Mistral wins
	// alphabetical iteration, but we lock it explicitly so the test stack
	// can switch to Anthropic via env).
	if cfg.AIDefaultProvider != "" {
		if _, ok := rt.Providers[cfg.AIDefaultProvider]; ok {
			rt.Default = cfg.AIDefaultProvider
		}
	}

	// BYOAI: when an org has stored its own provider + key, route that org's
	// completions to it. The key is sealed under the shield key, so this is
	// only wired when a shield key is configured; without one we cannot
	// decrypt stored keys and BYOAI stays off (the settings handler reports
	// the same). A nil resolver leaves the instance-default path unchanged.
	if cfg.AIShieldKey != "" {
		keyRaw, _ := hex.DecodeString(cfg.AIShieldKey) // validated above
		rt.ResolveOrgProvider = func(ctx context.Context, orgID uuid.UUID) (ai.Provider, bool) {
			row, err := q.GetOrgAISettings(ctx, orgID)
			if err != nil || row == nil || !row.Enabled {
				return nil, false
			}
			plain, err := ai.AESDecrypt(keyRaw, row.ApiKeyCt)
			if err != nil {
				return nil, false
			}
			switch row.Provider {
			case "anthropic":
				return ai.NewAnthropicProvider(row.BaseUrl, string(plain), row.Model, allowPrivate), true
			case "mistral":
				return ai.NewMistralProvider(row.BaseUrl, string(plain), row.Model, allowPrivate), true
			}
			return nil, false
		}
	}
	return rt, nil
}
