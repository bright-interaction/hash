// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// APIKeyFormat is `mth_<prefix>_<secret>`. New credentials use a type-prefixed
// 128-bit routing prefix (`a` for org API keys and `d` for document-agent
// tokens); the secret is 32 base64url chars (24 bytes of entropy). Hash stored
// in DB is the sha256 of the full key (bytes).
//
// Eight-hex-character prefixes remain parseable for already-issued legacy
// credentials. They are never minted again: 32 bits was too small for a shared
// lookup namespace and a collision could make an otherwise valid key
// unavailable.
type MintedKey struct {
	Plaintext string // returned to caller once; never stored
	Prefix    string
	Hash      []byte
}

// MintAPIKey generates a new API key. Caller stores Prefix + Hash; returns
// Plaintext to the user exactly once.
const (
	apiKeyPrefixNamespace      = "a"
	documentTokenNamespace     = "d"
	credentialPrefixEntropyLen = 16
)

func MintAPIKey() (*MintedKey, error) {
	return mintNamespacedKey(apiKeyPrefixNamespace)
}

// MintDocumentAgentKey gives document-scoped credentials a disjoint routing
// namespace from org-wide API keys. This prevents one credential table from
// shadowing the other even if a random prefix collision occurs.
func MintDocumentAgentKey() (*MintedKey, error) {
	return mintNamespacedKey(documentTokenNamespace)
}

func mintNamespacedKey(namespace string) (*MintedKey, error) {
	if namespace != apiKeyPrefixNamespace && namespace != documentTokenNamespace {
		return nil, errors.New("unsupported credential namespace")
	}
	prefBytes := make([]byte, credentialPrefixEntropyLen)
	if _, err := rand.Read(prefBytes); err != nil {
		return nil, err
	}
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	prefix := namespace + hex.EncodeToString(prefBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	plain := "mth_" + prefix + "_" + secret
	hash := sha256.Sum256([]byte(plain))
	return &MintedKey{Plaintext: plain, Prefix: prefix, Hash: hash[:]}, nil
}

// ParseAPIKey splits an inbound key into prefix and full-bytes for hashing.
func ParseAPIKey(k string) (prefix string, fullBytes []byte, err error) {
	if !strings.HasPrefix(k, "mth_") {
		return "", nil, errors.New("api key missing mth_ prefix")
	}
	rest := strings.TrimPrefix(k, "mth_")
	parts := strings.SplitN(rest, "_", 2)
	if len(parts) != 2 || !validCredentialPrefix(parts[0]) || parts[1] == "" {
		return "", nil, errors.New("malformed api key")
	}
	return parts[0], []byte(k), nil
}

func validCredentialPrefix(prefix string) bool {
	hexPart := prefix
	if credentialNamespace(prefix) != "" {
		hexPart = prefix[1:]
	} else if len(prefix) != 8 { // compatibility for already-issued v1 keys
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func credentialNamespace(prefix string) string {
	if len(prefix) != 1+credentialPrefixEntropyLen*2 {
		return ""
	}
	if prefix[0:1] == apiKeyPrefixNamespace || prefix[0:1] == documentTokenNamespace {
		return prefix[0:1]
	}
	return ""
}

// APIKeyVerifier looks up and verifies API keys against persistent storage.
// The DB layer implements LookupByPrefix. The DocScopeID return is
// uuid.Nil for org-wide keys; non-nil for per-document agent tokens
// (v1.1) and triggers the DocumentScopeKey context injection.
type APIKeyVerifier interface {
	LookupByPrefix(ctx context.Context, prefix string) (id uuid.UUID, userID uuid.UUID, orgID uuid.UUID, role string, email string, hash []byte, docScopeID uuid.UUID, scopes []string, err error)
	Claim(ctx context.Context, id, docScopeID uuid.UUID) error
}

// RequireAPIKey is the middleware for MCP endpoints. It enforces a Bearer
// token whose hash matches a row in api_keys, and injects identity into the
// context the same way RequireSession does so downstream handlers see one
// consistent shape.
func RequireAPIKey(v APIKeyVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				// Fall back to the X-API-Key header used by Claude Code's
				// MCP HTTP transport.
				if k := r.Header.Get("X-API-Key"); k != "" {
					authz = "Bearer " + k
				} else {
					http.Error(w, "missing bearer token", http.StatusUnauthorized)
					return
				}
			}
			token := strings.TrimPrefix(authz, "Bearer ")
			prefix, _, err := ParseAPIKey(token)
			if err != nil {
				http.Error(w, "malformed token", http.StatusUnauthorized)
				return
			}
			id, userID, orgID, role, email, storedHash, docScopeID, scopes, err := v.LookupByPrefix(r.Context(), prefix)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			incoming := sha256.Sum256([]byte(token))
			if subtle.ConstantTimeCompare(storedHash, incoming[:]) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// A document-token use is an authorization decision, not telemetry:
			// synchronously claim it after verifying the secret and before invoking
			// the handler. The database claim atomically rechecks expiry,
			// revocation, and max_uses so concurrent requests cannot oversubscribe
			// a capped token.
			if err := v.Claim(r.Context(), id, docScopeID); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, userID)
			ctx = context.WithValue(ctx, OrgIDKey, orgID)
			ctx = context.WithValue(ctx, RoleKey, role)
			ctx = context.WithValue(ctx, EmailKey, email)
			// Presence distinguishes API-token requests from human cookie sessions.
			// Always attach the value, including an empty/corrupt DB array, so a
			// malformed token record fails closed instead of inheriting full session
			// privileges.
			ctx = context.WithValue(ctx, TokenScopesKey, scopes)
			if docScopeID != uuid.Nil {
				ctx = context.WithValue(ctx, DocumentScopeKey, docScopeID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
