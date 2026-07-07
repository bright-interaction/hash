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

// APIKeyFormat is `mth_<prefix>_<secret>`. Prefix is 8 hex chars; secret is
// 32 base64url chars (24 bytes of entropy). Hash stored in DB is the
// sha256 of the full key (bytes).
type MintedKey struct {
	Plaintext string // returned to caller once; never stored
	Prefix    string
	Hash      []byte
}

// MintAPIKey generates a new API key. Caller stores Prefix + Hash; returns
// Plaintext to the user exactly once.
func MintAPIKey() (*MintedKey, error) {
	prefBytes := make([]byte, 4)
	if _, err := rand.Read(prefBytes); err != nil {
		return nil, err
	}
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	prefix := hex.EncodeToString(prefBytes)
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
	if len(parts) != 2 || len(parts[0]) != 8 || parts[1] == "" {
		return "", nil, errors.New("malformed api key")
	}
	return parts[0], []byte(k), nil
}

// APIKeyVerifier looks up and verifies API keys against persistent storage.
// The DB layer implements LookupByPrefix. The DocScopeID return is
// uuid.Nil for org-wide keys; non-nil for per-document agent tokens
// (v1.1) and triggers the DocumentScopeKey context injection.
type APIKeyVerifier interface {
	LookupByPrefix(ctx context.Context, prefix string) (id uuid.UUID, userID uuid.UUID, orgID uuid.UUID, role string, email string, hash []byte, docScopeID uuid.UUID, scopes []string, err error)
	Touch(ctx context.Context, id uuid.UUID) error
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
			// Best-effort touch; never block the request on it.
			go func() {
				_ = v.Touch(context.Background(), id)
			}()
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, userID)
			ctx = context.WithValue(ctx, OrgIDKey, orgID)
			ctx = context.WithValue(ctx, RoleKey, role)
			ctx = context.WithValue(ctx, EmailKey, email)
			if len(scopes) > 0 {
				ctx = context.WithValue(ctx, TokenScopesKey, scopes)
			}
			if docScopeID != uuid.Nil {
				ctx = context.WithValue(ctx, DocumentScopeKey, docScopeID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
