// Package auth provides sender-session and signer-token helpers.
//
// Senders authenticate via Zitadel OIDC; the resulting session is a signed
// cookie we mint server-side. Signers use magic links ,  a UUID + HMAC stored
// hashed in the recipients table.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ContextKey is a typed key for context values.
type ContextKey string

const (
	UserIDKey        ContextKey = "hash.user_id"
	OrgIDKey         ContextKey = "hash.org_id"
	RoleKey          ContextKey = "hash.role"
	EmailKey         ContextKey = "hash.email"
	DocumentScopeKey ContextKey = "hash.doc_scope" // present iff a per-doc agent token authenticated this request
	TokenScopesKey   ContextKey = "hash.token_scopes"
)

// DocumentScopeFromContext returns the document UUID this request is
// scoped to (set by the per-doc agent token middleware) plus true. When
// false, the caller is NOT scoped to a single document and any tool
// that respects the scope should treat the call as org-wide.
func DocumentScopeFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(DocumentScopeKey).(uuid.UUID)
	if !ok || v == uuid.Nil {
		return uuid.Nil, false
	}
	return v, true
}

// EnforceDocScope is the helper MCP tool handlers call before they
// operate on a document. If the request authenticated with a per-doc
// token, this returns an error when target != that document. Org-wide
// API keys always pass.
func EnforceDocScope(ctx context.Context, target uuid.UUID) error {
	scope, ok := DocumentScopeFromContext(ctx)
	if !ok {
		return nil
	}
	if scope != target {
		return ErrDocScopeMismatch
	}
	return nil
}

// ErrDocScopeMismatch is returned by EnforceDocScope when the caller's
// per-doc token is bound to a different document than the one the tool
// is operating on. MCP handlers surface this as a clear refusal.
var ErrDocScopeMismatch = errors.New("auth: token is scoped to a different document")

// ErrScopeForbidden is returned when an API token lacks a required scope
// (e.g. a read-only token attempting a write operation).
var ErrScopeForbidden = errors.New("auth: token lacks the required scope")

// TokenScopesFromContext returns the scope set the authenticating API token
// carries, and whether any scope set is present. Session-cookie callers carry
// no scope set (ok == false) and are treated as full-access.
func TokenScopesFromContext(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(TokenScopesKey).([]string)
	return v, ok
}

// HasScope reports whether the request's token grants the wanted scope. A
// request with NO scope set attached (human session-cookie callers, and
// legacy keys before the scopes column was populated) is treated as
// full-access so the UI is never gated; only scoped API/MCP tokens are
// constrained. The "admin" scope implies every scope.
func HasScope(ctx context.Context, want string) bool {
	scopes, ok := ctx.Value(TokenScopesKey).([]string)
	if !ok || len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == want || s == "admin" {
			return true
		}
	}
	return false
}

// EnforceScope returns ErrScopeForbidden when the token lacks the wanted scope.
func EnforceScope(ctx context.Context, want string) error {
	if !HasScope(ctx, want) {
		return ErrScopeForbidden
	}
	return nil
}

// HasWriteScope reports whether the token may perform write operations. The
// scope vocabulary is granular (write:authoring, write:workflow); any of them,
// a bare "write", or "admin" grants writes. A request with no scope set
// (session-cookie callers, legacy keys) is full-access. A token holding only
// "read" is refused. This is the read-vs-write boundary the MCP dispatch
// enforces for write tools.
func HasWriteScope(ctx context.Context) bool {
	scopes, ok := ctx.Value(TokenScopesKey).([]string)
	if !ok || len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == "write" || s == "admin" || strings.HasPrefix(s, "write:") {
			return true
		}
	}
	return false
}

// SessionUser holds identity we attach to the request context after auth.
type SessionUser struct {
	UserID uuid.UUID
	OrgID  uuid.UUID
	Role   string
	Email  string
}

// FromContext extracts the session user. Returns false if not authenticated.
func FromContext(ctx context.Context) (SessionUser, bool) {
	uid, ok := ctx.Value(UserIDKey).(uuid.UUID)
	if !ok || uid == uuid.Nil {
		return SessionUser{}, false
	}
	oid, _ := ctx.Value(OrgIDKey).(uuid.UUID)
	role, _ := ctx.Value(RoleKey).(string)
	email, _ := ctx.Value(EmailKey).(string)
	return SessionUser{UserID: uid, OrgID: oid, Role: role, Email: email}, true
}

// MintMagicToken generates a recipient signing link token and returns
// (token-as-shown-in-URL, sha256-of-token-for-DB-storage). The token itself
// is 32 random bytes base64url-encoded; the HMAC binding to recipient happens
// server-side at verification time by looking up by sha256.
func MintMagicToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

// HashMagicToken computes the SHA-256 of an inbound token so we can do a
// constant-time lookup against the stored hash.
func HashMagicToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// SignedCookie is a tiny session cookie scheme: hex(hmac) | "." |
// base64(payload). Avoids pulling in a session library for week 1; we'll
// migrate to gorilla/sessions or scs once we wire OIDC end-to-end.
type SignedCookie struct {
	key []byte
}

func NewSignedCookie(hexKey string) (*SignedCookie, error) {
	k, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(k) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	return &SignedCookie{key: k}, nil
}

func (s *SignedCookie) Mint(payload []byte, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	body := append([]byte{}, payload...)
	body = appendInt64(body, exp)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(body)
	tag := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(tag)
}

// Verify returns the original payload bytes if the signature and expiry are
// valid; an error otherwise.
func (s *SignedCookie) Verify(token string) ([]byte, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed token")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return nil, errors.New("bad signature")
	}
	if len(body) < 8 {
		return nil, errors.New("body too short")
	}
	exp := readInt64(body[len(body)-8:])
	if time.Now().Unix() > exp {
		return nil, errors.New("expired")
	}
	return body[:len(body)-8], nil
}

func appendInt64(b []byte, v int64) []byte {
	for i := 7; i >= 0; i-- {
		b = append(b, byte(v>>(uint(i)*8)))
	}
	return b
}

func readInt64(b []byte) int64 {
	var v int64
	for i := 0; i < 8; i++ {
		v = (v << 8) | int64(b[i])
	}
	return v
}

// Cookie writes the session cookie on the response.
func (s *SignedCookie) Cookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(ttl),
	}
}
