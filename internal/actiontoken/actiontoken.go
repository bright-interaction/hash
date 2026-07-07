// Package actiontoken mints and verifies stateless, HMAC-signed, expiring tokens
// that authorize a single action from an email link (e.g. approve a change
// request) without a login. The signing key is derived from the instance signer
// key so email-action tokens are cryptographically separate from magic links.
package actiontoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMalformed = errors.New("malformed action token")
	ErrBadSig    = errors.New("action token signature mismatch")
	ErrExpired   = errors.New("action token expired")
)

// Claims are the signed fields of an action token. Values must not contain '|'.
type Claims struct {
	Kind     string // e.g. "cr" (change request)
	OrgID    string
	DocID    string
	TargetID string // the change-request id
	Action   string // "approve" | "deny"
	Exp      int64  // unix seconds
}

func deriveKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("hash-action-token-v1"))
	return mac.Sum(nil)
}

func payload(c Claims) string {
	return strings.Join([]string{c.Kind, c.OrgID, c.DocID, c.TargetID, c.Action, strconv.FormatInt(c.Exp, 10)}, "|")
}

// Mint returns a signed token authorizing the claims until now+ttl.
func Mint(secret string, c Claims, now time.Time, ttl time.Duration) string {
	c.Exp = now.Add(ttl).Unix()
	p := payload(c)
	mac := hmac.New(sha256.New, deriveKey(secret))
	mac.Write([]byte(p))
	sig := mac.Sum(nil)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(p)) + "." + enc.EncodeToString(sig)
}

// Verify checks the signature + expiry and returns the claims.
func Verify(secret, token string, now time.Time) (Claims, error) {
	enc := base64.RawURLEncoding
	dot := strings.IndexByte(token, '.')
	if dot <= 0 {
		return Claims{}, ErrMalformed
	}
	pRaw, err := enc.DecodeString(token[:dot])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	sig, err := enc.DecodeString(token[dot+1:])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	mac := hmac.New(sha256.New, deriveKey(secret))
	mac.Write(pRaw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return Claims{}, ErrBadSig
	}
	parts := strings.Split(string(pRaw), "|")
	if len(parts) != 6 {
		return Claims{}, ErrMalformed
	}
	exp, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if now.Unix() > exp {
		return Claims{}, ErrExpired
	}
	return Claims{Kind: parts[0], OrgID: parts[1], DocID: parts[2], TargetID: parts[3], Action: parts[4], Exp: exp}, nil
}
