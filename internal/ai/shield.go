package ai

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// NoopShield is a passthrough. Used in dev/test environments where
// PII safety isn't a concern. Active() returns false so the audit log
// shows shield_active=false and operators can spot misconfiguration.
type NoopShield struct{}

func (NoopShield) Active() bool { return false }
func (NoopShield) Tokenize(_ context.Context, in string, _ ...string) (string, Handle, error) {
	return in, nopHandle{}, nil
}
func (NoopShield) Untokenize(_ context.Context, in string, _ Handle) (string, error) {
	return in, nil
}

type nopHandle struct{}

// LocalShield is an in-process Shield implementation tailored to Hash.
// PII patterns detected via regex (emails, e-mail-like addresses, names
// from the document recipients, phone numbers) get replaced with stable
// tokens of the form `[shield:<kind>:tok_<hex>]`. The plaintext map is
// scoped to each tokenize call (it hangs off the returned Handle), so the
// decrypted PII is GC'd with the request; the runtime restores values from
// that per-request map on the response.
//
// This is NOT the full Shield package brightcrm/dockyard/atomicsite ship
// (the AES-256-GCM + per-session vault). It's a stand-in for Phase 8.4
// so the AI runtime ships with PII protection on day one; a follow-up
// will port the full package into hash when the AES vault becomes
// load-bearing. The interface matches so the swap is mechanical.
type LocalShield struct {
	key    []byte // 32 bytes, AES-256-GCM
	hmacK  []byte // derived from key for deterministic tokenization
	active bool
}

// NewLocalShield builds a LocalShield with the supplied 32-byte key.
// An empty key disables Shield (returns a NoopShield-equivalent) so the
// app can boot in dev without a configured secret.
func NewLocalShield(key []byte) (Shield, error) {
	if len(key) == 0 {
		return NoopShield{}, nil
	}
	if len(key) != 32 {
		return nil, errors.New("ai.NewLocalShield: key must be 32 bytes")
	}
	hk := sha256.Sum256(append([]byte("hash-shield-hmac:"), key...))
	return &LocalShield{
		key:    key,
		hmacK:  hk[:],
		active: true,
	}, nil
}

func (s *LocalShield) Active() bool { return s.active }

// PII regexes. Deliberately conservative; the Phase 11 port to the full
// Shield package replaces these with typed tags + length-bucketed hints.
var (
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rePhone = regexp.MustCompile(`(?:\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{0,4}`)
	// Swedish personnummer: YYMMDD / YYYYMMDD then optional separator (- or +
	// for people 100+) then a 4-digit suffix; also the compact no-separator
	// forms. Tokenised BEFORE phone so the phone regex can't eat the digits.
	rePersonnummer = regexp.MustCompile(`\b(?:19|20)?\d{6}[-+]?\d{4}\b`)
	// IBAN: 2 country letters + 2 check digits + 11-30 contiguous alphanumerics
	// (the canonical no-spaces form). Case-insensitive: users type IBANs in
	// lower or mixed case, and a case-sensitive detector let a lowercase IBAN
	// reach the LLM untokenized. The old `(?:[ ]?[A-Z0-9])` form allowed a space
	// before every character, so it greedily swallowed the following word (e.g.
	// "SE45... senast"); matching a contiguous run instead stops cleanly at the
	// space. Tokenised before phone (the leading letters keep phone from eating
	// the digits).
	reIBAN = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
)

// Tokenize finds PII spans and replaces them with stable shielded tokens.
// "Stable" within the lifetime of a runtime process: identical plaintext
// produces identical tokens so the model can recognise the same entity
// across turns without learning who it is (matches the brightcrm
// HintLevel:deterministic v1.5 behaviour).
func (s *LocalShield) Tokenize(_ context.Context, in string, knownTerms ...string) (string, Handle, error) {
	if in == "" {
		return in, &localHandle{shield: s, ids: nil}, nil
	}
	h := &localHandle{shield: s, ids: []string{}, plain: map[string]string{}, ts: time.Now()}
	out := in
	out = reEmail.ReplaceAllStringFunc(out, func(match string) string {
		return s.token("email", match, h)
	})
	out = reIBAN.ReplaceAllStringFunc(out, func(match string) string {
		return s.token("iban", match, h)
	})
	out = rePersonnummer.ReplaceAllStringFunc(out, func(match string) string {
		return s.token("personnummer", match, h)
	})
	out = rePhone.ReplaceAllStringFunc(out, func(match string) string {
		// Avoid replacing tiny numbers (years, prices). Require at least 7 digits.
		stripped := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", "+", "").Replace(match)
		if len(stripped) < 7 {
			return match
		}
		return s.token("phone", match, h)
	})
	// Known-term redaction (document party names) runs LAST: the pattern passes
	// above can't see the name tokens (whose hex contains digits the phone regex
	// would otherwise mangle), and longest-first ordering tokenises a full name
	// "Jane Andersson" before the bare "Jane" inside it. Case-insensitive,
	// word-boundary matched so "Janet" survives when the term is "Jane".
	for _, term := range sortedDistinctByLenDesc(knownTerms) {
		re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(term) + `\b`)
		if err != nil {
			continue
		}
		out = re.ReplaceAllStringFunc(out, func(string) string {
			return s.token("name", term, h)
		})
	}
	return out, h, nil
}

// Untokenize swaps shielded tokens in the response back to their
// plaintext values.
func (s *LocalShield) Untokenize(_ context.Context, in string, raw Handle) (string, error) {
	h, ok := raw.(*localHandle)
	if !ok || h.shield != s {
		return in, nil
	}
	out := in
	// h.plain is populated + read within a single request (tokenize -> AI call
	// -> untokenize) on one goroutine, so no lock is needed.
	for _, id := range h.ids {
		plain, ok := h.plain[id]
		if !ok {
			continue
		}
		out = strings.ReplaceAll(out, id, plain)
	}
	return out, nil
}

func (s *LocalShield) token(kind, plain string, h *localHandle) string {
	mac := hmac.New(sha256.New, s.hmacK)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(plain))
	id := fmt.Sprintf("[shield:%s:tok_%s]", kind, hex.EncodeToString(mac.Sum(nil)[:8]))
	h.plain[id] = plain
	h.ids = append(h.ids, id)
	return id
}

type localHandle struct {
	shield *LocalShield
	ids    []string
	// plain holds token -> plaintext for THIS tokenize call only, so decrypted
	// PII is garbage-collected when the handle drops (request scope) instead of
	// accumulating in a process-global map for the server's lifetime (a
	// core-dump / swap exposure). Token ids stay HMAC-derived, so the
	// same-plaintext-same-token property is unaffected.
	plain map[string]string
	ts    time.Time
}

// sortedDistinctByLenDesc trims, drops blanks + too-short terms (< 2 chars,
// which would over-redact), de-duplicates case-insensitively, and orders
// longest-first so a full name is redacted before any substring of it.
func sortedDistinctByLenDesc(terms []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if len(t) < 2 {
			continue
		}
		k := strings.ToLower(t)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// AESEncrypt is a tiny utility callers can use to encrypt blobs with the
// shield key (e.g. session backups). Not used by the runtime in 8.4 but
// kept here so the full Shield port can reuse it.
func AESEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AESEncrypt: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// AESDecrypt reverses AESEncrypt: it expects nonce||ciphertext produced by
// AESEncrypt under the same 32-byte key and returns the plaintext.
func AESDecrypt(key []byte, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AESDecrypt: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("AESDecrypt: ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}
