// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// CertSigner produces detached ed25519 signatures over arbitrary payloads.
// The audit certificate uses one to bind a "this is the canonical signed
// PDF + this is the audit trail" assertion that anyone can verify offline
// against the published public key.
type CertSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewCertSigner accepts a base64-encoded ed25519 private key (the seed,
// 32 bytes, raw or base64). If the input is empty, NewCertSigner returns
// (nil, nil) so callers can opt out of signing in dev environments.
func NewCertSigner(seedB64 string) (*CertSigner, error) {
	if seedB64 == "" {
		return nil, nil
	}
	seed, err := decodeKey(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes; got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("could not derive public key")
	}
	return &CertSigner{priv: priv, pub: pub}, nil
}

// GenerateCertSigner creates a fresh signer. Used for tests and the
// first-boot bootstrap when HASH_AUDIT_PRIVATE_KEY isn't set.
func GenerateCertSigner() (*CertSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CertSigner{priv: priv, pub: pub}, nil
}

// PublicKeyBase64 returns the public key in base64 (raw, no PEM wrap).
// Marketing pages publish this so anyone can offline-verify a final PDF.
func (s *CertSigner) PublicKeyBase64() string {
	if s == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.pub)
}

// PublicKeyPEM returns the ed25519 public key in a PEM-style wrapper.
// Phase 10.2 evidence bundles embed this so a forensic examiner can
// verify the audit cert signature offline with standard PEM-aware
// tooling. Note: ed25519 keys don't strictly need ASN.1 DER encoding
// to round-trip through the verify endpoint (it accepts raw base64),
// but PEM is the format reviewers expect to see in a court-ready
// bundle.
func (s *CertSigner) PublicKeyPEM() string {
	if s == nil || len(s.pub) == 0 {
		return ""
	}
	// SPKI/DER so standard tooling (OpenSSL, python-cryptography, Go x509) can
	// parse the key and verify the certificate offline. A raw-bytes body inside
	// PUBLIC KEY markers is not valid SPKI and fails every generic parser.
	der, err := x509.MarshalPKIXPublicKey(s.pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// PublicKeyHex returns the public key as hex for the audit certificate
// human-readable display.
func (s *CertSigner) PublicKeyHex() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.pub)
}

// SeedBase64 returns the private-key seed in base64. Only used by the
// bootstrap path that generates a key + writes it to ops/.env on first
// boot. Production keys come in via env and never leave the process.
func (s *CertSigner) SeedBase64() string {
	if s == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.priv.Seed())
}

// SignPayload returns a detached signature over the given bytes. We sign
// the SHA-256 of the payload + a domain-separation prefix so an attacker
// can't replay one signed thing as another.
func (s *CertSigner) SignPayload(payload []byte) string {
	if s == nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("hash:audit-cert:v1:"), payload...))
	sig := ed25519.Sign(s.priv, digest[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// Verify checks a signature produced by SignPayload. Standalone helper so
// the marketing page + audit-trail viewer can both use the same code path.
func Verify(pubB64, payload, sigB64 string) bool {
	pub, err := decodeKey(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	digest := sha256.Sum256(append([]byte("hash:audit-cert:v1:"), []byte(payload)...))
	return ed25519.Verify(pub, digest[:], sig)
}

// decodeKey accepts base64-std or base64-url, with or without padding.
// Production env vars are usually base64-std; some operators paste url-safe
// variants from one-liner generators.
func decodeKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("not valid base64 (any encoding)")
}
