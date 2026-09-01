// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/bright-interaction/hash/internal/sign"
)

// resolveCertificateIssuerKey identifies the historical trusted key that
// signed a stored ceremony certificate. Export manifests may be signed by the
// current key after rotation, so the certificate key must be discovered and
// attached independently rather than assumed to equal the export key.
func resolveCertificateIssuerKey(payload, signature []byte, candidates []string) (string, []byte, string, error) {
	seen := make(map[string]struct{}, len(candidates))
	type match struct {
		b64 string
		raw ed25519.PublicKey
	}
	var matches []match
	for i, candidate := range candidates {
		raw, err := decodeRawEd25519PublicKey(strings.TrimSpace(candidate))
		if err != nil {
			return "", nil, "", fmt.Errorf("evidence: trusted certificate key %d: %w", i+1, err)
		}
		canonical := base64.StdEncoding.EncodeToString(raw)
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		if sign.Verify(canonical, string(payload), string(signature)) {
			matches = append(matches, match{b64: canonical, raw: raw})
		}
	}
	if len(matches) == 0 {
		return "", nil, "", errors.New("evidence: certificate signature does not match any trusted current or historical issuer key")
	}
	if len(matches) != 1 {
		return "", nil, "", errors.New("evidence: certificate signature ambiguously matches multiple trusted issuer keys")
	}
	der, err := x509.MarshalPKIXPublicKey(matches[0].raw)
	if err != nil {
		return "", nil, "", fmt.Errorf("evidence: marshal certificate issuer key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	fingerprint := sha256.Sum256(matches[0].raw)
	return matches[0].b64, pemBytes, hex.EncodeToString(fingerprint[:]), nil
}

func decodeRawEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	if value == "" {
		return nil, errors.New("key is empty")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			if len(decoded) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("decoded key must be %d bytes", ed25519.PublicKeySize)
			}
			return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
		}
	}
	return nil, errors.New("key is not valid base64")
}
