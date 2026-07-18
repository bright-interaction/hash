// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package trustlist validates QES signer certificate chains against an
// operator-curated allow-list of qualified trust service provider (QTSP)
// root certificates.
//
// The EU Trust List (https://eidas.ec.europa.eu/tl/EU/tl-mp.xml) is the
// authoritative source under eIDAS Article 22 + Decision 2015/1505. A future
// commit can parse the XML directly + auto-refresh; for now we gate on a
// smaller JSON file the operator maintains, which keeps the validator
// hermetic + auditable.
//
// File format (UTF-8 JSON):
//
//	{
//	  "version": "2026-06",
//	  "trusted_roots": [
//	    {
//	      "qtsp": "Idura Sweden AB",
//	      "country": "SE",
//	      "subject_cn": "Idura QES Root CA 2025",
//	      "sha256_fingerprint": "ab12...cdef",
//	      "root_pem": "-----BEGIN CERTIFICATE-----\n...genuine QTSP root...\n-----END CERTIFICATE-----\n"
//	    }
//	  ]
//	}
//
// root_pem is the genuine QTSP root certificate (free from the EU Trust List
// XML). It is the actual trust anchor: ValidateChain builds an x509 roots pool
// from these certificates and cryptographically verifies that the supplied
// leaf chains up to one of them (signature linkage, expiry, basic
// constraints). sha256_fingerprint is a redundant integrity check on the PEM,
// not the trust anchor - an earlier design that matched only the fingerprint
// of the LAST cert in the attacker-supplied chain was forgeable, because QTSP
// roots are public so an attacker could append a genuine root behind a forged
// self-signed leaf and pass.
//
// When no trust list is configured (Validator == nil) the QES engine logs a
// warning and accepts the chain so deployments without a curated list still
// function; production environments should set HASH_QES_TRUST_LIST_PATH so
// the gate is enforced.
package trustlist

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrChainEmpty signals an empty / unparseable PEM input.
var ErrChainEmpty = errors.New("trustlist: empty or unparseable certificate chain")

// timeNow is overridable in tests so expiry assertions are deterministic.
var timeNow = time.Now

// ErrRootNotTrusted signals that the supplied chain does not chain up to any
// allow-listed QTSP root. Carries the chain's terminal subject CN + SHA-256
// fingerprint so audit logs can record what was rejected.
type ErrRootNotTrusted struct {
	SubjectCN   string
	Fingerprint string
}

func (e *ErrRootNotTrusted) Error() string {
	return fmt.Sprintf("trustlist: chain does not anchor to a trusted EU QTSP root (terminal cert %q, sha256=%s)", e.SubjectCN, e.Fingerprint)
}

// ErrChainNotVerified signals a cryptographic verification failure (bad
// signature linkage, expired cert, bad usage) for a chain whose anchor IS
// on the allow-list. Wraps the underlying x509 error.
type ErrChainNotVerified struct{ Err error }

func (e *ErrChainNotVerified) Error() string {
	return "trustlist: chain verification failed: " + e.Err.Error()
}
func (e *ErrChainNotVerified) Unwrap() error { return e.Err }

// TrustedRoot describes one QTSP root the operator vouches for.
type TrustedRoot struct {
	QTSP              string `json:"qtsp"`
	Country           string `json:"country"`
	SubjectCN         string `json:"subject_cn"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	// RootPEM is the genuine QTSP root certificate in PEM. Required: an entry
	// without it cannot anchor real verification.
	RootPEM string `json:"root_pem"`
}

// File is the on-disk shape of the trust-list JSON.
type File struct {
	Version      string        `json:"version"`
	TrustedRoots []TrustedRoot `json:"trusted_roots"`
}

// Validator holds an x509 roots pool built from the genuine root certificates
// plus a fingerprint->metadata map for reporting the matched QTSP. Safe for
// concurrent use; built once at Load time.
type Validator struct {
	roots         *x509.CertPool
	byFingerprint map[string]TrustedRoot
	source        string
}

// Load reads the JSON trust list at path. Empty path returns (nil, nil) so
// callers can treat "not configured" as "skip validation" without a branch at
// every call site. An entry whose root_pem is missing/unparseable, or whose
// PEM does not hash to its declared fingerprint, is a hard load error: a
// misconfigured trust list must fail closed rather than silently weaken the
// gate.
func Load(path string) (*Validator, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trustlist: read %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("trustlist: parse %s: %w", path, err)
	}
	v := &Validator{
		roots:         x509.NewCertPool(),
		byFingerprint: make(map[string]TrustedRoot, len(f.TrustedRoots)),
		source:        path,
	}
	for i, r := range f.TrustedRoots {
		declared := normalizeFingerprint(r.SHA256Fingerprint)
		if strings.TrimSpace(r.RootPEM) == "" {
			return nil, fmt.Errorf("trustlist: entry %d (%q) has no root_pem; the genuine QTSP root certificate is required to verify chains", i, r.SubjectCN)
		}
		cert, perr := firstCertFromPEM(r.RootPEM)
		if perr != nil {
			return nil, fmt.Errorf("trustlist: entry %d (%q) root_pem: %w", i, r.SubjectCN, perr)
		}
		actual := Fingerprint(cert)
		if declared != "" && declared != actual {
			return nil, fmt.Errorf("trustlist: entry %d (%q) root_pem fingerprint %s does not match declared sha256_fingerprint %s", i, r.SubjectCN, actual, declared)
		}
		v.roots.AddCert(cert)
		v.byFingerprint[actual] = r
	}
	return v, nil
}

// Source returns the file path the validator was loaded from.
func (v *Validator) Source() string {
	if v == nil {
		return ""
	}
	return v.source
}

// Count returns the number of trusted roots currently loaded.
func (v *Validator) Count() int {
	if v == nil {
		return 0
	}
	return len(v.byFingerprint)
}

// ValidateChain parses a PEM-encoded certificate chain (leaf-first) and
// cryptographically verifies that the leaf chains up to an allow-listed QTSP
// root. Returns the matched TrustedRoot + nil on success.
//
// Trust comes from OUR roots pool, never from the supplied chain's terminal
// block: the supplied certs[1:] are offered only as candidate intermediates.
// A forged self-signed leaf with a genuine root appended therefore fails,
// because the leaf's signature does not verify against the genuine root's key.
func (v *Validator) ValidateChain(pemChain string) (*TrustedRoot, error) {
	if v == nil {
		return nil, nil
	}
	certs, err := ParsePEMChain(pemChain)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrChainEmpty
	}
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	chains, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   timeNow(),
		// eIDAS QES leaf certs declare non-standard or no EKU; don't gate on
		// EKU here (KeyUsage is asserted separately below). Passing Any avoids
		// the stdlib default of requiring ServerAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if verr != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(verr, &unknown) {
			terminal := certs[len(certs)-1]
			return nil, &ErrRootNotTrusted{SubjectCN: terminal.Subject.CommonName, Fingerprint: Fingerprint(terminal)}
		}
		return nil, &ErrChainNotVerified{Err: verr}
	}

	// A QES signing certificate must be usable for signing. If KeyUsage is
	// asserted at all, it must include digitalSignature or contentCommitment
	// (the bit historically called nonRepudiation).
	const sigBits = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	if leaf.KeyUsage != 0 && leaf.KeyUsage&sigBits == 0 {
		return nil, &ErrChainNotVerified{Err: errors.New("leaf certificate lacks digitalSignature/nonRepudiation key usage")}
	}

	// The verified chain's anchor (last cert of the first chain) is the
	// trusted root that actually anchored the path. Map it back to its
	// allow-list metadata.
	verifiedRoot := chains[0][len(chains[0])-1]
	r, ok := v.byFingerprint[Fingerprint(verifiedRoot)]
	if !ok {
		return nil, &ErrRootNotTrusted{SubjectCN: verifiedRoot.Subject.CommonName, Fingerprint: Fingerprint(verifiedRoot)}
	}
	return &r, nil
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate's DER
// bytes. Matches `openssl x509 -fingerprint -noout -sha256` output.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// firstCertFromPEM parses the first CERTIFICATE block from a PEM string.
func firstCertFromPEM(raw string) (*x509.Certificate, error) {
	certs, err := ParsePEMChain(raw)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParsePEMChain walks the PEM blocks in the input and returns each
// CERTIFICATE in order. Non-cert blocks (e.g. PRIVATE KEY) are skipped.
func ParsePEMChain(raw string) ([]*x509.Certificate, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrChainEmpty
	}
	var out []*x509.Certificate
	rest := []byte(raw)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trustlist: parse cert: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, ErrChainEmpty
	}
	return out, nil
}

func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
