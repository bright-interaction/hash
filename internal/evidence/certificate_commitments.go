// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CertificateCommitments are the non-circular artifact and ledger claims
// carried inside the exact HTML covered by an audit-certificate signature.
// They let a verifier distinguish a merely self-consistent export from the
// contract and document-event set committed at ceremony time.
type CertificateCommitments struct {
	DocumentID                 string
	OrgID                      string
	DocumentNameSHA256         string
	FinalPDFSHA256             string
	CompletionEffectiveAt      string
	PreFinalChainHeadSHA256    string
	PreFinalChainHeadCreatedAt string
	PreFinalChainScope         string
	DocumentEventsSHA256       string
	DocumentEventsCount        int
	DocumentEventsScope        string
}

const (
	certificateChainScopeOrganization = "organization"
	certificateEventScopeCeremonyRoot = "ceremony-root"
)

// ParseCertificateCommitments extracts and validates every required signed
// claim. Each attribute must occur exactly once; accepting the first of two
// values would make verifier behavior parser-dependent.
func ParseCertificateCommitments(payload []byte) (CertificateCommitments, error) {
	documentID, err := certificateTextClaim(payload, "data-hash-document-id")
	if err != nil {
		return CertificateCommitments{}, err
	}
	if parsed, parseErr := uuid.Parse(documentID); parseErr != nil || parsed == uuid.Nil || parsed.String() != documentID {
		return CertificateCommitments{}, errors.New("signed certificate document id is not a canonical non-zero UUID")
	}
	orgID, err := certificateTextClaim(payload, "data-hash-org-id")
	if err != nil {
		return CertificateCommitments{}, err
	}
	if parsed, parseErr := uuid.Parse(orgID); parseErr != nil || parsed == uuid.Nil || parsed.String() != orgID {
		return CertificateCommitments{}, errors.New("signed certificate organization id is not a canonical non-zero UUID")
	}
	documentNameSHA, err := certificateSHA256Claim(payload, "data-hash-document-name-sha256")
	if err != nil {
		return CertificateCommitments{}, err
	}
	finalPDF, err := certificateSHA256Claim(payload, "data-hash-final-pdf-sha256")
	if err != nil {
		return CertificateCommitments{}, err
	}
	completionEffectiveAt, present, err := optionalCertificateTextClaim(payload, "data-hash-completion-effective-at")
	if err != nil {
		return CertificateCommitments{}, err
	}
	if present {
		parsed, parseErr := time.Parse(time.RFC3339Nano, completionEffectiveAt)
		if parseErr != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != completionEffectiveAt {
			return CertificateCommitments{}, errors.New("signed completion-effective timestamp is invalid")
		}
	}
	chainHead, err := certificateSHA256Claim(payload, "data-hash-pre-final-chain-head-sha256")
	if err != nil {
		return CertificateCommitments{}, err
	}
	chainAt, err := certificateTextClaim(payload, "data-hash-pre-final-chain-head-created-at")
	if err != nil {
		return CertificateCommitments{}, err
	}
	parsedAt, err := time.Parse(time.RFC3339Nano, chainAt)
	if err != nil || parsedAt.IsZero() || parsedAt.UTC().Format(time.RFC3339Nano) != chainAt {
		return CertificateCommitments{}, errors.New("signed pre-final chain-head timestamp is invalid")
	}
	chainScope, chainScopePresent, err := optionalCertificateTextClaim(payload, "data-hash-pre-final-chain-scope")
	if err != nil {
		return CertificateCommitments{}, err
	}
	if chainScopePresent && chainScope != certificateChainScopeOrganization {
		return CertificateCommitments{}, errors.New("signed pre-final chain scope is unsupported")
	}
	eventsSHA, err := certificateSHA256Claim(payload, "data-hash-document-events-sha256")
	if err != nil {
		return CertificateCommitments{}, err
	}
	eventsCountText, err := certificateTextClaim(payload, "data-hash-document-events-count")
	if err != nil {
		return CertificateCommitments{}, err
	}
	eventsCount, err := strconv.Atoi(eventsCountText)
	if err != nil || eventsCount <= 0 || eventsCount > maxEvidenceEvents {
		return CertificateCommitments{}, fmt.Errorf("signed certificate document-event count must be between 1 and %d", maxEvidenceEvents)
	}
	if strconv.Itoa(eventsCount) != eventsCountText {
		return CertificateCommitments{}, errors.New("signed certificate document-event count is not canonical")
	}
	eventsScope, eventsScopePresent, err := optionalCertificateTextClaim(payload, "data-hash-document-events-scope")
	if err != nil {
		return CertificateCommitments{}, err
	}
	if eventsScopePresent && eventsScope != certificateEventScopeCeremonyRoot {
		return CertificateCommitments{}, errors.New("signed document-event scope is unsupported")
	}
	// Bound completion evidence was introduced in the same production cutover as
	// these explicit scopes. Require both so a new envelope can never silently
	// imply that its root-only events attachment is a full family/org-chain proof.
	if present && (!chainScopePresent || !eventsScopePresent) {
		return CertificateCommitments{}, errors.New("signed completion evidence omits its audit scope")
	}
	return CertificateCommitments{
		DocumentID:                 documentID,
		OrgID:                      orgID,
		DocumentNameSHA256:         documentNameSHA,
		FinalPDFSHA256:             finalPDF,
		CompletionEffectiveAt:      completionEffectiveAt,
		PreFinalChainHeadSHA256:    chainHead,
		PreFinalChainHeadCreatedAt: parsedAt.UTC().Format(time.RFC3339Nano),
		PreFinalChainScope:         chainScope,
		DocumentEventsSHA256:       eventsSHA,
		DocumentEventsCount:        eventsCount,
		DocumentEventsScope:        eventsScope,
	}, nil
}

func optionalCertificateTextClaim(payload []byte, attribute string) (string, bool, error) {
	marker := []byte(attribute + `="`)
	switch bytes.Count(payload, marker) {
	case 0:
		return "", false, nil
	case 1:
		value, err := certificateTextClaim(payload, attribute)
		return value, err == nil, err
	default:
		return "", false, fmt.Errorf("signed certificate must contain at most one %s claim", attribute)
	}
}

func certificateTextClaim(payload []byte, attribute string) (string, error) {
	marker := []byte(attribute + `="`)
	if bytes.Count(payload, marker) != 1 {
		return "", fmt.Errorf("signed certificate must contain exactly one %s claim", attribute)
	}
	start := bytes.Index(payload, marker) + len(marker)
	rest := payload[start:]
	end := bytes.IndexByte(rest, '"')
	if end <= 0 {
		return "", fmt.Errorf("signed certificate %s claim is malformed", attribute)
	}
	value := string(rest[:end])
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("signed certificate %s claim is not canonical", attribute)
	}
	return value, nil
}

func certificateSHA256Claim(payload []byte, attribute string) (string, error) {
	value, err := certificateTextClaim(payload, attribute)
	if err != nil {
		return "", err
	}
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return "", fmt.Errorf("signed certificate %s claim is not a canonical SHA-256", attribute)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("signed certificate %s claim is not a canonical SHA-256", attribute)
	}
	return value, nil
}
