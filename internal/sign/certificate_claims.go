// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// certificateEvidenceClaims are the non-circular commitments carried inside
// the exact HTML covered by the audit certificate's Ed25519 signature. The
// final PDF is the contract body only; the separately stored certificate can
// therefore bind its digest without hashing bytes that contain the claim.
type certificateEvidenceClaims struct {
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

const maxCertificateDocumentEvents = 10000

const (
	preFinalChainScopeOrganization  = "organization"
	documentEventsScopeCeremonyRoot = "ceremony-root"
)

func newCertificateEvidenceClaims(doc *generated.Document, finalPDFSHA []byte, head *generated.LatestEventChainHeadForOrgRow, events []*generated.Event) (certificateEvidenceClaims, error) {
	if doc == nil || doc.ID == [16]byte{} || doc.OrgID == [16]byte{} || doc.Name == "" {
		return certificateEvidenceClaims{}, errors.New("audit certificate: document identity unavailable")
	}
	if len(finalPDFSHA) != 32 {
		return certificateEvidenceClaims{}, errors.New("audit certificate: final PDF digest must be 32 bytes")
	}
	if !doc.CompletionEffectiveAtBound {
		return certificateEvidenceClaims{}, errors.New("audit certificate: completion-effective timestamp is not bound for this ceremony")
	}
	completionEffectiveAt, err := canonicalCompletionEffectiveAt(doc.CompletionEffectiveAt)
	if err != nil {
		return certificateEvidenceClaims{}, fmt.Errorf("audit certificate: %w", err)
	}
	if head == nil || len(head.RowHash) != 32 || !head.CreatedAt.Valid || head.CreatedAt.Time.IsZero() {
		return certificateEvidenceClaims{}, errors.New("audit certificate: pre-final audit chain head unavailable")
	}
	for i, event := range events {
		if event == nil || event.OrgID != doc.OrgID || !event.DocumentID.Valid || event.DocumentID.Bytes != doc.ID {
			return certificateEvidenceClaims{}, fmt.Errorf("audit certificate: pre-final event %d does not belong to the document", i)
		}
	}
	eventsSHA, eventsCount, err := documentEventsCommitment(events)
	if err != nil {
		return certificateEvidenceClaims{}, err
	}
	return certificateEvidenceClaims{
		DocumentID:                 doc.ID.String(),
		OrgID:                      doc.OrgID.String(),
		DocumentNameSHA256:         fmt.Sprintf("%x", sha256.Sum256([]byte(doc.Name))),
		FinalPDFSHA256:             hex.EncodeToString(finalPDFSHA),
		CompletionEffectiveAt:      completionEffectiveAt,
		PreFinalChainHeadSHA256:    hex.EncodeToString(head.RowHash),
		PreFinalChainHeadCreatedAt: head.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		PreFinalChainScope:         preFinalChainScopeOrganization,
		DocumentEventsSHA256:       eventsSHA,
		DocumentEventsCount:        eventsCount,
		DocumentEventsScope:        documentEventsScopeCeremonyRoot,
	}, nil
}

// documentEventsCommitment binds the exact pre-final document-event set while
// avoiding a false claim that a document-only export is a contiguous proof of
// the interleaved org chain. Ordering is chronological by created_at then UUID.
func documentEventsCommitment(events []*generated.Event) (string, int, error) {
	if len(events) == 0 {
		return "", 0, errors.New("audit certificate: document has no pre-final events")
	}
	if len(events) > maxCertificateDocumentEvents {
		return "", 0, fmt.Errorf("audit certificate: document has more than %d pre-final events", maxCertificateDocumentEvents)
	}
	ordered := append([]*generated.Event(nil), events...)
	for i, event := range ordered {
		if event == nil || event.ID == [16]byte{} || len(event.RowHash) != 32 || !event.CreatedAt.Valid || event.CreatedAt.Time.IsZero() {
			return "", 0, fmt.Errorf("audit certificate: invalid pre-final event at index %d", i)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if !a.CreatedAt.Time.Equal(b.CreatedAt.Time) {
			return a.CreatedAt.Time.Before(b.CreatedAt.Time)
		}
		return bytes.Compare(a.ID[:], b.ID[:]) < 0
	})
	for _, event := range ordered {
		recomputed, err := audit.RecomputeEventRowHash(event)
		if err != nil {
			return "", 0, fmt.Errorf("audit certificate: recompute pre-final event %s: %w", event.ID, err)
		}
		if subtle.ConstantTimeCompare(recomputed, event.RowHash) != 1 {
			return "", 0, fmt.Errorf("audit certificate: pre-final event %s row hash is invalid", event.ID)
		}
	}
	digest, err := audit.DocumentEventSetDigest(ordered)
	if err != nil {
		return "", 0, fmt.Errorf("audit certificate: document-event set: %w", err)
	}
	return hex.EncodeToString(digest[:]), len(ordered), nil
}

// HTML uses stable data attributes so offline verifiers can extract the
// commitments from the signed payload without scraping human prose.
func (c certificateEvidenceClaims) HTML() string {
	return fmt.Sprintf(`<section class="hash-evidence-claims" data-hash-document-id="%s" data-hash-org-id="%s" data-hash-document-name-sha256="%s" data-hash-final-pdf-sha256="%s" data-hash-completion-effective-at="%s" data-hash-pre-final-chain-head-sha256="%s" data-hash-pre-final-chain-head-created-at="%s" data-hash-pre-final-chain-scope="%s" data-hash-document-events-sha256="%s" data-hash-document-events-count="%d" data-hash-document-events-scope="%s"><h3>Cryptographic commitments</h3><p><strong>Document ID:</strong> <code>%s</code></p><p><strong>Organization ID:</strong> <code>%s</code></p><p><strong>Document name SHA-256:</strong> <code>%s</code></p><p><strong>Final PDF SHA-256:</strong> <code>%s</code></p><p><strong>Completion effective at:</strong> %s</p><p><strong>Pre-final organization audit-chain head SHA-256:</strong> <code>%s</code></p><p><strong>Pre-final audit-chain head timestamp:</strong> %s</p><p><strong>Ceremony-root document-event set SHA-256:</strong> <code>%s</code> (%d events)</p><p>The event-set attachment is scoped to this ceremony root. For an envelope, child content and identity are bound by the signed envelope manifest; child lifecycle rows remain in the organization audit chain committed by the pre-final head.</p></section>`,
		htmlEscape(c.DocumentID),
		htmlEscape(c.OrgID),
		htmlEscape(c.DocumentNameSHA256),
		htmlEscape(c.FinalPDFSHA256),
		htmlEscape(c.CompletionEffectiveAt),
		htmlEscape(c.PreFinalChainHeadSHA256),
		htmlEscape(c.PreFinalChainHeadCreatedAt),
		htmlEscape(c.PreFinalChainScope),
		htmlEscape(c.DocumentEventsSHA256),
		c.DocumentEventsCount,
		htmlEscape(c.DocumentEventsScope),
		htmlEscape(c.DocumentID),
		htmlEscape(c.OrgID),
		htmlEscape(c.DocumentNameSHA256),
		htmlEscape(c.FinalPDFSHA256),
		htmlEscape(c.CompletionEffectiveAt),
		htmlEscape(c.PreFinalChainHeadSHA256),
		htmlEscape(c.PreFinalChainHeadCreatedAt),
		htmlEscape(c.DocumentEventsSHA256),
		c.DocumentEventsCount,
	)
}
