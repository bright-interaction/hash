// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestCertificateEvidenceClaimsBindFinalBodyAndChainHead(t *testing.T) {
	finalSHA := bytes.Repeat([]byte{0x11}, 32)
	headSHA := bytes.Repeat([]byte{0x22}, 32)
	createdAt := time.Date(2026, 8, 30, 12, 34, 56, 123000000, time.FixedZone("test", 2*60*60))
	doc := &generated.Document{
		ID:    uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		OrgID: uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), Name: "Partner Agreement",
		CompletionEffectiveAtBound: true,
		CompletionEffectiveAt:      pgtype.Timestamptz{Time: createdAt.Add(2 * time.Second), Valid: true},
	}
	events := []*generated.Event{
		claimEvent(t, uuid.MustParse("22222222-2222-2222-2222-222222222222"), doc, createdAt.Add(time.Second), []byte(`{"event":2}`)),
		claimEvent(t, uuid.MustParse("11111111-1111-1111-1111-111111111111"), doc, createdAt, []byte(`{"event":1}`)),
	}
	claims, err := newCertificateEvidenceClaims(doc, finalSHA, &generated.LatestEventChainHeadForOrgRow{
		RowHash:   headSHA,
		CreatedAt: pgtype.Timestamptz{Time: createdAt, Valid: true},
	}, events)
	if err != nil {
		t.Fatal(err)
	}
	html := claims.HTML()
	for _, want := range []string{
		`data-hash-document-id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
		`data-hash-org-id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"`,
		`data-hash-document-name-sha256="` + fmt.Sprintf("%x", sha256.Sum256([]byte("Partner Agreement"))) + `"`,
		`data-hash-final-pdf-sha256="` + strings.Repeat("11", 32) + `"`,
		`data-hash-completion-effective-at="2026-08-30T10:34:58.123Z"`,
		`data-hash-pre-final-chain-head-sha256="` + strings.Repeat("22", 32) + `"`,
		`data-hash-pre-final-chain-head-created-at="2026-08-30T10:34:56.123Z"`,
		`data-hash-pre-final-chain-scope="organization"`,
		`data-hash-document-events-sha256="` + claims.DocumentEventsSHA256 + `"`,
		`data-hash-document-events-count="2"`,
		`data-hash-document-events-scope="ceremony-root"`,
		`child content and identity are bound by the signed envelope manifest`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("claims HTML missing %q: %s", want, html)
		}
	}
}

func TestCertificateEvidenceClaimsRejectChildDocumentEvents(t *testing.T) {
	now := time.Now().UTC()
	root := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Name: "Envelope", IsEnvelope: true,
		CompletionEffectiveAtBound: true,
		CompletionEffectiveAt:      pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true},
	}
	child := &generated.Document{
		ID: uuid.New(), OrgID: root.OrgID, Name: "Child",
		ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true},
	}
	head := &generated.LatestEventChainHeadForOrgRow{
		RowHash:   bytes.Repeat([]byte{0x22}, 32),
		CreatedAt: pgtype.Timestamptz{Time: now, Valid: true},
	}
	rootEvent := claimEvent(t, uuid.New(), root, now.Add(-time.Second), []byte(`{"document":"root"}`))
	childEvent := claimEvent(t, uuid.New(), child, now, []byte(`{"document":"child"}`))
	if _, err := newCertificateEvidenceClaims(root, bytes.Repeat([]byte{1}, 32), head, []*generated.Event{rootEvent, childEvent}); err == nil {
		t.Fatal("ceremony-root event attachment accepted an envelope child event without an explicit per-event document identity")
	}
}

func TestEnvelopeCertificateSeparatesRootEventsFromChildChainCommitment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	root := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Name: "Envelope", IsEnvelope: true,
		CompletionEffectiveAtBound: true,
		CompletionEffectiveAt:      pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true},
	}
	child := &generated.Document{
		ID: uuid.New(), OrgID: root.OrgID, Name: "Child",
		ParentEnvelopeID: pgtype.UUID{Bytes: root.ID, Valid: true},
	}
	rootEvent := claimEvent(t, uuid.New(), root, now.Add(-2*time.Second), []byte(`{"document":"root"}`))
	childEvent := claimEvent(t, uuid.New(), child, now.Add(-time.Second), []byte(`{"document":"child"}`))
	childEvent.PrevHash = append([]byte(nil), rootEvent.RowHash...)
	childHash, err := audit.RecomputeEventRowHash(childEvent)
	if err != nil {
		t.Fatal(err)
	}
	childEvent.RowHash = childHash
	head := &generated.LatestEventChainHeadForOrgRow{
		RowHash:   append([]byte(nil), childEvent.RowHash...),
		CreatedAt: childEvent.CreatedAt,
	}
	claims, err := newCertificateEvidenceClaims(root, bytes.Repeat([]byte{1}, 32), head, []*generated.Event{rootEvent})
	if err != nil {
		t.Fatal(err)
	}
	if claims.DocumentEventsScope != documentEventsScopeCeremonyRoot || claims.DocumentEventsCount != 1 {
		t.Fatalf("root attachment scope/count = %q/%d", claims.DocumentEventsScope, claims.DocumentEventsCount)
	}
	if claims.PreFinalChainScope != preFinalChainScopeOrganization || claims.PreFinalChainHeadSHA256 != fmt.Sprintf("%x", childEvent.RowHash) {
		t.Fatalf("organization chain claim does not bind the child head: %+v", claims)
	}

	// The signed organization head commits the child row transitively even
	// though the portable event attachment intentionally contains only root
	// events. Changing the child row necessarily changes the committed head.
	tampered := *childEvent
	tampered.PayloadJson = []byte(`{"document":"tampered-child"}`)
	tampered.PayloadHashed = append([]byte(nil), tampered.PayloadJson...)
	tamperedHash, err := audit.RecomputeEventRowHash(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tamperedHash, childEvent.RowHash) {
		t.Fatal("tampering a child event did not change the organization chain head")
	}
}

func TestCertificateEvidenceClaimsFailClosed(t *testing.T) {
	validHead := &generated.LatestEventChainHeadForOrgRow{
		RowHash:   bytes.Repeat([]byte{0x22}, 32),
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	validDoc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(), Name: "Agreement",
		CompletionEffectiveAtBound: true,
		CompletionEffectiveAt:      pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}
	validEvents := []*generated.Event{claimEvent(t, uuid.New(), validDoc, time.Now(), []byte(`{}`))}
	if _, err := newCertificateEvidenceClaims(validDoc, []byte{1}, validHead, validEvents); err == nil {
		t.Fatal("short final digest must fail")
	}
	if _, err := newCertificateEvidenceClaims(validDoc, bytes.Repeat([]byte{1}, 32), nil, validEvents); err == nil {
		t.Fatal("missing audit chain head must fail")
	}
	validHead.RowHash = []byte{1}
	if _, err := newCertificateEvidenceClaims(validDoc, bytes.Repeat([]byte{1}, 32), validHead, validEvents); err == nil {
		t.Fatal("short audit chain hash must fail")
	}
	validHead.RowHash = bytes.Repeat([]byte{0x22}, 32)
	if _, err := newCertificateEvidenceClaims(nil, bytes.Repeat([]byte{1}, 32), validHead, validEvents); err == nil {
		t.Fatal("missing document identity must fail")
	}
	missingCompletion := *validDoc
	missingCompletion.CompletionEffectiveAt = pgtype.Timestamptz{}
	if _, err := newCertificateEvidenceClaims(&missingCompletion, bytes.Repeat([]byte{1}, 32), validHead, validEvents); err == nil {
		t.Fatal("missing completion-effective timestamp must fail")
	}
	unboundCompletion := *validDoc
	unboundCompletion.CompletionEffectiveAtBound = false
	if _, err := newCertificateEvidenceClaims(&unboundCompletion, bytes.Repeat([]byte{1}, 32), validHead, validEvents); err == nil {
		t.Fatal("unbound completion provenance must fail")
	}
}

func TestDocumentEventsCommitmentIsChronologicalAndTamperEvident(t *testing.T) {
	now := time.Now().UTC()
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Name: "Agreement"}
	a := claimEvent(t, uuid.New(), doc, now, []byte(`{"event":"a"}`))
	b := claimEvent(t, uuid.New(), doc, now.Add(time.Second), []byte(`{"event":"b"}`))
	forward, count, err := documentEventsCommitment([]*generated.Event{a, b})
	if err != nil || count != 2 {
		t.Fatalf("commit forward: digest=%q count=%d err=%v", forward, count, err)
	}
	reverse, _, err := documentEventsCommitment([]*generated.Event{b, a})
	if err != nil || reverse != forward {
		t.Fatalf("query ordering changed commitment: %q != %q, err=%v", reverse, forward, err)
	}
	b.RowHash = bytes.Repeat([]byte{9}, 32)
	if _, _, err := documentEventsCommitment([]*generated.Event{a, b}); err == nil {
		t.Fatal("tampered row hash must fail recomputation")
	}
	if _, _, err := documentEventsCommitment(nil); err == nil {
		t.Fatal("empty event set must fail closed")
	}
}

func claimEvent(t *testing.T, id uuid.UUID, doc *generated.Document, createdAt time.Time, payload []byte) *generated.Event {
	t.Helper()
	event := &generated.Event{
		ID: id, OrgID: doc.OrgID,
		DocumentID:  pgtype.UUID{Bytes: doc.ID, Valid: true},
		Kind:        audit.KindDocumentSigned,
		PayloadJson: append([]byte(nil), payload...), PayloadHashed: append([]byte(nil), payload...),
		CreatedAt: pgtype.Timestamptz{Time: createdAt.UTC().Truncate(time.Microsecond), Valid: true},
	}
	rowHash, err := audit.RecomputeEventRowHash(event)
	if err != nil {
		t.Fatalf("build canonical claim event: %v", err)
	}
	event.RowHash = rowHash
	return event
}
