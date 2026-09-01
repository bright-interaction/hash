// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
)

type evidenceQueriesStub struct {
	events       []*generated.Event
	eventErr     error
	qes          []*generated.QesSigningSession
	qesErr       error
	eventLimit   int32
	qesWasCalled bool
}

func (s *evidenceQueriesStub) ListEventsByDocumentChronological(_ context.Context, p generated.ListEventsByDocumentChronologicalParams) ([]*generated.Event, error) {
	s.eventLimit = p.Limit
	return s.events, s.eventErr
}

func (s *evidenceQueriesStub) ListCompletedQESSessionsForDocument(context.Context, uuid.UUID) ([]*generated.QesSigningSession, error) {
	s.qesWasCalled = true
	return s.qes, s.qesErr
}

type evidenceBlobStoreStub struct {
	objects map[string][]byte
	err     error
}

func (s *evidenceBlobStoreStub) Get(_ context.Context, key string) ([]byte, error) {
	if b, ok := s.objects[key]; ok {
		return b, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	return nil, errors.New("object not found")
}

func (s *evidenceBlobStoreStub) GetVerified(ctx context.Context, key string, expected []byte) ([]byte, error) {
	body, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(body)
	if len(expected) != sha256.Size || !bytes.Equal(actual[:], expected) {
		return nil, ErrArtifactIntegrity
	}
	return body, nil
}

func (s *evidenceBlobStoreStub) GetVerifiedVersion(ctx context.Context, key, _ string, expected []byte) ([]byte, error) {
	return s.GetVerified(ctx, key, expected)
}

func (s *evidenceBlobStoreStub) ResolveVerifiedLegacy(ctx context.Context, key string, expected []byte) ([]byte, storage.StoredObject, error) {
	body, err := s.GetVerified(ctx, key, expected)
	ref := storage.StoredObject{VersionID: "version-legacy"}
	copy(ref.SHA256[:], expected)
	return body, ref, err
}

type evidenceVersionsStub struct {
	history      []*generated.DocumentVersion
	historyErr   error
	prior        *generated.DocumentVersion
	priorErr     error
	historyLimit int32
}

func (s *evidenceVersionsStub) History(_ context.Context, _ uuid.UUID, limit int32) ([]*generated.DocumentVersion, error) {
	s.historyLimit = limit
	return s.history, s.historyErr
}

func (s *evidenceVersionsStub) GetByNo(context.Context, uuid.UUID, int32) (*generated.DocumentVersion, error) {
	return s.prior, s.priorErr
}

func evidenceBuildFixture(t *testing.T) (*generated.Document, *Builder, *evidenceQueriesStub, *evidenceVersionsStub) {
	return evidenceBuildFixtureWithCompletionBinding(t, true)
}

func evidenceBuildFixtureWithCompletionBinding(t *testing.T, completionBound bool) (*generated.Document, *Builder, *evidenceQueriesStub, *evidenceVersionsStub) {
	t.Helper()
	docID := uuid.New()
	orgID := uuid.New()
	pdfConfig := pdfmodel.NewDefaultConfiguration()
	pdfContext, err := pdfcpu.CreateContextWithXRefTable(pdfConfig, pdftypes.PaperSize["A4"])
	if err != nil {
		t.Fatal(err)
	}
	var finalBuffer bytes.Buffer
	if err := pdfapi.WriteContext(pdfContext, &finalBuffer); err != nil {
		t.Fatal(err)
	}
	final := finalBuffer.Bytes()
	sum := sha256.Sum256(final)
	// Both the contract attachment and the visible certificate cover must be
	// parseable PDFs: Build opens the certificate as the bundle's input PDF.
	certPDF := append([]byte(nil), final...)
	certPDFSHA := sha256.Sum256(certPDF)
	completionEffectiveAt := time.Date(2026, 5, 12, 0, 0, 1, 234567000, time.UTC)
	doc := &generated.Document{
		ID: docID, OrgID: orgID, Name: "Agreement", Status: "completed",
		CompletionEffectiveAtBound:  completionBound,
		CompletionEffectiveAt:       pgtype.Timestamptz{Time: completionEffectiveAt, Valid: true},
		CompletedAt:                 pgtype.Timestamptz{Time: completionEffectiveAt, Valid: true},
		EvidenceVersionPinsRequired: true,
		FinalPdfKey:                 pgtype.Text{String: "org/o/documents/d/final-" + hex.EncodeToString(sum[:]) + ".pdf", Valid: true},
		FinalPdfSha:                 sum[:],
		FinalPdfVersionID:           pgtype.Text{String: "final-version-1", Valid: true},
		AuditCertKey:                pgtype.Text{String: "org/o/documents/d/audit-" + hex.EncodeToString(certPDFSHA[:]) + ".pdf", Valid: true},
		AuditCertSha256:             certPDFSHA[:],
		AuditCertVersionID:          pgtype.Text{String: "cert-version-1", Valid: true},
	}
	createdAt := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	event := &generated.Event{
		ID: uuid.New(), OrgID: orgID,
		DocumentID: pgtype.UUID{Bytes: docID, Valid: true},
		Kind:       "document.signed", PayloadJson: json.RawMessage(`{}`), PayloadHashed: []byte(`{}`),
		CreatedAt: pgtype.Timestamptz{Time: createdAt, Valid: true},
	}
	event.RowHash = audit.ChainHashRecord(audit.HashInput{
		OrgID: orgID, DocID: docID, Kind: event.Kind, CreatedAt: createdAt, Payload: event.PayloadHashed,
	})
	eventsDigest, _ := audit.DocumentEventSetDigest([]*generated.Event{event})
	nameDigest := sha256.Sum256([]byte(doc.Name))
	completionClaim := ""
	if completionBound {
		completionClaim = ` data-hash-completion-effective-at="` + completionEffectiveAt.Format(time.RFC3339Nano) + `"` +
			` data-hash-pre-final-chain-scope="organization"` +
			` data-hash-document-events-scope="ceremony-root"`
	}
	payload := []byte(fmt.Sprintf(`<section data-hash-document-id="%s" data-hash-org-id="%s" data-hash-document-name-sha256="%x" data-hash-final-pdf-sha256="%x"%s data-hash-pre-final-chain-head-sha256="%x" data-hash-pre-final-chain-head-created-at="%s" data-hash-document-events-sha256="%x" data-hash-document-events-count="1"></section>`,
		doc.ID, doc.OrgID, nameDigest, sum, completionClaim, event.RowHash, createdAt.Format(time.RFC3339Nano), eventsDigest))
	seed := make([]byte, 32)
	seed[0] = 1
	signer, _ := sign.NewCertSigner(base64.StdEncoding.EncodeToString(seed))
	signature := []byte(signer.SignPayload(payload))
	payloadSHA := sha256.Sum256(payload)
	signatureSHA := sha256.Sum256(signature)
	doc.AuditPayloadKey = pgtype.Text{String: "org/o/documents/d/audit-payload-" + hex.EncodeToString(payloadSHA[:]) + ".txt", Valid: true}
	doc.AuditPayloadSha256 = payloadSHA[:]
	doc.AuditPayloadVersionID = pgtype.Text{String: "payload-version-1", Valid: true}
	doc.AuditSignatureKey = pgtype.Text{String: "org/o/documents/d/audit-signature-" + hex.EncodeToString(signatureSHA[:]) + ".txt", Valid: true}
	doc.AuditSignatureSha256 = signatureSHA[:]
	doc.AuditSignatureVersionID = pgtype.Text{String: "signature-version-1", Valid: true}
	q := &evidenceQueriesStub{events: []*generated.Event{event}}
	v := &evidenceVersionsStub{}
	b := &Builder{
		Q: q,
		Storage: &evidenceBlobStoreStub{objects: map[string][]byte{
			doc.FinalPdfKey.String: final, doc.AuditCertKey.String: certPDF,
			doc.AuditPayloadKey.String: payload, doc.AuditSignatureKey.String: signature,
		}},
		Versions: v, Signer: signer, CertificateTrustedPublicKeys: []string{signer.PublicKeyBase64()},
	}
	return doc, b, q, v
}

func TestBuildRejectsStatesWithoutCompletedSignedReceipt(t *testing.T) {
	for _, status := range []string{"draft", "sent", "in_progress", "declined", "voided", "expired", ""} {
		doc := &generated.Document{Status: status}
		if _, err := (&Builder{}).Build(context.Background(), doc); !errors.Is(err, ErrEvidenceUnavailable) {
			t.Errorf("status %q: got %v, want ErrEvidenceUnavailable", status, err)
		}
	}
}

func TestBuildCommitsExactCompletionEffectiveTimestamp(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixture(t)
	result, err := b.Build(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	want := doc.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)
	if result.Manifest.SchemaVersion != CurrentManifestSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", result.Manifest.SchemaVersion, CurrentManifestSchemaVersion)
	}
	if result.Manifest.CompletionEffectiveAt != want {
		t.Fatalf("completion_effective_at = %q, want %q", result.Manifest.CompletionEffectiveAt, want)
	}
}

func TestBoundCertificateDeclaresRootEventAndOrganizationChainScopes(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixture(t)
	store, ok := b.Storage.(*evidenceBlobStoreStub)
	if !ok {
		t.Fatal("fixture storage has unexpected type")
	}
	payload := store.objects[doc.AuditPayloadKey.String]
	commitments, err := ParseCertificateCommitments(payload)
	if err != nil {
		t.Fatal(err)
	}
	if commitments.PreFinalChainScope != certificateChainScopeOrganization ||
		commitments.DocumentEventsScope != certificateEventScopeCeremonyRoot {
		t.Fatalf("certificate scopes = chain:%q events:%q", commitments.PreFinalChainScope, commitments.DocumentEventsScope)
	}
	withoutEventScope := bytes.Replace(payload, []byte(` data-hash-document-events-scope="ceremony-root"`), nil, 1)
	if _, err := ParseCertificateCommitments(withoutEventScope); err == nil || !strings.Contains(err.Error(), "omits its audit scope") {
		t.Fatalf("bound certificate without event scope error = %v", err)
	}
	unsupportedChainScope := bytes.Replace(payload, []byte(`data-hash-pre-final-chain-scope="organization"`), []byte(`data-hash-pre-final-chain-scope="document"`), 1)
	if _, err := ParseCertificateCommitments(unsupportedChainScope); err == nil || !strings.Contains(err.Error(), "chain scope is unsupported") {
		t.Fatalf("bound certificate with unsupported chain scope error = %v", err)
	}
}

func TestBuildPreservesLegacyUnboundCompletionEvidenceAsSchemaV2(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixtureWithCompletionBinding(t, false)
	result, err := b.Build(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SchemaVersion != LegacyManifestSchemaVersion {
		t.Fatalf("schema_version = %d, want legacy %d", result.Manifest.SchemaVersion, LegacyManifestSchemaVersion)
	}
	if result.Manifest.CompletionEffectiveAt != "" {
		t.Fatalf("legacy manifest synthesized completion_effective_at %q", result.Manifest.CompletionEffectiveAt)
	}
}

func TestBuildRejectsCompletionTimestampDrift(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixture(t)
	doc.CompletedAt.Time = doc.CompletedAt.Time.Add(time.Microsecond)
	if _, err := b.Build(context.Background(), doc); err == nil || !strings.Contains(err.Error(), "completion-effective timestamp") {
		t.Fatalf("completion timestamp drift error = %v", err)
	}
}

func TestNoopOTSAnchor(t *testing.T) {
	a := NoopOTSAnchor{}
	out, err := a.Stamp(context.Background(), make([]byte, 32))
	if err != nil {
		t.Fatalf("noop should never error, got %v", err)
	}
	if out != nil {
		t.Fatalf("noop should return nil bytes, got %d", len(out))
	}
}

func TestHTTPOTSAnchor_RejectsWrongDigestSize(t *testing.T) {
	a := NewHTTPOTSAnchor("")
	_, err := a.Stamp(context.Background(), make([]byte, 31))
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected 32-byte error, got %v", err)
	}
}

func TestFirstCertFromPEM_ExtractsLeaf(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Mock Signer Anna Anka",
			Organization: []string{"Hash Test"},
		},
		Issuer: pkix.Name{
			CommonName: "Mock QTSP Root",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	leaf, err := firstCertFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf == nil || leaf.Subject.CommonName != "Mock Signer Anna Anka" {
		t.Errorf("subject CN = %q, want %q", leaf.Subject.CommonName, "Mock Signer Anna Anka")
	}
}

func TestFirstCertFromPEM_EmptyReturnsNil(t *testing.T) {
	leaf, err := firstCertFromPEM([]byte(""))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if leaf != nil {
		t.Errorf("expected nil cert on empty input")
	}
}

func TestManifest_QTSPBlockSerializes(t *testing.T) {
	m := Manifest{
		SchemaVersion: 1,
		DocumentID:    "doc-1",
		QTSP: []QTSPBlock{{
			Provider:            "idura",
			SessionID:           "sess-1",
			RecipientID:         "rec-1",
			CertChainSHA256:     hex.EncodeToString(make([]byte, 32)),
			CertChainAttachment: "qes-cert-chain-1.pem",
			SubjectCN:           "Test Subject",
		}},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"qtsp":[{`) {
		t.Errorf("qtsp block missing from manifest JSON: %s", s)
	}
	if !strings.Contains(s, `"subject_cn":"Test Subject"`) {
		t.Errorf("subject_cn missing")
	}
}

func TestManifest_OmitsQTSPWhenEmpty(t *testing.T) {
	m := Manifest{SchemaVersion: 1, DocumentID: "doc-1"}
	out, _ := json.Marshal(m)
	if strings.Contains(string(out), "qtsp") {
		t.Errorf("expected qtsp omitted when empty: %s", out)
	}
}

func TestManifestCanonicalShape(t *testing.T) {
	m := Manifest{
		SchemaVersion:              1,
		DocumentID:                 "doc-1",
		DocumentName:               "Test",
		FinalPDFSHA256:             hex.EncodeToString(make([]byte, 32)),
		EventsSHA256:               hex.EncodeToString(make([]byte, 32)),
		VersionsSHA256:             hex.EncodeToString(make([]byte, 32)),
		ManifestPublicKeyPEMSHA256: hex.EncodeToString(make([]byte, 32)),
		Bundle:                     BundleSummary{EventCount: 5, VersionCount: 3},
	}
	if m.SchemaVersion != 1 {
		t.Fatal("schema_version should be 1")
	}
	if len(m.FinalPDFSHA256) != 64 {
		t.Fatalf("sha256 hex should be 64 chars, got %d", len(m.FinalPDFSHA256))
	}
}

func TestBuildRejectsStoredFinalPDFHashMismatch(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixture(t)
	doc.FinalPdfSha = make([]byte, sha256.Size)
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("expected ErrArtifactIntegrity, got %v", err)
	}
}

func TestBuildRejectsEventResultThatDoesNotMatchSignedCount(t *testing.T) {
	doc, b, q, _ := evidenceBuildFixture(t)
	q.events = make([]*generated.Event, maxEvidenceEvents+1)
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("expected ErrArtifactIntegrity, got %v", err)
	}
	if q.eventLimit != 1 {
		t.Fatalf("event query limit = %d, want signed count 1", q.eventLimit)
	}
}

func TestBuildPropagatesVersionHistoryFailure(t *testing.T) {
	doc, b, _, v := evidenceBuildFixture(t)
	want := errors.New("version database unavailable")
	v.historyErr = want
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped version history error, got %v", err)
	}
	if v.historyLimit != maxEvidenceVersions+1 {
		t.Fatalf("version query limit = %d, want probe limit %d", v.historyLimit, maxEvidenceVersions+1)
	}
}

func TestBuildDetectsVersionTruncation(t *testing.T) {
	doc, b, _, v := evidenceBuildFixture(t)
	v.history = make([]*generated.DocumentVersion, maxEvidenceVersions+1)
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, ErrEvidenceTooLarge) {
		t.Fatalf("expected ErrEvidenceTooLarge, got %v", err)
	}
}

func TestBuildPropagatesMissingVersionPredecessor(t *testing.T) {
	doc, b, _, v := evidenceBuildFixture(t)
	want := errors.New("predecessor missing")
	v.history = []*generated.DocumentVersion{{
		DocumentID:    doc.ID,
		VersionNo:     2,
		BlockTreeJson: []byte(`{"version":1,"blocks":[]}`),
	}}
	v.priorErr = want
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped predecessor error, got %v", err)
	}
}

func TestBuildPropagatesVersionDiffFailure(t *testing.T) {
	doc, b, _, v := evidenceBuildFixture(t)
	v.history = []*generated.DocumentVersion{{
		DocumentID:    doc.ID,
		VersionNo:     2,
		BlockTreeJson: []byte(`not-json`),
	}}
	v.prior = &generated.DocumentVersion{
		DocumentID:    doc.ID,
		VersionNo:     1,
		BlockTreeJson: []byte(`{"version":1,"blocks":[]}`),
	}
	_, err := b.Build(context.Background(), doc)
	if err == nil || !strings.Contains(err.Error(), "diff versions 1 and 2") {
		t.Fatalf("expected version diff failure, got %v", err)
	}
}

func TestBuildPropagatesQESQueryFailure(t *testing.T) {
	doc, b, q, _ := evidenceBuildFixture(t)
	want := errors.New("QES database unavailable")
	q.qesErr = want
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped QES query error, got %v", err)
	}
	if !q.qesWasCalled {
		t.Fatal("QES query was not called")
	}
}

func TestBuildRejectsCompletedLegacyQESMaterialInsteadOfAssertingValidity(t *testing.T) {
	doc, b, q, _ := evidenceBuildFixture(t)
	q.qes = []*generated.QesSigningSession{{
		ID:          uuid.New(),
		DocumentID:  doc.ID,
		RecipientID: uuid.New(),
		Provider:    "legacy-provider",
		Status:      "completed",
	}}
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, ErrUnboundLegacyQES) {
		t.Fatalf("error = %v, want ErrUnboundLegacyQES", err)
	}
}

func TestBuildFailsWhenDeclaredAuditCertificateCannotBeLoaded(t *testing.T) {
	doc, b, _, _ := evidenceBuildFixture(t)
	want := errors.New("storage unavailable")
	finalPDF := append([]byte(nil), b.Storage.(*evidenceBlobStoreStub).objects[doc.FinalPdfKey.String]...)
	doc.AuditCertKey = pgtype.Text{String: "org/o/documents/d/audit.pdf", Valid: true}
	certDigest := sha256.Sum256([]byte("declared-audit-certificate"))
	doc.AuditCertSha256 = certDigest[:]
	b.Storage = &evidenceBlobStoreStub{
		objects: map[string][]byte{doc.FinalPdfKey.String: finalPDF},
		err:     want,
	}
	_, err := b.Build(context.Background(), doc)
	if !errors.Is(err, want) {
		t.Fatalf("expected declared certificate load failure, got %v", err)
	}
}
