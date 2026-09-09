// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

type recordedDataPlaneRequest struct {
	method            string
	path              string
	version           string
	serverEncryption  string
	customerAlgorithm string
	hasCustomerKey    bool
	hasCustomerMD5    bool
	customerKeySHA256 [sha256.Size]byte
}

type fakeVersionedS3 struct {
	mu                        sync.Mutex
	encryptionMode            encrypt.Type
	payload                   []byte
	requests                  []recordedDataPlaneRequest
	storedCustomerKey         string
	storedCustomerMD5         string
	logicalDeleted            bool
	exactDeleted              bool
	shadowLatestAfterDelete   bool
	preexistingShadow         bool
	ignoreSSECKey             bool
	omitSSES3ResponseMetadata bool
	denyExactDelete           bool
	retentionMode             minio.RetentionMode
	retentionUntil            time.Time
	retentionGetCalls         int
	retentionPutCalls         int
	versionListCalls          int
	prefixCollisionPages      int
	prefixCollisionExact      bool
}

type cancellationErrorVersionLister struct {
	key        string
	secondSent chan struct{}
	exited     chan struct{}
	opts       minio.ListObjectsOptions
}

func (l *cancellationErrorVersionLister) ListObjects(ctx context.Context, _ string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	l.opts = opts
	items := make(chan minio.ObjectInfo, 1)
	go func() {
		defer close(l.exited)
		defer close(items)
		items <- minio.ObjectInfo{Key: l.key, VersionID: "provider-version-1"}
		items <- minio.ObjectInfo{Key: l.key + "~collision", VersionID: "collision-version"}
		close(l.secondSent)
		<-ctx.Done()
		// minio-go emits this final context error without a cancellation select.
		// It blocks behind the buffered collision unless the consumer drains.
		items <- minio.ObjectInfo{Err: ctx.Err()}
	}()
	return items
}

func (f *fakeVersionedS3) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Query().Has("versions") {
		f.serveVersionList(w, r)
		return
	}
	if r.URL.Query().Has("retention") {
		f.serveRetention(w, r)
		return
	}
	versionID := r.URL.Query().Get("versionId")
	customerKey := r.Header.Get(encrypt.SseCustomerKey)
	f.requests = append(f.requests, recordedDataPlaneRequest{
		method:            r.Method,
		path:              r.URL.Path,
		version:           versionID,
		serverEncryption:  r.Header.Get(encrypt.SseGenericHeader),
		customerAlgorithm: r.Header.Get(encrypt.SseCustomerAlgorithm),
		hasCustomerKey:    customerKey != "",
		hasCustomerMD5:    r.Header.Get(encrypt.SseCustomerKeyMD5) != "",
		customerKeySHA256: sha256.Sum256([]byte(customerKey)),
	})
	if r.Method != http.MethodDelete && !f.acceptEncryptionHeaders(r) {
		writeFakeS3Error(w, r, http.StatusBadRequest, "InvalidRequest")
		return
	}

	const objectVersion = "provider-version-1"
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		f.payload = append([]byte(nil), body...)
		if f.encryptionMode == encrypt.SSEC {
			f.storedCustomerKey = r.Header.Get(encrypt.SseCustomerKey)
			f.storedCustomerMD5 = r.Header.Get(encrypt.SseCustomerKeyMD5)
		}
		w.Header().Set("ETag", `"probe-etag"`)
		w.Header().Set("X-Amz-Version-Id", objectVersion)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		notFound := len(f.payload) == 0 || (f.exactDeleted && versionID == objectVersion) ||
			(f.logicalDeleted && versionID == "") ||
			(f.exactDeleted && !f.shadowLatestAfterDelete && versionID == "")
		if notFound {
			w.Header().Set("X-Amz-Request-Id", "probe-request")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		responseVersion := objectVersion
		if f.exactDeleted && f.shadowLatestAfterDelete && !f.logicalDeleted && versionID == "" {
			responseVersion = "shadow-version"
		} else if versionID != "" && versionID != objectVersion {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(f.payload)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"probe-etag"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Header().Set("X-Amz-Version-Id", responseVersion)
		if f.encryptionMode == encrypt.S3 && !f.omitSSES3ResponseMetadata {
			w.Header().Set(encrypt.SseGenericHeader, "AES256")
		} else if f.encryptionMode == encrypt.SSEC {
			w.Header().Set(encrypt.SseCustomerAlgorithm, "AES256")
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(f.payload)
		}
	case http.MethodDelete:
		if versionID == "" {
			f.logicalDeleted = true
			w.Header().Set("X-Amz-Delete-Marker", "true")
		} else if versionID == objectVersion {
			if f.denyExactDelete {
				writeFakeS3Error(w, r, http.StatusForbidden, "AccessDenied")
				return
			}
			f.exactDeleted = true
		} else {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeVersionedS3) serveRetention(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("versionId") != "provider-version-1" || f.retentionMode == "" || f.retentionUntil.IsZero() {
		writeFakeS3Error(w, r, http.StatusNotFound, "NoSuchObjectLockConfiguration")
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.retentionGetCalls++
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w,
			`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
			f.retentionMode, f.retentionUntil.UTC().Format(time.RFC3339))
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Contains(body, []byte("<Mode>COMPLIANCE</Mode>")) ||
			!bytes.Contains(body, []byte(f.retentionUntil.UTC().Format(time.RFC3339))) {
			writeFakeS3Error(w, r, http.StatusBadRequest, "InvalidRequest")
			return
		}
		f.retentionPutCalls++
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeVersionedS3) serveVersionList(w http.ResponseWriter, r *http.Request) {
	f.versionListCalls++
	key := r.URL.Query().Get("prefix")
	if f.prefixCollisionPages > 0 {
		page := f.versionListCalls
		truncated := page < f.prefixCollisionPages
		nextKeyMarker := ""
		if truncated {
			nextKeyMarker = fmt.Sprintf("%s~collision-%06d", key, page)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>hash-canary</Name><Prefix>%s</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><NextKeyMarker>%s</NextKeyMarker><MaxKeys>2</MaxKeys><IsTruncated>%t</IsTruncated>`, key, nextKeyMarker, truncated)
		if page == 1 && f.prefixCollisionExact {
			_, _ = fmt.Fprintf(w, `<Version><Key>%s</Key><VersionId>provider-version-1</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:00Z</LastModified><ETag>&quot;probe-etag&quot;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, key, len(f.payload))
		}
		_, _ = fmt.Fprintf(w, `<Version><Key>%s~collision-%06d</Key><VersionId>collision-version-%06d</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:01Z</LastModified><ETag>&quot;collision-etag&quot;</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Version>`, key, page, page)
		_, _ = fmt.Fprint(w, `</ListVersionsResult>`)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = fmt.Fprintf(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>hash-canary</Name><Prefix>%s</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><MaxKeys>2</MaxKeys><IsTruncated>false</IsTruncated>`, key)
	if len(f.payload) != 0 && !f.exactDeleted {
		_, _ = fmt.Fprintf(w, `<Version><Key>%s</Key><VersionId>provider-version-1</VersionId><IsLatest>%t</IsLatest><LastModified>2026-09-09T00:00:00Z</LastModified><ETag>&quot;probe-etag&quot;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, key, !f.logicalDeleted, len(f.payload))
	}
	if f.preexistingShadow {
		_, _ = fmt.Fprintf(w, `<Version><Key>%s</Key><VersionId>shadow-version</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:01Z</LastModified><ETag>&quot;shadow-etag&quot;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, key, len(f.payload))
	}
	if f.shadowLatestAfterDelete && f.exactDeleted {
		_, _ = fmt.Fprintf(w, `<Version><Key>%s</Key><VersionId>shadow-version</VersionId><IsLatest>%t</IsLatest><LastModified>2026-09-09T00:00:01Z</LastModified><ETag>&quot;shadow-etag&quot;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, key, !f.logicalDeleted, len(f.payload))
	}
	if f.logicalDeleted {
		_, _ = fmt.Fprintf(w, `<DeleteMarker><Key>%s</Key><VersionId>delete-marker-1</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:02Z</LastModified></DeleteMarker>`, key)
	}
	_, _ = fmt.Fprint(w, `</ListVersionsResult>`)
}

func (f *fakeVersionedS3) acceptEncryptionHeaders(r *http.Request) bool {
	switch f.encryptionMode {
	case encrypt.S3:
		if r.Method == http.MethodPut {
			return r.Header.Get(encrypt.SseGenericHeader) == "AES256" &&
				r.Header.Get(encrypt.SseCustomerAlgorithm) == "" &&
				r.Header.Get(encrypt.SseCustomerKey) == "" &&
				r.Header.Get(encrypt.SseCustomerKeyMD5) == ""
		}
		return r.Header.Get(encrypt.SseGenericHeader) == "" &&
			r.Header.Get(encrypt.SseCustomerAlgorithm) == "" &&
			r.Header.Get(encrypt.SseCustomerKey) == "" &&
			r.Header.Get(encrypt.SseCustomerKeyMD5) == ""
	case encrypt.SSEC:
		if r.Header.Get(encrypt.SseGenericHeader) != "" ||
			r.Header.Get(encrypt.SseCustomerAlgorithm) != "AES256" ||
			r.Header.Get(encrypt.SseCustomerKey) == "" ||
			r.Header.Get(encrypt.SseCustomerKeyMD5) == "" {
			return false
		}
		if r.Method == http.MethodPut || f.ignoreSSECKey {
			return true
		}
		return r.Header.Get(encrypt.SseCustomerKey) == f.storedCustomerKey &&
			r.Header.Get(encrypt.SseCustomerKeyMD5) == f.storedCustomerMD5
	default:
		return false
	}
}

func writeFakeS3Error(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("X-Amz-Request-Id", "probe-request")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = fmt.Fprintf(w, "<Error><Code>%s</Code><Message>request rejected</Message></Error>", code)
	}
}

func newFakeDataPlaneClient(t *testing.T, fake *fakeVersionedS3) (*Client, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := minio.New(endpoint.Host, &minio.Options{
		Creds:        credentials.NewStaticV4("test-access", "test-secret", ""),
		Secure:       true,
		Region:       "eu-central-1",
		BucketLookup: minio.BucketLookupPath,
		Transport:    server.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{mc: sdk, bucket: "hash-canary", requireEvidenceLock: true}
	switch fake.encryptionMode {
	case encrypt.S3:
		client.writeServerSideEncryption = encrypt.NewSSE()
		client.sseMode = "sse-s3"
		return client, nil
	case encrypt.SSEC:
		key := []byte("0123456789abcdef0123456789abcdef")
		sse, err := encrypt.NewSSEC(key)
		if err != nil {
			t.Fatal(err)
		}
		client.writeServerSideEncryption = sse
		client.readServerSideEncryption = sse
		client.sseMode = "sse-c"
		return client, key
	default:
		t.Fatal("fake data-plane client needs an encryption mode")
		return nil, nil
	}
}

func TestCheckDataPlaneCarriesSSECAndUsesSafeCleanup(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.SSEC}
	client, _ := newFakeDataPlaneClient(t, fake)
	if err := client.CheckDataPlane(context.Background()); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.payload) != dataPlaneCheckPayloadBytes {
		t.Fatalf("probe payload length = %d, want %d", len(fake.payload), dataPlaneCheckPayloadBytes)
	}
	var deleteRequests int
	deleteSeen := false
	postDeleteExactHead := false
	customerKeyFingerprints := make(map[[sha256.Size]byte]struct{})
	var correctCustomerKeyFingerprint [sha256.Size]byte
	wrongKeyHeadSeen := false
	wrongKeyGetSeen := false
	for _, req := range fake.requests {
		if !strings.HasPrefix(req.path, "/hash-canary/"+dataPlaneCheckPrefix) {
			t.Fatalf("request escaped reserved canary prefix: %s", req.path)
		}
		suffix := strings.TrimPrefix(req.path, "/hash-canary/"+dataPlaneCheckPrefix)
		if len(suffix) != 32 {
			t.Fatalf("canary suffix length = %d, want 32 hex characters", len(suffix))
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			t.Fatalf("canary suffix is not hexadecimal: %v", err)
		}
		switch req.method {
		case http.MethodPut, http.MethodGet, http.MethodHead:
			if req.customerAlgorithm != "AES256" || !req.hasCustomerKey || !req.hasCustomerMD5 {
				t.Fatalf("%s request omitted SSE-C headers", req.method)
			}
			customerKeyFingerprints[req.customerKeySHA256] = struct{}{}
			if req.method == http.MethodPut {
				correctCustomerKeyFingerprint = req.customerKeySHA256
			} else if correctCustomerKeyFingerprint != ([sha256.Size]byte{}) &&
				req.customerKeySHA256 != correctCustomerKeyFingerprint && req.version == "provider-version-1" {
				if req.method == http.MethodHead {
					wrongKeyHeadSeen = true
				} else if req.method == http.MethodGet {
					wrongKeyGetSeen = true
				}
			}
			if deleteSeen && req.method == http.MethodHead && req.version == "provider-version-1" {
				postDeleteExactHead = true
			}
		case http.MethodDelete:
			deleteRequests++
			deleteSeen = true
			if req.version != "provider-version-1" {
				t.Fatalf("DELETE VersionId = %q, want exact provider version", req.version)
			}
		}
	}
	if deleteRequests != 1 || !fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("canary cleanup did not delete only its exact probe version")
	}
	if fake.versionListCalls < 3 {
		t.Fatalf("canary version-list proofs = %d, want pre-PUT, pre-delete, and post-delete", fake.versionListCalls)
	}
	if len(customerKeyFingerprints) < 2 || !wrongKeyHeadSeen || !wrongKeyGetSeen {
		t.Fatal("SSE-C canary did not prove both correct-key use and distinct wrong-key rejection")
	}
	if !postDeleteExactHead {
		t.Fatal("canary cleanup did not verify exact-version absence")
	}
}

func TestCheckDataPlanePreservesDefaultSSES3ReadPolicy(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3}
	client, _ := newFakeDataPlaneClient(t, fake)
	if err := client.CheckDataPlane(context.Background()); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, req := range fake.requests {
		switch req.method {
		case http.MethodPut:
			if req.serverEncryption != "AES256" {
				t.Fatal("SSE-S3 canary PUT omitted AES256 policy")
			}
		case http.MethodGet, http.MethodHead:
			if req.serverEncryption != "" || req.customerAlgorithm != "" || req.hasCustomerKey || req.hasCustomerMD5 {
				t.Fatalf("%s sent a write-only encryption header on an SSE-S3 read", req.method)
			}
		case http.MethodDelete:
			if req.version != "provider-version-1" {
				t.Fatal("default SSE-S3 canary did not request exact version deletion")
			}
		}
	}
}

func TestCheckDataPlaneRejectsMissingSSES3ResponseProof(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, omitSSES3ResponseMetadata: true}
	client, _ := newFakeDataPlaneClient(t, fake)
	err := client.CheckDataPlane(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not report SSE-S3 AES256") {
		t.Fatalf("missing SSE-S3 response proof accepted: %v", err)
	}
	if !fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("failed SSE-S3 proof did not physically clean up its exact probe version")
	}
}

func TestFakeProviderRejectsPlaintextCanaryWrite(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3}
	client, _ := newFakeDataPlaneClient(t, fake)
	client.writeServerSideEncryption = nil
	if err := client.CheckDataPlane(context.Background()); err == nil || !strings.Contains(err.Error(), "storage data-plane PUT") {
		t.Fatalf("fake provider accepted a plaintext canary write: %v", err)
	}
}

func TestCheckDataPlaneRejectsSSECProviderThatIgnoresCustomerKeyWithoutLeakingIt(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.SSEC, ignoreSSECKey: true}
	client, key := newFakeDataPlaneClient(t, fake)
	err := client.CheckDataPlane(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HEAD was not rejected") {
		t.Fatalf("SSE-C provider that ignored the customer key accepted: %v", err)
	}
	keyMD5 := md5.Sum(key)
	for _, sensitive := range []string{
		string(key),
		base64.StdEncoding.EncodeToString(key),
		base64.StdEncoding.EncodeToString(keyMD5[:]),
	} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatal("negative SSE-C proof leaked key material or its request MD5")
		}
	}
	if !fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("failed SSE-C proof did not physically clean up its exact probe version")
	}
}

func TestVerifyRetentionConformanceIsNoOpAndProvesDeleteDenial(t *testing.T) {
	payload := []byte("reserved bootstrap control marker")
	digest := sha256.Sum256(payload)
	deadline := time.Date(2033, time.January, 2, 3, 4, 5, 0, time.UTC)
	fake := &fakeVersionedS3{
		encryptionMode:  encrypt.S3,
		payload:         append([]byte(nil), payload...),
		denyExactDelete: true,
		retentionMode:   minio.Compliance,
		retentionUntil:  deadline,
	}
	client, _ := newFakeDataPlaneClient(t, fake)
	if err := client.VerifyRetentionConformance(context.Background(), "org/customer/evidence.pdf",
		"provider-version-1", digest[:], deadline.Add(-time.Hour)); err == nil || !strings.Contains(err.Error(), "reserved bootstrap-estate control key") {
		t.Fatalf("retention conformance accepted customer evidence: %v", err)
	}
	if err := client.VerifyRetentionConformance(context.Background(), "_hash/bootstrap-estate/v1",
		"provider-version-1", digest[:], deadline.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.retentionPutCalls != 1 || fake.retentionGetCalls != 3 {
		t.Fatalf("retention calls = PUT %d / GET %d, want 1 / 3", fake.retentionPutCalls, fake.retentionGetCalls)
	}
	if fake.exactDeleted || fake.logicalDeleted || !fake.retentionUntil.Equal(deadline) {
		t.Fatal("retention conformance changed or deleted the reserved control version")
	}
}

func TestExplicitRetentionDeleteDenialRejectsAmbiguousFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "explicit provider forbidden", err: minio.ErrorResponse{StatusCode: http.StatusForbidden}, want: true},
		{name: "explicit provider forbidden pointer", err: &minio.ErrorResponse{StatusCode: http.StatusForbidden}, want: true},
		{name: "bad request", err: minio.ErrorResponse{StatusCode: http.StatusBadRequest}},
		{name: "transport failure", err: errors.New("connection reset")},
		{name: "nil", err: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isExplicitRetentionDeleteDenial(test.err); got != test.want {
				t.Fatalf("isExplicitRetentionDeleteDenial() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPermanentCleanupRejectsVersionCreatedDuringDeletion(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, shadowLatestAfterDelete: true}
	client, _ := newFakeDataPlaneClient(t, fake)
	err := client.CheckDataPlane(context.Background())
	if err == nil || !strings.Contains(err.Error(), "post-delete inventory") {
		t.Fatalf("permanent cleanup ignored a newer latest version: %v", err)
	}
	if !fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("failed permanent cleanup should remove only its exact version without creating a delete marker")
	}
}

func TestExactKeyScanCancelsAndDrainsMinIOStyleIterator(t *testing.T) {
	key := "org/test/documents/source.pdf"
	lister := &cancellationErrorVersionLister{
		key:        key,
		secondSent: make(chan struct{}),
		exited:     make(chan struct{}),
	}
	visited := 0
	err := scanExactKeyVersions(context.Background(), lister, "hash-canary", key, 2, func(_ context.Context, item minio.ObjectInfo) (bool, error) {
		visited++
		if item.Key != key || item.VersionID != "provider-version-1" {
			t.Fatalf("visitor received unexpected item: %#v", item)
		}
		<-lister.secondSent
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if visited != 1 {
		t.Fatalf("visited versions = %d, want 1", visited)
	}
	if lister.opts.Prefix != key || !lister.opts.Recursive || !lister.opts.WithVersions || lister.opts.MaxKeys != 2 {
		t.Fatalf("unexpected exact-key list options: %#v", lister.opts)
	}
	select {
	case <-lister.exited:
	case <-time.After(time.Second):
		t.Fatal("cancelled version-list producer remained blocked on its final channel send")
	}
}

func TestExactKeyInventoryStopsBeforeAdversarialPrefixPagination(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, prefixCollisionPages: 64}
	client, _ := newFakeDataPlaneClient(t, fake)
	key := "org/test/documents/source.pdf"
	if err := client.verifyExactKeyVersionInventory(context.Background(), key, ""); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.versionListCalls == 0 || fake.versionListCalls > 2 {
		t.Fatalf("prefix-collision inventory requests = %d, want at most first page plus one cancellation race", fake.versionListCalls)
	}
}

func TestResolveVerifiedLegacyStopsBeforeAdversarialPrefixPagination(t *testing.T) {
	payload := []byte("latest shadow bytes")
	fake := &fakeVersionedS3{
		encryptionMode:       encrypt.S3,
		payload:              append([]byte(nil), payload...),
		prefixCollisionPages: 64,
		prefixCollisionExact: true,
	}
	client, _ := newFakeDataPlaneClient(t, fake)
	wanted := sha256.Sum256([]byte("committed historical bytes that are absent"))
	_, _, err := client.ResolveVerifiedLegacy(context.Background(), "org/test/documents/source.pdf", wanted[:])
	if !errors.Is(err, errStoredVersionNotFound) {
		t.Fatalf("missing committed legacy version error = %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.versionListCalls == 0 || fake.versionListCalls > 2 {
		t.Fatalf("legacy prefix-collision requests = %d, want at most first page plus one cancellation race", fake.versionListCalls)
	}
}

func TestDeleteVersionPhysicallyRemovesSoleCommittedVersion(t *testing.T) {
	payload := []byte("mutable draft customer PDF")
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...)}
	client, _ := newFakeDataPlaneClient(t, fake)
	digest := sha256.Sum256(payload)
	if err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", "provider-version-1", digest[:]); err != nil {
		t.Fatal(err)
	}
	if !fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("exact cleanup did not physically remove only the committed version")
	}
	if fake.versionListCalls < 2 {
		t.Fatalf("version-list proofs = %d, want pre- and post-delete", fake.versionListCalls)
	}
}

func TestDeleteVersionRefusesShadowOrDeleteMarkerBeforeMutation(t *testing.T) {
	payload := []byte("mutable draft customer PDF")
	digest := sha256.Sum256(payload)
	for _, test := range []struct {
		name string
		fake *fakeVersionedS3
	}{
		{
			name: "shadow version",
			fake: &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...), preexistingShadow: true},
		},
		{
			name: "delete marker",
			fake: &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...), logicalDeleted: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newFakeDataPlaneClient(t, test.fake)
			err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", "provider-version-1", digest[:])
			if err == nil || !strings.Contains(err.Error(), "pre-delete inventory") {
				t.Fatalf("ambiguous history accepted: %v", err)
			}
			if test.fake.exactDeleted {
				t.Fatal("ambiguous history was mutated")
			}
		})
	}
}

func TestDeleteVersionAcceptsAlreadyEmptyHistoryForCrashRetry(t *testing.T) {
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3}
	client, _ := newFakeDataPlaneClient(t, fake)
	digest := sha256.Sum256([]byte("previously deleted bytes"))
	if err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", "provider-version-1", digest[:]); err != nil {
		t.Fatal(err)
	}
	if fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("idempotent empty-history retry issued a delete")
	}
}

func TestDeleteVersionDigestMismatchDoesNotDelete(t *testing.T) {
	payload := []byte("authentic draft bytes")
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...)}
	client, _ := newFakeDataPlaneClient(t, fake)
	wrong := sha256.Sum256([]byte("different bytes"))
	err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", "provider-version-1", wrong[:])
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
	if fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("digest mismatch mutated provider state")
	}
}

func TestDeleteVersionPropagatesProviderRetentionDenial(t *testing.T) {
	payload := []byte("unexpected retained draft bytes")
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...), denyExactDelete: true}
	client, _ := newFakeDataPlaneClient(t, fake)
	digest := sha256.Sum256(payload)
	err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", "provider-version-1", digest[:])
	if err == nil || !strings.Contains(err.Error(), "delete exact object version") {
		t.Fatalf("provider retention denial not propagated: %v", err)
	}
	if fake.exactDeleted || fake.logicalDeleted {
		t.Fatal("denied exact delete changed provider state")
	}
}

func TestDeleteVersionDevelopmentSentinelUsesLogicalDelete(t *testing.T) {
	payload := []byte("local disposable draft")
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append([]byte(nil), payload...)}
	client, _ := newFakeDataPlaneClient(t, fake)
	client.requireEvidenceLock = false
	digest := sha256.Sum256(payload)
	if err := client.DeleteVersion(context.Background(), "org/test/documents/source.pdf", DevelopmentVersionID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if !fake.logicalDeleted || fake.exactDeleted {
		t.Fatal("development sentinel did not use the unversioned logical-delete path")
	}
}

func TestNewDataPlaneCheckProbeIsUniqueAndBounded(t *testing.T) {
	firstKey, firstPayload, err := newDataPlaneCheckProbe()
	if err != nil {
		t.Fatal(err)
	}
	secondKey, secondPayload, err := newDataPlaneCheckProbe()
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == secondKey {
		t.Fatal("successive canary keys collided")
	}
	if !strings.HasPrefix(firstKey, dataPlaneCheckPrefix) || !strings.HasPrefix(secondKey, dataPlaneCheckPrefix) {
		t.Fatal("canary key escaped reserved prefix")
	}
	if len(firstPayload) != dataPlaneCheckPayloadBytes || len(secondPayload) != dataPlaneCheckPayloadBytes {
		t.Fatal("canary payload is not fixed and bounded")
	}
	if bytes.Equal(firstPayload, secondPayload) {
		t.Fatal("successive canary payloads unexpectedly matched")
	}
}

func TestObjectNotFoundIncludesDeletedExactVersion(t *testing.T) {
	for _, err := range []error{
		minio.ErrorResponse{Code: "NoSuchVersion"},
		&minio.ErrorResponse{Code: "NoSuchVersion"},
	} {
		if !isObjectNotFound(err) {
			t.Fatal("NoSuchVersion was not accepted as successful exact-version cleanup")
		}
	}
}

func TestSSECKeyRejectionRequiresProviderClientError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "bad request", err: minio.ErrorResponse{StatusCode: http.StatusBadRequest}, want: true},
		{name: "forbidden pointer", err: &minio.ErrorResponse{StatusCode: http.StatusForbidden}, want: true},
		{name: "not found", err: minio.ErrorResponse{StatusCode: http.StatusNotFound}},
		{name: "server error", err: minio.ErrorResponse{StatusCode: http.StatusInternalServerError}},
		{name: "transport error", err: fmt.Errorf("connection closed")},
		{name: "nil", err: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isSSECKeyRejection(test.err); got != test.want {
				t.Fatalf("isSSECKeyRejection() = %t, want %t", got, test.want)
			}
		})
	}
}
