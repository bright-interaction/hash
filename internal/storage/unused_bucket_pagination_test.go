// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func newUnusedBucketTestClient(t *testing.T, handler http.Handler) (*minio.Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds:        credentials.NewStaticV4("access", "secret", ""),
		Secure:       false,
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server.Close
}

func TestCheckBootstrapEstateInventoryFollowsBothVersionAndMultipartMarkers(t *testing.T) {
	var versionPages, uploadPages atomic.Int32
	client, closeServer := newUnusedBucketTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		query := r.URL.Query()
		if _, ok := query["versions"]; ok {
			page := versionPages.Add(1)
			if page == 1 {
				_, _ = fmt.Fprint(w, `<ListVersionsResult><Name>hash</Name><IsTruncated>true</IsTruncated><NextKeyMarker>next-key</NextKeyMarker><NextVersionIdMarker>next-version</NextVersionIdMarker></ListVersionsResult>`)
				return
			}
			if query.Get("key-marker") != "next-key" || query.Get("version-id-marker") != "next-version" {
				http.Error(w, "missing version markers", http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprint(w, `<ListVersionsResult><Name>hash</Name><IsTruncated>false</IsTruncated></ListVersionsResult>`)
			return
		}
		if _, ok := query["uploads"]; ok {
			page := uploadPages.Add(1)
			if page == 1 {
				_, _ = fmt.Fprint(w, `<ListMultipartUploadsResult><Bucket>hash</Bucket><IsTruncated>true</IsTruncated><NextKeyMarker>upload-key</NextKeyMarker><NextUploadIdMarker>upload-id</NextUploadIdMarker></ListMultipartUploadsResult>`)
				return
			}
			if query.Get("key-marker") != "upload-key" || query.Get("upload-id-marker") != "upload-id" {
				http.Error(w, "missing upload markers", http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprint(w, `<ListMultipartUploadsResult><Bucket>hash</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`)
			return
		}
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}))
	defer closeServer()
	if err := checkBootstrapEstateInventory(context.Background(), client, "hash", nil); err != nil {
		t.Fatal(err)
	}
	if versionPages.Load() != 2 || uploadPages.Load() != 2 {
		t.Fatalf("pagination pages versions=%d uploads=%d", versionPages.Load(), uploadPages.Load())
	}
}

func TestCheckBootstrapEstateInventoryRejectsMalformedTruncatedPagination(t *testing.T) {
	for _, malformed := range []string{"versions", "uploads"} {
		t.Run(malformed, func(t *testing.T) {
			var requests atomic.Int32
			client, closeServer := newUnusedBucketTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				query := r.URL.Query()
				if malformed == "versions" && query.Has("versions") {
					if requests.Add(1) > 1 {
						http.Error(w, "repeated empty continuation", http.StatusInternalServerError)
						return
					}
					_, _ = fmt.Fprint(w, `<ListVersionsResult><Name>hash</Name><IsTruncated>true</IsTruncated></ListVersionsResult>`)
					return
				}
				if query.Has("versions") {
					_, _ = fmt.Fprint(w, `<ListVersionsResult><Name>hash</Name><IsTruncated>false</IsTruncated></ListVersionsResult>`)
					return
				}
				if malformed == "uploads" && query.Has("uploads") {
					if requests.Add(1) > 1 {
						http.Error(w, "repeated empty continuation", http.StatusInternalServerError)
						return
					}
					_, _ = fmt.Fprint(w, `<ListMultipartUploadsResult><Bucket>hash</Bucket><IsTruncated>true</IsTruncated></ListMultipartUploadsResult>`)
					return
				}
				http.Error(w, "unexpected request", http.StatusBadRequest)
			}))
			defer closeServer()
			if err := checkBootstrapEstateInventory(context.Background(), client, "hash", nil); err == nil {
				t.Fatal("malformed truncated pagination was accepted")
			}
		})
	}
}
