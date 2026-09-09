// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"github.com/gotenberg/gotenberg/v8/pkg/modules/pdfengines"
)

func TestModuleGraphIsRenderOnly(t *testing.T) {
	descriptors := gotenberg.GetModuleDescriptors()
	ids := make([]string, len(descriptors))
	for i, descriptor := range descriptors {
		ids[i] = descriptor.ID
	}
	want := []string{"api", "chromium", renderOnlyEngineID, "pdfengines"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("module IDs = %v, want %v", ids, want)
	}
}

// GHSA-86m8-88fq-xfxp affected Gotenberg through v8.32.0 because transition
// and site-local IPv6 addresses could encapsulate private IPv4 destinations.
// Keep a direct regression assertion on the checksum-pinned v8.36 helper in
// addition to Hash's stricter deny-all-HTTP renderer policy.
func TestPinnedUpstreamRejectsTransitionAndSiteLocalIPv6(t *testing.T) {
	for _, raw := range []string{
		"2002:a9fe:a9fe::",     // 6to4 wrapping 169.254.169.254.
		"64:ff9b::a9fe:a9fe",   // NAT64 well-known prefix.
		"64:ff9b:1::a9fe:a9fe", // NAT64 local-use prefix.
		"fec0::1",              // Deprecated site-local range.
	} {
		if gotenberg.IsPublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("IsPublicIP(%s) = true, want false", raw)
		}
	}
	if !gotenberg.IsPublicIP(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Error("known public IPv6 control was rejected")
	}
}

// Hash's request fields control Chromium printing only. This test pins the
// upstream no-op behavior that allows the native PDF to pass through without
// invoking the deliberately unsupported PDF post-processing engine.
func TestHashDefaultConversionDoesNotCallPdfEngine(t *testing.T) {
	engine := new(renderOnlyEngine)
	paths := []string{"input.pdf"}

	got, err := pdfengines.SplitPdfStub(nil, engine, gotenberg.SplitMode{}, paths)
	if err != nil || !reflect.DeepEqual(got, paths) {
		t.Fatalf("split no-op = %v, %v", got, err)
	}
	for operation, err := range map[string]error{
		"watermark":      pdfengines.WatermarkStub(nil, engine, nil, paths),
		"stamp":          pdfengines.StampStub(nil, engine, nil, paths),
		"rotate":         pdfengines.RotateStub(nil, engine, 0, "", paths),
		"optimize":       pdfengines.OptimizeStub(nil, engine, false, 80, paths),
		"write metadata": pdfengines.WriteMetadataStub(nil, engine, nil, paths),
		"embed":          pdfengines.EmbedFilesStub(nil, engine, nil, paths),
		"embed metadata": pdfengines.EmbedFilesMetadataStub(nil, engine, nil, paths),
		"Factur-X":       pdfengines.ApplyFacturXStub(nil, engine, gotenberg.FacturX{}, "", paths),
		"encrypt": pdfengines.EncryptPdfStub(nil, engine, gotenberg.EncryptOptions{
			Permissions: gotenberg.PdfPermissions{
				AllowPrinting:     true,
				AllowCopying:      true,
				AllowModifying:    true,
				AllowAnnotating:   true,
				AllowFillingForms: true,
				AllowAssembling:   true,
			},
		}, paths),
	} {
		if err != nil {
			t.Errorf("%s no-op: %v", operation, err)
		}
	}

	formats := pdfengines.FacturXPdfFormats(nil, engine, gotenberg.FacturX{}, gotenberg.PdfFormats{}, true, nil)
	got, err = pdfengines.ConvertStub(nil, engine, formats, paths)
	if err != nil || !reflect.DeepEqual(got, paths) {
		t.Fatalf("convert no-op = %v, %v", got, err)
	}
}

// Pin the pass-through conditions of every remaining upstream PDF-engine
// helper. Chromium does not call merge, flatten, or bookmark helpers during
// HTML conversion, but covering them here prevents a future route refactor
// from turning an empty/default option into an unexpected engine call.
func TestOtherPdfEngineStubsDoNotCallEngineForNoOpInputs(t *testing.T) {
	engine := new(renderOnlyEngine)
	paths := []string{"input.pdf"}

	merged, err := pdfengines.MergeStub(nil, engine, paths)
	if err != nil || merged != paths[0] {
		t.Fatalf("merge pass-through = %q, %v", merged, err)
	}
	if err := pdfengines.FlattenStub(nil, engine, nil); err != nil {
		t.Fatalf("flatten empty input: %v", err)
	}
	if err := pdfengines.WriteBookmarksStub(nil, engine, nil, paths); err != nil {
		t.Fatalf("write bookmarks no-op: %v", err)
	}
	if err := pdfengines.InjectFacturXXMPStub(nil, engine, gotenberg.FacturX{}, paths); err != nil {
		t.Fatalf("inject Factur-X no-op: %v", err)
	}
}

func TestRenderOnlyEngineIdentityAndFailClosedContract(t *testing.T) {
	engine := new(renderOnlyEngine)
	descriptor := engine.Descriptor()
	if descriptor.ID != renderOnlyEngineID || descriptor.New == nil {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	if _, ok := descriptor.New().(*renderOnlyEngine); !ok {
		t.Fatalf("descriptor New returned %T", descriptor.New())
	}

	ctx := context.Background()
	type operationResult struct {
		name string
		err  error
	}
	checks := []operationResult{
		{"merge", engine.Merge(ctx, nil, nil, "")},
		{"flatten", engine.Flatten(ctx, nil, "")},
		{"convert", engine.Convert(ctx, nil, gotenberg.PdfFormats{}, "", "")},
		{"optimize images", engine.OptimizeImages(ctx, nil, 80, "")},
		{"write metadata", engine.WriteMetadata(ctx, nil, nil, "")},
		{"write bookmarks", engine.WriteBookmarks(ctx, nil, "", nil)},
		{"encrypt", engine.Encrypt(ctx, nil, "", gotenberg.EncryptOptions{})},
		{"embed files", engine.EmbedFiles(ctx, nil, nil, "")},
		{"embed metadata", engine.EmbedFilesMetadata(ctx, nil, nil, "")},
		{"watermark", engine.Watermark(ctx, nil, "", gotenberg.Stamp{})},
		{"stamp", engine.Stamp(ctx, nil, "", gotenberg.Stamp{})},
		{"rotate", engine.Rotate(ctx, nil, "", 90, "")},
		{"inject Factur-X XMP", engine.InjectFacturXXMP(ctx, nil, gotenberg.FacturX{}, "")},
	}

	splitPaths, splitErr := engine.Split(ctx, nil, gotenberg.SplitMode{}, "", "")
	if splitPaths != nil {
		t.Errorf("split paths = %v, want nil", splitPaths)
	}
	checks = append(checks, operationResult{"split", splitErr})

	metadata, metadataErr := engine.ReadMetadata(ctx, nil, "")
	if metadata != nil {
		t.Errorf("metadata = %v, want nil", metadata)
	}
	checks = append(checks, operationResult{"read metadata", metadataErr})

	pageCount, pageCountErr := engine.PageCount(ctx, nil, "")
	if pageCount != 0 {
		t.Errorf("page count = %d, want 0", pageCount)
	}
	checks = append(checks, operationResult{"page count", pageCountErr})

	bookmarks, bookmarksErr := engine.ReadBookmarks(ctx, nil, "")
	if bookmarks != nil {
		t.Errorf("bookmarks = %v, want nil", bookmarks)
	}
	checks = append(checks, operationResult{"read bookmarks", bookmarksErr})

	part, conformance, conformanceErr := engine.ReadPdfAConformance(ctx, nil, "")
	if part != "" || conformance != "" {
		t.Errorf("PDF/A conformance = %q, %q, want empty", part, conformance)
	}
	checks = append(checks, operationResult{"read PDF/A conformance", conformanceErr})

	for _, check := range checks {
		if !errors.Is(check.err, gotenberg.ErrPdfEngineMethodNotSupported) {
			t.Errorf("%s returned %v", check.name, check.err)
		}
	}
}
