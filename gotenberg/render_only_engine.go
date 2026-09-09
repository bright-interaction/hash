// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"log/slog"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	flag "github.com/spf13/pflag"
)

const renderOnlyEngineID = "hash-render-only"

// renderOnlyEngine satisfies Gotenberg's Chromium module dependency without
// shipping qpdf, pdfcpu, PDFtk, ExifTool, LibreOffice, or their routes. Hash
// only submits HTML and uses Chromium's native print-to-PDF output. Every
// optional PDF post-processing operation fails closed if a future caller adds
// an unsupported form field instead of silently weakening the result.
type renderOnlyEngine struct{}

func init() {
	gotenberg.MustRegisterModule(new(renderOnlyEngine))
}

func (*renderOnlyEngine) Descriptor() gotenberg.ModuleDescriptor {
	return gotenberg.ModuleDescriptor{
		ID:      renderOnlyEngineID,
		FlagSet: flag.NewFlagSet(renderOnlyEngineID, flag.ExitOnError),
		New:     func() gotenberg.Module { return new(renderOnlyEngine) },
	}
}

func (*renderOnlyEngine) Merge(context.Context, *slog.Logger, []string, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Split(context.Context, *slog.Logger, gotenberg.SplitMode, string, string) ([]string, error) {
	return nil, gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Flatten(context.Context, *slog.Logger, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Convert(context.Context, *slog.Logger, gotenberg.PdfFormats, string, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) OptimizeImages(context.Context, *slog.Logger, int, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) ReadMetadata(context.Context, *slog.Logger, string) (map[string]any, error) {
	return nil, gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) PageCount(context.Context, *slog.Logger, string) (int, error) {
	return 0, gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) WriteMetadata(context.Context, *slog.Logger, map[string]any, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) ReadBookmarks(context.Context, *slog.Logger, string) ([]gotenberg.Bookmark, error) {
	return nil, gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) WriteBookmarks(context.Context, *slog.Logger, string, []gotenberg.Bookmark) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Encrypt(context.Context, *slog.Logger, string, gotenberg.EncryptOptions) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) EmbedFiles(context.Context, *slog.Logger, []string, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) EmbedFilesMetadata(context.Context, *slog.Logger, map[string]map[string]string, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Watermark(context.Context, *slog.Logger, string, gotenberg.Stamp) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Stamp(context.Context, *slog.Logger, string, gotenberg.Stamp) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) Rotate(context.Context, *slog.Logger, string, int, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) InjectFacturXXMP(context.Context, *slog.Logger, gotenberg.FacturX, string) error {
	return gotenberg.ErrPdfEngineMethodNotSupported
}

func (*renderOnlyEngine) ReadPdfAConformance(context.Context, *slog.Logger, string) (string, string, error) {
	return "", "", gotenberg.ErrPdfEngineMethodNotSupported
}

var (
	_ gotenberg.Module    = (*renderOnlyEngine)(nil)
	_ gotenberg.PdfEngine = (*renderOnlyEngine)(nil)
)
