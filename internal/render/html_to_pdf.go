// Package render builds final-PDF and signature artefacts for Hash
// documents. The HTML→PDF path uses Gotenberg's Chromium converter; the
// signature image path uses freetype for cases where we have to stamp
// signatures onto an externally-supplied PDF (week 4+).
package render

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// Gotenberg wraps the HTTP client we use to talk to a Gotenberg instance.
// Default endpoint matches the docker-compose wiring; production uses the
// gotenberg service inside the brightinteraction VPC.
type Gotenberg struct {
	BaseURL string
	HTTP    *http.Client
}

// NewGotenberg builds a client with sensible defaults (60-second timeout).
// Pass a custom http.Client if you need TLS/transport overrides.
func NewGotenberg(baseURL string) *Gotenberg {
	return &Gotenberg{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Ping confirms Gotenberg is reachable. Hits the documented /health
// endpoint (which returns 200 + a small JSON body when both Chromium
// and LibreOffice modules are loaded). Used by Hash /health so a
// dead PDF service surfaces as 503 instead of silently failing the
// next sign ceremony.
func (g *Gotenberg) Ping(ctx context.Context) error {
	if g.BaseURL == "" {
		return fmt.Errorf("gotenberg base url not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.BaseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("gotenberg /health returned %d", resp.StatusCode)
	}
	return nil
}

// HTMLToPDF posts an index.html plus optional CSS/asset files to Gotenberg
// and returns the rendered PDF bytes. Reference:
// https://gotenberg.dev/docs/routes#convert-with-chromium-html
func (g *Gotenberg) HTMLToPDF(ctx context.Context, html string, opts PDFOptions) ([]byte, error) {
	if g.BaseURL == "" {
		return nil, fmt.Errorf("gotenberg base url not configured")
	}
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)

	// index.html is the file Gotenberg renders.
	if err := writeFormFile(mw, "files", "index.html", "text/html", []byte(html)); err != nil {
		return nil, err
	}

	// Attach every embedded asset (woff2 font binaries, etc) so Chromium can
	// resolve relative url('./Caveat.woff2') references without leaving the
	// container. Callers without explicit assets get the default font set so
	// signature + cert pages render hermetic by default.
	assets := opts.Assets
	if assets == nil {
		assets = FontAssets()
	}
	for _, a := range assets {
		mime := a.Mime
		if mime == "" {
			mime = "font/woff2"
		}
		if err := writeFormFile(mw, "files", a.Filename, mime, a.Bytes); err != nil {
			return nil, err
		}
	}

	// Page sizing + margins. Gotenberg expects these as form fields.
	if opts.PaperWidth == 0 {
		opts.PaperWidth = 8.27 // A4 inches
	}
	if opts.PaperHeight == 0 {
		opts.PaperHeight = 11.69
	}
	if opts.Margins == [4]float32{} && !opts.PreferCSSPageSize {
		// Google-Docs default page geometry: A4 (set above) with 1 inch margins
		// on all sides. Combined with the in-body centered .hash-doc column
		// this gives the familiar comfortable document measure. Skipped when the
		// caller wants the document's own @page CSS to drive geometry (designed
		// proposals), so we don't force 1-inch margins onto a full-bleed layout.
		opts.Margins = [4]float32{1.0, 1.0, 1.0, 1.0}
	}
	_ = mw.WriteField("paperWidth", fmt.Sprintf("%.2f", opts.PaperWidth))
	_ = mw.WriteField("paperHeight", fmt.Sprintf("%.2f", opts.PaperHeight))
	_ = mw.WriteField("marginTop", fmt.Sprintf("%.2f", opts.Margins[0]))
	_ = mw.WriteField("marginRight", fmt.Sprintf("%.2f", opts.Margins[1]))
	_ = mw.WriteField("marginBottom", fmt.Sprintf("%.2f", opts.Margins[2]))
	_ = mw.WriteField("marginLeft", fmt.Sprintf("%.2f", opts.Margins[3]))
	_ = mw.WriteField("printBackground", "true")
	if opts.PreferCSSPageSize {
		// Honour the document's own `@page { size: ... }` rule so a designed
		// proposal (e.g. a landscape deck) renders at its intended geometry
		// instead of being squeezed into the paperWidth/Height fallback.
		_ = mw.WriteField("preferCssPageSize", "true")
	}
	if opts.WaitForExpression != "" {
		_ = mw.WriteField("waitForExpression", opts.WaitForExpression)
	}
	if opts.WaitDelay != "" {
		_ = mw.WriteField("waitDelay", opts.WaitDelay)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	url := g.BaseURL + "/forms/chromium/convert/html"
	frozenBody := body.Bytes()
	contentType := mw.FormDataContentType()

	// Gotenberg + Chromium restart cleanly under load but the convert
	// route occasionally answers 503 / closes the connection mid-flight
	// (Chromium worker pool exhaustion). Three attempts with 200ms +
	// 600ms backoff turns a flaky deploy into a stable render without
	// pushing the latency budget past the 60s client timeout.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 200 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(frozenBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := g.HTTP.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("gotenberg request: %w", err)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		// 4xx (other than 408 / 429) is a deterministic input error;
		// retrying won't change the outcome. 5xx + 408 + 429 retry.
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			return nil, fmt.Errorf("gotenberg returned %d: %s", resp.StatusCode, string(out))
		}
		lastErr = fmt.Errorf("gotenberg returned %d: %s", resp.StatusCode, string(out))
	}
	return nil, lastErr
}

// PDFOptions configures the Chromium-rendered PDF.
type PDFOptions struct {
	PaperWidth        float32     // inches; A4 width = 8.27
	PaperHeight       float32     // inches; A4 height = 11.69
	Margins           [4]float32  // top, right, bottom, left in inches
	WaitForExpression string      // e.g. window.fontsLoaded === true
	WaitDelay         string      // e.g. "1s"; gives Chromium time to settle
	Assets            []FontAsset // optional; nil falls back to FontAssets()
	// PreferCSSPageSize makes Gotenberg honour the document's own
	// `@page { size: ... }` and suppresses the default 1-inch margins, so an
	// author-designed proposal renders at its intended page geometry.
	PreferCSSPageSize bool
}

func writeFormFile(mw *multipart.Writer, fieldName, filename, mime string, contents []byte) error {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, filename))
	h.Set("Content-Type", mime)
	w, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := w.Write(contents); err != nil {
		return err
	}
	return nil
}
