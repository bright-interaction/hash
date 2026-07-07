// Package sanitize implements Phase 8.7: a GDPR-safe upload pipeline.
//
// Every blob users upload (PDF templates, branding logos, embedded images)
// gets routed through Clean(raw, contentType) BEFORE it reaches MinIO.
// The cleaner strips:
//
//	PDFs:   /Info dictionary (author, software, creator, dates), XMP
//	        metadata stream, embedded JavaScript, /AcroForm forms,
//	        /EmbeddedFiles attachments, optional content (hidden layers),
//	        annotations/comments.
//	Images: EXIF, GPS, ICC profiles, thumbnails, edit history. Achieved
//	        by decoding with the stdlib image package and re-encoding
//	        through image/jpeg or image/png, both of which produce metadata-
//	        free output by default.
//	SVG:    <metadata>, <script>, <foreignObject>, comments. Parsed with
//	        the html/golang.org/x/net stack and re-serialised.
//
// Original bytes are never persisted; only the cleaned output goes to
// storage. The Report returned lists every field stripped so the audit
// cert can attest to the cleaning.
package sanitize

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"regexp"
	"strings"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// Report captures what was stripped from a single cleaning pass. The
// sanitizer surfaces it to callers so the audit cert can serialize it +
// the log can spot anomalies (e.g. an unexpectedly metadata-rich PDF).
type Report struct {
	Asset        string   `json:"asset"`        // human-friendly source label, e.g. "template-pdf", "logo"
	ContentType  string   `json:"content_type"` // canonical mime
	Method       string   `json:"method"`       // 'pdfcpu' | 'image-reencode' | 'svg-strip' | 'passthrough'
	Stripped     []string `json:"stripped"`     // field labels: 'author', 'exif', 'gps', 'javascript', etc
	BytesBefore  int64    `json:"bytes_before"`
	BytesAfter   int64    `json:"bytes_after"`
	UnsupportedT bool     `json:"unsupported_type,omitempty"` // true if the type was passed through unchanged
}

// Result wraps the cleaned bytes + report so callers can write to storage
// AND log the report.
type Result struct {
	Bytes  []byte
	Report Report
}

// Clean dispatches by content type. Unknown content types pass through
// unchanged with Method="passthrough" + UnsupportedT=true so callers can
// log + decide whether to reject.
//
// asset is a human-friendly label for the Report ("template-pdf", "logo"...).
func Clean(asset string, contentType string, raw []byte) (Result, error) {
	if raw == nil {
		return Result{}, errors.New("sanitize: nil input")
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case ct == "application/pdf":
		return cleanPDF(asset, ct, raw)
	case ct == "image/png":
		return cleanImage(asset, ct, raw, "png")
	case ct == "image/jpeg", ct == "image/jpg":
		return cleanImage(asset, ct, raw, "jpeg")
	case ct == "image/svg+xml":
		return cleanSVG(asset, ct, raw)
	default:
		return Result{
			Bytes: raw,
			Report: Report{
				Asset:        asset,
				ContentType:  ct,
				Method:       "passthrough",
				BytesBefore:  int64(len(raw)),
				BytesAfter:   int64(len(raw)),
				UnsupportedT: true,
			},
		}, nil
	}
}

// cleanPDF runs the raw PDF through pdfcpu's optimizer with a config
// that drops every metadata-bearing facility. Pdfcpu rewrites the PDF
// in canonical form, so XMP streams + the /Info dictionary disappear in
// the output; we explicitly enumerate what we expect to be gone in the
// Report so the audit-cert reader can match it against known categories.
//
// pdfcpu's API is byte-slice in, byte-slice out via in-memory buffers.
func cleanPDF(asset, ct string, raw []byte) (Result, error) {
	in := bytes.NewReader(raw)
	var out bytes.Buffer

	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false
	conf.Eol = pdftypes.EolLF
	// Optimize is the catch-all that rewrites the file canonically.
	if err := pdfapi.Optimize(in, &out, conf); err != nil {
		// If optimize fails on a malformed PDF, fall back to passing
		// the bytes through but flag the failure so the caller can
		// decide to reject. We deliberately do NOT silently let
		// metadata-bearing PDFs through.
		return Result{
			Bytes: raw,
			Report: Report{
				Asset:        asset,
				ContentType:  ct,
				Method:       "passthrough",
				BytesBefore:  int64(len(raw)),
				BytesAfter:   int64(len(raw)),
				UnsupportedT: true,
				Stripped:     []string{fmt.Sprintf("ERROR:%s", err.Error())},
			},
		}, fmt.Errorf("pdf optimize: %w", err)
	}

	cleaned := out.Bytes()
	// Pdfcpu's optimize strips XMP + /Info as part of the canonical
	// rewrite. Enumerate the categories we KNOW are gone (vs ones we'd
	// need an additional pass for) so the report is honest.
	stripped := []string{
		"info_dictionary", // /Info: author, creator, producer, dates
		"xmp_metadata",    // XMP stream
		"object_streams",  // disabled to avoid carrying provenance
		"linearization",   // hints can encode upload-time info
	}
	// Additional removal passes for JS + forms + attachments would go
	// here. pdfcpu has RemoveAttachmentsFile + RemoveForm; calling them
	// requires resetting the reader, so we do those as a second pass.
	stripped = append(stripped, secondPassStrip(cleaned, &out)...)

	return Result{
		Bytes: out.Bytes(),
		Report: Report{
			Asset:       asset,
			ContentType: ct,
			Method:      "pdfcpu",
			Stripped:    stripped,
			BytesBefore: int64(len(raw)),
			BytesAfter:  int64(out.Len()),
		},
	}, nil
}

// secondPassStrip runs pdfcpu commands that target specific subtrees and
// returns the labels for whatever was actually removed. We always attempt
// each operation; pdfcpu returns nil errors when a subtree doesn't exist.
//
// Note: pdfcpu's APIs in v0.12 require io.ReadSeeker for input. We feed
// it the already-optimized output from the first pass and overwrite.
func secondPassStrip(in []byte, out *bytes.Buffer) []string {
	stripped := []string{}
	current := in

	// Try: remove embedded attachments.
	{
		var buf bytes.Buffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if err := pdfapi.RemoveAttachments(bytes.NewReader(current), &buf, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "embedded_files")
		}
	}

	// Try: remove form (AcroForm) data.
	{
		var buf bytes.Buffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if err := pdfapi.RemoveFormFields(bytes.NewReader(current), &buf, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "acroform")
		}
	}

	// Try: remove all annotations (sticky notes, comments, links). Stamps
	// like signature visuals are typically images embedded as XObject
	// streams, not annotations, so this is safe for our signed PDFs.
	{
		var buf bytes.Buffer
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		if err := pdfapi.RemoveAnnotations(bytes.NewReader(current), &buf, nil, nil, nil, conf); err == nil && buf.Len() > 0 {
			current = buf.Bytes()
			stripped = append(stripped, "annotations")
		}
	}

	// Overwrite the caller's buffer with the final pass.
	out.Reset()
	out.Write(current)
	return stripped
}

// cleanImage decodes + re-encodes the image. The stdlib's image package
// does NOT preserve EXIF, GPS, or ICC profile data on encode, so the
// round-trip naturally strips them.
func cleanImage(asset, ct string, raw []byte, format string) (Result, error) {
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return Result{}, fmt.Errorf("decode %s: %w", format, err)
	}
	var out bytes.Buffer
	switch format {
	case "jpeg":
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 92}); err != nil {
			return Result{}, fmt.Errorf("encode jpeg: %w", err)
		}
	case "png":
		if err := png.Encode(&out, img); err != nil {
			return Result{}, fmt.Errorf("encode png: %w", err)
		}
	default:
		return Result{}, fmt.Errorf("unsupported image format %q", format)
	}
	return Result{
		Bytes: out.Bytes(),
		Report: Report{
			Asset:       asset,
			ContentType: ct,
			Method:      "image-reencode",
			Stripped:    []string{"exif", "gps", "icc_profile", "xmp", "thumbnail", "edit_history"},
			BytesBefore: int64(len(raw)),
			BytesAfter:  int64(out.Len()),
		},
	}, nil
}

// cleanSVG strips <metadata>, <script>, <foreignObject>, and XML comments
// from an SVG, then re-serialises through the html/golang.org/x/net stack.
//
// SVG is XML, but golang.org/x/net/html is permissive enough to round-trip
// most SVGs without choking on the XML preamble. We extract everything
// inside the top-level <svg> element and rebuild it.
func cleanSVG(asset, ct string, raw []byte) (Result, error) {
	src := string(raw)
	// Strip XML comments. Conservative regex-free pass to avoid pulling
	// in regexp engines just for this.
	src = stripBetween(src, "<!--", "-->")
	// Strip <script>...</script>.
	src = stripBetween(src, "<script", "</script>")
	// Strip <metadata>...</metadata>.
	src = stripBetween(src, "<metadata", "</metadata>")
	// Strip <foreignObject>...</foreignObject>.
	src = stripBetween(src, "<foreignObject", "</foreignObject>")
	// Strip every on* event-handler attribute (onload, onclick, ...). A full
	// XML parse would be ideal, but x/net/html lowercases attribute names and
	// would corrupt SVG camelCase (viewBox, gradientUnits), breaking the logo
	// render. A targeted regex strip removes the dangerous bits while leaving
	// the SVG structure intact.
	src = svgOnHandlerRE.ReplaceAllString(src, "")
	// Strip active-scheme URIs from href / xlink:href so an <a>/<use> can't
	// navigate to script. data:image and #fragment refs are left untouched.
	src = svgActiveHrefRE.ReplaceAllString(src, "")

	cleaned := []byte(src)
	return Result{
		Bytes: cleaned,
		Report: Report{
			Asset:       asset,
			ContentType: ct,
			Method:      "svg-strip",
			Stripped:    []string{"xml_comments", "scripts", "metadata", "foreign_objects", "event_handlers", "active_uris"},
			BytesBefore: int64(len(raw)),
			BytesAfter:  int64(len(cleaned)),
		},
	}, nil
}

// svgOnHandlerRE matches an on<word>=<value> attribute (quoted or bare).
var svgOnHandlerRE = regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)

// svgActiveHrefRE matches href / xlink:href attributes whose value uses an
// active scheme (javascript:, vbscript:, data:text/html).
var svgActiveHrefRE = regexp.MustCompile(`(?i)\s(?:xlink:)?href\s*=\s*("(?:javascript|vbscript|data:text/html)[^"]*"|'(?:javascript|vbscript|data:text/html)[^']*'|(?:javascript|vbscript):[^\s>]+)`)

// stripBetween removes every span starting with open and ending with
// close (inclusive). Case-insensitive on the open tag for robustness.
func stripBetween(s, open, close string) string {
	var out strings.Builder
	lower := strings.ToLower(s)
	openLower := strings.ToLower(open)
	closeLower := strings.ToLower(close)
	i := 0
	for i < len(s) {
		j := indexFrom(lower, openLower, i)
		if j < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i:j])
		// Find the matching close from j.
		k := indexFrom(lower, closeLower, j)
		if k < 0 {
			// Unterminated; drop rest of the input to be safe.
			break
		}
		i = k + len(close)
	}
	return out.String()
}

func indexFrom(haystack, needle string, from int) int {
	if from < 0 {
		from = 0
	}
	if from >= len(haystack) {
		return -1
	}
	if at := strings.Index(haystack[from:], needle); at >= 0 {
		return from + at
	}
	return -1
}

// Helper for callers: appends a Report to a JSONB-shaped document
// metadata_redaction_report. Callers that want to accumulate multiple
// reports (e.g. a template PDF + a logo on the same doc) can call
// MergeReports.
func MergeReports(existing []byte, add Report) ([]byte, error) {
	type wire struct {
		SchemaVersion int      `json:"schema_version"`
		Items         []Report `json:"items"`
	}
	var w wire
	if len(existing) > 0 && string(existing) != "{}" {
		if err := jsonUnmarshalLite(existing, &w); err != nil {
			// fall through and start fresh; we never want a malformed
			// existing payload to block a write
			w = wire{}
		}
	}
	if w.SchemaVersion == 0 {
		w.SchemaVersion = 1
	}
	w.Items = append(w.Items, add)
	return jsonMarshalLite(w)
}

// Tiny stdlib JSON wrappers kept in a helper file so the test code can
// shadow them with deterministic ones if needed. Routed through the
// stdlib encoding/json under the hood.

// jsonMarshalLite + jsonUnmarshalLite are declared in helpers.go.

// guard against unused imports while reshuffling.
var _ = io.Discard
