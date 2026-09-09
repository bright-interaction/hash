// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// registerBrandingTools mounts the Phase 8.5 brand-theming MCP surface.
// Agents can read the current org palette + set every field; per-document
// overrides are also accessible so a co-branded contract can break from
// the org theme without overwriting it.
func registerBrandingTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "get_org_branding",
		Description: "Read the org-level brand palette + logo + fonts. Returns the system defaults if no row exists yet.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			b := loadOrgBranding(r, d, u.OrgID)
			return brandingToMap(b), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_org_branding",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST PUT /branding is owner-only; match it (branding renders into every signer page + final PDF)
		MinFeature:  "branding",     // paid-feature gate, mirroring the REST handleSetBranding
		Description: "Upsert the org-level brand palette. All fields optional; missing fields default to the system palette. Hex colours accept 3- or 6-char form with optional leading '#' and normalise to '#RRGGBB'. Font lists accept safe comma-separated family names and are stored canonically.",
		InputSchema: schemaObject(map[string]any{
			"primary_hex":     stringSchema("hex color for primary surfaces"),
			"accent_hex":      stringSchema("hex color for accents + links"),
			"surface_hex":     stringSchema("hex color for the page background"),
			"text_hex":        stringSchema("hex color for body text"),
			"muted_hex":       stringSchema("hex color for secondary text"),
			"logo_url":        stringSchema("absolute URL to the org logo (PNG/JPG/SVG)"),
			"logo_alt":        stringSchema("alt text for the logo"),
			"font_heading":    stringSchema("CSS font-family for headings"),
			"font_body":       stringSchema("CSS font-family for body"),
			"signature_color": stringSchema("hex color used to ink rendered signatures"),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var in struct {
				PrimaryHex     string `json:"primary_hex"`
				AccentHex      string `json:"accent_hex"`
				SurfaceHex     string `json:"surface_hex"`
				TextHex        string `json:"text_hex"`
				MutedHex       string `json:"muted_hex"`
				LogoURL        string `json:"logo_url"`
				LogoAlt        string `json:"logo_alt"`
				FontHeading    string `json:"font_heading"`
				FontBody       string `json:"font_body"`
				SignatureColor string `json:"signature_color"`
			}
			if err := MustParseArgs(args, &in); err != nil {
				return nil, err
			}
			in.LogoURL = strings.TrimSpace(in.LogoURL)
			// Reject malformed caller-supplied fonts before even consulting the
			// database. The merged effective values are checked again below so a
			// legacy invalid row cannot survive an unrelated palette update.
			for _, font := range []struct {
				name  string
				value *string
			}{
				{name: "font_heading", value: &in.FontHeading},
				{name: "font_body", value: &in.FontBody},
			} {
				if *font.value == "" {
					continue
				}
				normalized, err := branding.NormaliseFontFamily(*font.value)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", font.name, err)
				}
				*font.value = normalized
			}
			// Validate + normalise hex inputs before persisting.
			pairs := []struct {
				name string
				ptr  *string
			}{
				{"primary_hex", &in.PrimaryHex},
				{"accent_hex", &in.AccentHex},
				{"surface_hex", &in.SurfaceHex},
				{"text_hex", &in.TextHex},
				{"muted_hex", &in.MutedHex},
				{"signature_color", &in.SignatureColor},
			}
			for _, p := range pairs {
				if *p.ptr == "" {
					continue
				}
				norm := branding.NormaliseHex(*p.ptr)
				if norm == "" {
					return nil, fmt.Errorf("%s must be a hex colour", p.name)
				}
				*p.ptr = norm
			}
			if err := branding.ValidateLogoURLForEnvironment(d.Environment, in.LogoURL); err != nil {
				return nil, err
			}
			merged := mergeForMCP(loadOrgBranding(r, d, u.OrgID), in.PrimaryHex, in.AccentHex,
				in.SurfaceHex, in.TextHex, in.MutedHex, in.LogoURL, in.LogoAlt,
				in.FontHeading, in.FontBody, in.SignatureColor)
			// MCP updates merge omitted fields into the existing row. Recheck the
			// effective value so an old logo cannot survive a production palette
			// edit and bypass the immutable-logo gate.
			merged.LogoURL = strings.TrimSpace(merged.LogoURL)
			if err := branding.ValidateLogoURLForEnvironment(d.Environment, merged.LogoURL); err != nil {
				return nil, err
			}
			normalizedFont, err := branding.NormaliseFontFamily(merged.FontHeading)
			if err != nil {
				return nil, fmt.Errorf("font_heading: %w", err)
			}
			merged.FontHeading = normalizedFont
			normalizedFont, err = branding.NormaliseFontFamily(merged.FontBody)
			if err != nil {
				return nil, fmt.Errorf("font_body: %w", err)
			}
			merged.FontBody = normalizedFont
			row, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.OrgBranding, error) {
					return q.UpsertOrgBranding(r.Context(), generated.UpsertOrgBrandingParams{
						OrgID:          u.OrgID,
						PrimaryHex:     merged.PrimaryHex,
						AccentHex:      merged.AccentHex,
						SurfaceHex:     merged.SurfaceHex,
						TextHex:        merged.TextHex,
						MutedHex:       merged.MutedHex,
						LogoUrl:        merged.LogoURL,
						LogoAlt:        merged.LogoAlt,
						FontHeading:    merged.FontHeading,
						FontBody:       merged.FontBody,
						SignatureColor: merged.SignatureColor,
					})
				},
				func(*generated.OrgBranding) audit.Entry {
					return audit.Entry{
						OrgID:       u.OrgID,
						ActorUserID: &u.UserID,
						Kind:        audit.KindDocumentUpdated,
						Payload:     map[string]any{"via": "mcp", "tool": "set_org_branding"},
					}
				},
			)
			if err != nil {
				return nil, err
			}
			return brandingToMap(branding.Branding{
				PrimaryHex:     row.PrimaryHex,
				AccentHex:      row.AccentHex,
				SurfaceHex:     row.SurfaceHex,
				TextHex:        row.TextHex,
				MutedHex:       row.MutedHex,
				LogoURL:        row.LogoUrl,
				LogoAlt:        row.LogoAlt,
				FontHeading:    row.FontHeading,
				FontBody:       row.FontBody,
				SignatureColor: row.SignatureColor,
			}), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "resolve_document_branding",
		Description: "Return the effective branding for a document (org defaults overlaid with any per-document override). Useful before drafting a co-branded contract so the agent knows what palette will render.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			// Resolver lives outside MCP Deps; replicate the merge inline.
			b := loadOrgBranding(r, d, u.OrgID)
			if ov, err := d.Queries.GetDocumentBrandingOverride(r.Context(), doc.ID); err == nil {
				if ov.PrimaryHex.Valid && ov.PrimaryHex.String != "" {
					b.PrimaryHex = ov.PrimaryHex.String
				}
				if ov.AccentHex.Valid && ov.AccentHex.String != "" {
					b.AccentHex = ov.AccentHex.String
				}
				if ov.SurfaceHex.Valid && ov.SurfaceHex.String != "" {
					b.SurfaceHex = ov.SurfaceHex.String
				}
				if ov.TextHex.Valid && ov.TextHex.String != "" {
					b.TextHex = ov.TextHex.String
				}
				if ov.MutedHex.Valid && ov.MutedHex.String != "" {
					b.MutedHex = ov.MutedHex.String
				}
				if ov.LogoUrl.Valid && ov.LogoUrl.String != "" {
					b.LogoURL = ov.LogoUrl.String
				}
				if ov.LogoAlt.Valid && ov.LogoAlt.String != "" {
					b.LogoAlt = ov.LogoAlt.String
				}
				if ov.FontHeading.Valid && ov.FontHeading.String != "" {
					b.FontHeading = ov.FontHeading.String
				}
				if ov.FontBody.Valid && ov.FontBody.String != "" {
					b.FontBody = ov.FontBody.String
				}
				if ov.SignatureColor.Valid && ov.SignatureColor.String != "" {
					b.SignatureColor = ov.SignatureColor.String
				}
			}
			return brandingToMap(b), nil
		},
	})
}

func loadOrgBranding(r *http.Request, d Deps, orgID uuid.UUID) branding.Branding {
	out := branding.DefaultBranding()
	row, err := d.Queries.GetOrgBranding(r.Context(), orgID)
	if err != nil || row == nil {
		return out
	}
	if row.PrimaryHex != "" {
		out.PrimaryHex = row.PrimaryHex
	}
	if row.AccentHex != "" {
		out.AccentHex = row.AccentHex
	}
	if row.SurfaceHex != "" {
		out.SurfaceHex = row.SurfaceHex
	}
	if row.TextHex != "" {
		out.TextHex = row.TextHex
	}
	if row.MutedHex != "" {
		out.MutedHex = row.MutedHex
	}
	if row.LogoUrl != "" {
		out.LogoURL = row.LogoUrl
	}
	if row.LogoAlt != "" {
		out.LogoAlt = row.LogoAlt
	}
	if row.FontHeading != "" {
		out.FontHeading = row.FontHeading
	}
	if row.FontBody != "" {
		out.FontBody = row.FontBody
	}
	if row.SignatureColor != "" {
		out.SignatureColor = row.SignatureColor
	}
	return out
}

func brandingToMap(b branding.Branding) map[string]any {
	return map[string]any{
		"primary_hex":     b.PrimaryHex,
		"accent_hex":      b.AccentHex,
		"surface_hex":     b.SurfaceHex,
		"text_hex":        b.TextHex,
		"muted_hex":       b.MutedHex,
		"logo_url":        b.LogoURL,
		"logo_alt":        b.LogoAlt,
		"font_heading":    b.FontHeading,
		"font_body":       b.FontBody,
		"signature_color": b.SignatureColor,
	}
}

func mergeForMCP(base branding.Branding, primary, accent, surface, text, muted, logoURL, logoAlt, fontHeading, fontBody, signatureColor string) branding.Branding {
	if primary != "" {
		base.PrimaryHex = primary
	}
	if accent != "" {
		base.AccentHex = accent
	}
	if surface != "" {
		base.SurfaceHex = surface
	}
	if text != "" {
		base.TextHex = text
	}
	if muted != "" {
		base.MutedHex = muted
	}
	if logoURL != "" {
		base.LogoURL = logoURL
	}
	if logoAlt != "" {
		base.LogoAlt = logoAlt
	}
	if fontHeading != "" {
		base.FontHeading = fontHeading
	}
	if fontBody != "" {
		base.FontBody = fontBody
	}
	if signatureColor != "" {
		base.SignatureColor = signatureColor
	}
	return base
}
