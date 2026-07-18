// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/send"
)

// handleRemindDocument re-mints magic links (with expiry) for any pending
// recipients and re-sends reminder emails. All the work lives in
// internal/send.Engine.Remind so REST, MCP, and the worker share one path.
func (s *Server) handleRemindDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	sent, err := s.Send.Remind(r.Context(), send.Actor{
		UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email, IP: clientIP(r), Via: "rest",
	}, docID, false)
	if err != nil {
		switch {
		case errors.Is(err, send.ErrDocumentNotFound):
			writeError(w, http.StatusNotFound, "document not found")
		case errors.Is(err, send.ErrNotRemindable):
			writeError(w, http.StatusConflict, "document not in a remindable state")
		default:
			writeInternalError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reminded": sent})
}

// handleOpenBeacon serves a 1×1 transparent GIF and logs `document.opened`
// keyed by the magic-link token in the URL. Idempotent: every email open
// fires another event so analytics see opens-vs-clicks.
func (s *Server) handleOpenBeacon(w http.ResponseWriter, r *http.Request) {
	tok := chi.URLParam(r, "token")
	if tok != "" && s.Sign != nil {
		hash := auth.HashMagicToken(tok)
		if rc, err := s.Sign.LookupByToken(r.Context(), hash); err == nil {
			docID := rc.Document.ID
			recID := rc.Recipient.ID
			_, _ = s.Audit.Log(r.Context(), audit.Entry{
				OrgID:       rc.Document.OrgID,
				DocumentID:  &docID,
				RecipientID: &recID,
				Kind:        audit.KindDocumentOpened,
				IP:          clientIP(r),
				UserAgent:   r.UserAgent(),
			})
		}
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(transparentPixelGIF)
}

// transparentPixelGIF is a 43-byte GIF89a with one fully-transparent pixel.
// Hand-crafted so we don't pull image/gif into the handler hot path.
var transparentPixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x21,
	0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
	0x01, 0x00, 0x3B,
}
