// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/send"
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

// handleRetiredOpenBeacon is a non-recording compatibility response for old
// emails. It deliberately does not parse or hash the path token, query a
// recipient, or create an event. New invite/reminder templates never link it.
func (s *Server) handleRetiredOpenBeacon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
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
