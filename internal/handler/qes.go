// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import "net/http"

const qesUnavailableMessage = "QES ceremony endpoints are retired in this SES-only release"

// These handlers are fail-closed compatibility tombstones. The HTTP router
// mounts them solely so retired endpoints return 410 instead of the SPA shell.
// Enabling QES requires a new ceremony implementation that persists the exact
// document digest, verifies the provider signature over it, and atomically
// consumes that proof with the legal response. Reintroducing the removed
// lifecycle logic by toggling a flag is intentionally impossible.
func (s *Server) handleQESStart(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusGone, qesUnavailableMessage)
}

func (s *Server) handleQESStatus(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusGone, qesUnavailableMessage)
}

func (s *Server) handleQESCallback(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusGone, qesUnavailableMessage)
}
