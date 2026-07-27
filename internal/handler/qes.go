// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/qes"
	"github.com/bright-interaction/hash/internal/sign"
)

// handleQESStart kicks off a QES challenge for a recipient on a
// QES-tier document. Magic-token authed via the parent /sign/{token}
// route group. Returns the QTSP redirect URL.
//
// Refuses when the document's routing_tier is not QES so a SES/AES doc
// can't be force-elevated by a clever signer; senders set the tier
// upstream (Phase 9 eIDAS routing rules).
func (s *Server) handleQESStart(w http.ResponseWriter, r *http.Request) {
	if s.QES == nil || s.QES.Provider == nil || s.QES.Provider.Name() == "noop" {
		writeError(w, http.StatusServiceUnavailable, "QES not enabled on this instance")
		return
	}
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	// Qualified Electronic Signatures are a paid-plan feature.
	if !s.requireFeature(w, r, rc.Document.OrgID, "qes") {
		return
	}
	if !strings.EqualFold(rc.Document.RoutingTier, "QES") {
		writeError(w, http.StatusConflict, "document routing_tier is not QES; use the regular sign endpoint")
		return
	}
	// Document digest the QTSP signs over. Either the final PDF (if
	// already rendered) or the rendered HTML body the signer is about
	// to sign. We use the resolved HTML so the binding works before
	// finalization happens.
	html, err := s.Sign.RenderForSigner(r.Context(), rc)
	if err != nil {
		writeInternalErrorMsg(w, "render for QES digest", err)
		return
	}
	digest := sha256.Sum256([]byte(html))

	callbackURL := s.PublicURL
	if callbackURL == "" {
		callbackURL = inferBase(r)
	}
	// Provider-session ID isn't known yet, so the QTSP callback URL
	// uses a placeholder that the provider fills in. Idura swaps in its
	// session id; the mock provider just appends '?mock=1' and lets the
	// /qes/callback/{provider_session_id} route extract it on the way back.
	startIn := qes.StartInput{
		DocumentID:     rc.Document.ID,
		RecipientID:    rc.Recipient.ID,
		RecipientEmail: rc.Recipient.Email,
		RecipientName:  rc.Recipient.Name,
		CallbackURL:    callbackURL + "/qes/callback/__session__",
		SignedDigest:   digest,
	}
	session, err := s.QES.StartSession(r.Context(), startIn, rc.Document.OrgID)
	if err != nil {
		if errors.Is(err, qes.ErrDisabled) {
			writeError(w, http.StatusServiceUnavailable, "QES disabled")
			return
		}
		writeError(w, http.StatusBadGateway, "qes start: "+err.Error())
		return
	}
	// Swap the placeholder in the redirect URL we hand the browser so
	// the QTSP can post back with the right session id; for providers
	// that returned a fully-formed redirect URL, leave it alone.
	redirect := strings.ReplaceAll(session.RedirectURL, "__session__", session.ProviderSessionID)

	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       rc.Document.OrgID,
		DocumentID:  &rc.Document.ID,
		RecipientID: &rc.Recipient.ID,
		Kind:        audit.KindQESSessionStarted,
		Payload: map[string]any{
			"via":              "qes",
			"provider":         session.Provider,
			"provider_session": session.ProviderSessionID,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":   session.ID.String(),
		"redirect_url": redirect,
		"provider":     session.Provider,
		"expires_at":   session.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleQESStatus polls the current session state. Returns the most
// recent pending/redirected/completed session for the recipient. Used
// by the signer page to detect "QTSP callback already landed; finish
// the UI flow" without forcing the user to refresh.
func (s *Server) handleQESStatus(w http.ResponseWriter, r *http.Request) {
	if s.QES == nil {
		writeError(w, http.StatusServiceUnavailable, "QES not enabled")
		return
	}
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	session, err := s.QES.MostRecentForRecipient(r.Context(), rc.Recipient.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "none"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":   session.ID.String(),
		"status":       session.Status,
		"provider":     session.Provider,
		"redirect_url": session.RedirectURL,
		"completed_at": completedAtStr(session.CompletedAt),
	})
}

// handleQESCallback is the QTSP-facing endpoint. Public route, no
// session auth - the QTSP HMAC-signs the body using a per-session
// secret we generated at /qes/start. After validation, drive the sign
// engine's existing Sign() path with a synthetic typed_name = QTSP
// signer name so the final PDF + audit cert + envelope fan-out all
// happen through the normal code path.
func (s *Server) handleQESCallback(w http.ResponseWriter, r *http.Request) {
	if s.QES == nil {
		writeError(w, http.StatusServiceUnavailable, "QES not enabled")
		return
	}
	providerSessionID := chi.URLParam(r, "provider_session_id")
	if providerSessionID == "" || providerSessionID == "__session__" {
		writeError(w, http.StatusBadRequest, "missing provider_session_id")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	// Mock provider has no body + no headers; synthesize a minimal
	// callback so the engine can complete. Detect via the URL hint the
	// mock Start handed back ('?mock=1').
	if len(raw) == 0 && r.URL.Query().Get("mock") == "1" {
		raw = []byte(`{"mock":true}`)
	}
	session, result, err := s.QES.CompleteCallback(r.Context(), providerSessionID, raw, headers)
	if err != nil {
		if errors.Is(err, qes.ErrInvalidCallback) {
			writeError(w, http.StatusUnauthorized, "callback signature invalid")
			return
		}
		writeError(w, http.StatusBadRequest, "qes callback: "+err.Error())
		return
	}

	// Drive the existing Sign() path so the document status flips +
	// final PDF renders + audit cert binds the QES assertion. Pass the
	// QTSP-issued signer name as typed_name so the audit trail records
	// the human who actually authenticated.
	rc, err := s.Sign.LookupByRecipientID(r.Context(), session.RecipientID, session.OrgID)
	if err != nil {
		writeInternalErrorMsg(w, "load recipient", err)
		return
	}
	signerName := result.SignerName
	if signerName == "" {
		signerName = rc.Recipient.Name
	}
	signRes, err := s.Sign.Sign(r.Context(), rc, sign.SignInput{
		TypedName: signerName,
		Font:      "Caveat",
		IP:        clientIP(r),
		UserAgent: r.UserAgent() + " (via QES " + session.Provider + ")",
	})
	if err != nil {
		writeInternalErrorMsg(w, "qes finalize", err)
		return
	}

	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       rc.Document.OrgID,
		DocumentID:  &rc.Document.ID,
		RecipientID: &rc.Recipient.ID,
		Kind:        audit.KindQESSessionCompleted,
		Payload: map[string]any{
			"via":              "qes",
			"provider":         session.Provider,
			"provider_session": session.ProviderSessionID,
			"signer_name":      result.SignerName,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"session_id":         session.ID.String(),
		"document_status":    signRes.Status,
		"document_completed": signRes.Completed,
	})
}

func completedAtStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func inferBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && !strings.HasPrefix(r.Host, "localhost") {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// keep pgtype import alive in case future extensions need it.
var _ = pgtype.Text{}
