// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"fmt"
	"html"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// One-click email actions. A signed, expiring token authorizes a single action
// (approve/deny a change request) without a login. GET shows a confirmation page
// (safe against email-client prefetch, which must never mutate); the POST on
// that page performs the action. Both verify the same token.

func (s *Server) actionPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>%s</title>
<style>body{font-family:Inter,system-ui,-apple-system,sans-serif;color:#18181b;background:#fafaf9;margin:0;padding:48px 16px;display:flex;justify-content:center}
.card{background:#fff;border:1px solid #e7e5e4;border-radius:12px;max-width:520px;width:100%%;padding:28px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
h1{font-weight:600;font-size:20px;margin:0 0 12px}
.rule{height:3px;border-radius:2px;background:#0891B2;margin:0 0 20px}
blockquote{border-left:3px solid #0891B2;padding-left:12px;color:#555;margin:10px 0}
.btn{display:inline-block;text-decoration:none;border:0;cursor:pointer;font:inherit;font-weight:600;padding:11px 18px;border-radius:7px;color:#fff}
.approve{background:#16a34a}.deny{background:#b91c1c}.muted{color:#777;font-size:13px}</style>
</head><body><div class="card"><div class="rule"></div><h1>%s</h1>%s</div></body></html>`,
		html.EscapeString(title), html.EscapeString(title), body)
}

func (s *Server) verifyChangeActionToken(w http.ResponseWriter, tok string) (actiontoken.Claims, bool) {
	if s.ActionSecret == "" {
		s.actionPage(w, http.StatusServiceUnavailable, "Unavailable", `<p class="muted">Email actions are not configured.</p>`)
		return actiontoken.Claims{}, false
	}
	c, err := actiontoken.Verify(s.ActionSecret, tok, time.Now())
	if err != nil || c.Kind != "cr" {
		s.actionPage(w, http.StatusBadRequest, "Link not valid", `<p class="muted">This link is invalid or has expired. Open the document to act on the request.</p>`)
		return actiontoken.Claims{}, false
	}
	return c, true
}

// handleChangeActionPage (GET /a/cr) renders a confirmation page for the action.
func (s *Server) handleChangeActionPage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("t")
	c, ok := s.verifyChangeActionToken(w, tok)
	if !ok {
		return
	}
	orgID, err1 := uuid.Parse(c.OrgID)
	crID, err2 := uuid.Parse(c.TargetID)
	if err1 != nil || err2 != nil {
		s.actionPage(w, http.StatusBadRequest, "Link not valid", `<p class="muted">This link is malformed.</p>`)
		return
	}
	cr, err := s.Queries.GetChangeRequest(r.Context(), generated.GetChangeRequestParams{ID: crID, OrgID: orgID})
	if err != nil {
		s.actionPage(w, http.StatusNotFound, "Not found", `<p class="muted">This change request no longer exists.</p>`)
		return
	}
	if cr.Status != "open" {
		res := "resolved"
		if cr.Resolution.Valid {
			res = cr.Resolution.String
		}
		s.actionPage(w, http.StatusOK, "Already "+res, fmt.Sprintf(`<p class="muted">This change request was already %s.</p>`, html.EscapeString(res)))
		return
	}
	verb := "Approve"
	cls := "approve"
	if c.Action == "deny" {
		verb, cls = "Deny", "deny"
	}
	var snippet string
	if cr.Quote != "" {
		snippet += fmt.Sprintf(`<p class="muted">Marked text</p><blockquote>%s</blockquote>`, html.EscapeString(cr.Quote))
	}
	if cr.Message != "" {
		snippet += fmt.Sprintf(`<p class="muted">Comment</p><blockquote>%s</blockquote>`, html.EscapeString(cr.Message))
	}
	if cr.Proposed != "" {
		snippet += fmt.Sprintf(`<p class="muted">Proposed</p><blockquote>%s</blockquote>`, html.EscapeString(cr.Proposed))
	}
	body := snippet + fmt.Sprintf(`<form method="POST" action="/a/cr" style="margin-top:20px">
<input type="hidden" name="t" value="%s"/>
<button type="submit" class="btn %s">%s this change</button></form>`,
		html.EscapeString(tok), cls, verb)
	s.actionPage(w, http.StatusOK, verb+" change request?", body)
}

// handleChangeActionConfirm (POST /a/cr) performs the approve/deny.
func (s *Server) handleChangeActionConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := r.FormValue("t")
	c, ok := s.verifyChangeActionToken(w, tok)
	if !ok {
		return
	}
	orgID, err1 := uuid.Parse(c.OrgID)
	docID, err2 := uuid.Parse(c.DocID)
	crID, err3 := uuid.Parse(c.TargetID)
	if err1 != nil || err2 != nil || err3 != nil {
		s.actionPage(w, http.StatusBadRequest, "Link not valid", `<p class="muted">This link is malformed.</p>`)
		return
	}
	if _, err := s.Sign.ResolveChange(r.Context(), orgID, docID, crID, c.Action == "approve"); err != nil {
		// Most likely already resolved; show a friendly terminal state.
		s.actionPage(w, http.StatusOK, "Already handled", `<p class="muted">This change request was already approved or denied.</p>`)
		return
	}
	done := "approved"
	if c.Action == "deny" {
		done = "denied"
	}
	s.actionPage(w, http.StatusOK, "Change "+done, fmt.Sprintf(
		`<p>The change request was <strong>%s</strong>. Open the document to revise and re-send it for signature.</p>
<p style="margin-top:16px"><a class="btn approve" style="background:#0891B2" href="%s/documents/%s">Open document</a></p>`,
		html.EscapeString(done), html.EscapeString(s.PublicURL), html.EscapeString(docID.String())))
}

// Legacy comment-reply action tokens bypassed the current Article 13 notice.
// Keep both routes as non-mutating tombstones so already-delivered emails fail
// safely and tell the recipient to return through their normal signing link.
func (s *Server) handleCommentReplyPage(w http.ResponseWriter, _ *http.Request) {
	s.retiredCommentReplyPage(w)
}

func (s *Server) handleCommentReplyConfirm(w http.ResponseWriter, _ *http.Request) {
	s.retiredCommentReplyPage(w)
}

func (s *Server) retiredCommentReplyPage(w http.ResponseWriter) {
	s.actionPage(w, http.StatusGone, "Reply link retired", `<p class="muted">For privacy and evidence integrity, replies must be posted from the signing page after you review the current privacy notice. Reopen the signing link from your invitation or reminder email.</p>`)
}
