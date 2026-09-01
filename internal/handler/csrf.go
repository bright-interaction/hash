// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/url"
	"strings"
)

// requireSameOriginMutation rejects cookie-authenticated browser writes from
// sibling or foreign origins. Requests without browser fetch metadata remain
// available to trusted non-browser clients that explicitly possess a session
// cookie; browsers send Origin and/or Sec-Fetch-Site for unsafe requests.
func (s *Server) requireSameOriginMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
			case "", "none", "same-origin":
				next.ServeHTTP(w, r)
			default:
				http.Error(w, "cross-origin mutation refused", http.StatusForbidden)
			}
			return
		}

		if !allowedMutationOrigin(origin, r.Host, s.PublicURL) {
			http.Error(w, "cross-origin mutation refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowedMutationOrigin(origin, requestHost, publicURL string) bool {
	o, err := url.Parse(origin)
	if err != nil || (o.Scheme != "http" && o.Scheme != "https") || o.User != nil || o.Host == "" || o.Path != "" || o.RawQuery != "" || o.Fragment != "" {
		return false
	}
	p, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.User != nil || p.Host == "" {
		return false
	}
	originHost := strings.ToLower(o.Host)
	if strings.EqualFold(o.Scheme, p.Scheme) && originHost == strings.ToLower(strings.TrimSpace(requestHost)) {
		return true
	}
	return strings.EqualFold(o.Scheme, p.Scheme) && originHost == strings.ToLower(p.Host)
}
