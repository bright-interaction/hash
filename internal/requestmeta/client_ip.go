// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package requestmeta normalizes security-relevant HTTP request metadata.
package requestmeta

import (
	"net"
	"strings"
)

// ClientIP returns a canonical client address from http.Request.RemoteAddr.
// RemoteAddr is normally host:port, but tests, internal callers, and some
// transports may provide a bare IPv4 or IPv6 literal. A last-colon split is
// unsafe because it truncates bare IPv6 addresses.
func ClientIP(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}

	// SplitHostPort removes IPv6 brackets. Also tolerate a bracketed, portless
	// literal so audit records never persist transport punctuation as identity.
	candidate := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if ip := net.ParseIP(candidate); ip != nil {
		return ip.String()
	}
	return addr
}
