// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package nethard provides an SSRF-hardened HTTP transport for outbound calls
// to tenant-controlled URLs (webhooks, BYOAI endpoints). The guard runs at DIAL
// time, on the exact IP the kernel is about to connect to, so it closes SSRF via
// DNS rebinding: a prior LookupIP-based check can be raced by a short-TTL
// resolver that answers the check with a public IP and the dial with an internal
// one, but a net.Dialer.Control hook validates the real connect address and
// cannot be raced. It also re-runs on every redirect hop.
package nethard

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

var (
	_, cgnatRange, _     = net.ParseCIDR("100.64.0.0/10")
	_, benchmarkRange, _ = net.ParseCIDR("198.18.0.0/15")
)

// IsBlockedIP reports whether ip is one an SSRF guard must refuse: nil,
// loopback, RFC1918 private, link-local (incl. 169.254 cloud metadata),
// unspecified, multicast, shared-address-space (CGNAT/Tailscale), or the
// benchmarking range frequently used for private service networks.
func IsBlockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() ||
		cgnatRange.Contains(ip) || benchmarkRange.Contains(ip)
}

// dialControl returns a net.Dialer.Control that refuses to connect to a blocked
// IP unless allowPrivate() is true (local dev/e2e). address is "host:port" where
// host is the resolved IP the dial is about to use.
func dialControl(allowPrivate func() bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		if allowPrivate != nil && allowPrivate() {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("nethard: bad dial address %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if IsBlockedIP(ip) {
			return fmt.Errorf("nethard: refused connection to internal address %s", host)
		}
		return nil
	}
}

// Transport returns an *http.Transport whose dialer enforces the blocked-IP
// guard at dial time. allowPrivate is read at dial time so a caller may flip a
// flag after construction.
func Transport(allowPrivate func() bool) *http.Transport {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl(allowPrivate),
	}
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 25 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
	}
}

// Client returns an *http.Client using the hardened Transport with redirects
// disabled. Its current consumers send AI prompts together with API-key
// headers; following even a public redirect could replay that credential/body
// to a different origin or downgrade HTTPS. API endpoints are configured as
// final URLs, so a redirect is treated as a fail-closed configuration error.
func Client(timeout time.Duration, allowPrivate func() bool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(allowPrivate),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("nethard: redirects are disabled for credentialed requests")
		},
	}
}
