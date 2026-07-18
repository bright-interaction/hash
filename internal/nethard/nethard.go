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

// IsBlockedIP reports whether ip is one an SSRF guard must refuse: nil,
// loopback, RFC1918 private, link-local (incl. 169.254 cloud metadata),
// unspecified, or multicast.
func IsBlockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
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

// Client returns an *http.Client using the hardened Transport plus a redirect
// cap. Each redirect hop re-dials through the same Control guard, so a 3xx to an
// internal host is refused too.
func Client(timeout time.Duration, allowPrivate func() bool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(allowPrivate),
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("nethard: stopped after 3 redirects")
			}
			return nil
		},
	}
}
