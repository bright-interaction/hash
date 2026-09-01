// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package requestmeta

import "testing"

func TestClientIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{name: "IPv4 with port", remote: "192.0.2.10:43123", want: "192.0.2.10"},
		{name: "bare IPv4", remote: "192.0.2.10", want: "192.0.2.10"},
		{name: "IPv6 with port", remote: "[2001:0db8::1]:43123", want: "2001:db8::1"},
		{name: "bare IPv6", remote: "2001:0db8::1", want: "2001:db8::1"},
		{name: "bracketed IPv6 without port", remote: "[2001:0db8::1]", want: "2001:db8::1"},
		{name: "hostname with port", remote: "proxy.internal:43123", want: "proxy.internal"},
		{name: "opaque value", remote: "unknown", want: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ClientIP(test.remote); got != test.want {
				t.Fatalf("ClientIP(%q) = %q, want %q", test.remote, got, test.want)
			}
		})
	}
}
