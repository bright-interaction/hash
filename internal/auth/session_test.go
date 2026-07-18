// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"strings"
	"testing"
	"time"
)

func TestSignedCookie_RoundTrip(t *testing.T) {
	c, err := NewSignedCookie(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	tok := c.Mint([]byte("hello"), time.Minute)
	got, err := c.Verify(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("payload mismatch: got %q want %q", got, "hello")
	}
}

func TestSignedCookie_BadSignature(t *testing.T) {
	c, _ := NewSignedCookie(strings.Repeat("a", 64))
	tok := c.Mint([]byte("hello"), time.Minute)
	// Mangle the body segment (before the dot). Use a clearly non-base64
	// character so the decode itself fails OR the HMAC mismatches.
	dot := strings.Index(tok, ".")
	if dot <= 0 {
		t.Fatalf("token has no body separator: %s", tok)
	}
	tampered := tok[:dot-1] + "!" + tok[dot:]
	if _, err := c.Verify(tampered); err == nil {
		t.Fatal("tampered token verified successfully ,  expected error")
	}
}

func TestSignedCookie_Expired(t *testing.T) {
	c, _ := NewSignedCookie(strings.Repeat("a", 64))
	tok := c.Mint([]byte("hello"), -1*time.Second) // already expired
	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expired token verified ,  expected error")
	}
}

func TestSignedCookie_DifferentKeyRejects(t *testing.T) {
	c1, _ := NewSignedCookie(strings.Repeat("a", 64))
	c2, _ := NewSignedCookie(strings.Repeat("b", 64))
	tok := c1.Mint([]byte("hello"), time.Minute)
	if _, err := c2.Verify(tok); err == nil {
		t.Fatal("different-key cookie verified ,  expected error")
	}
}

func TestSignedCookie_KeyTooShort(t *testing.T) {
	if _, err := NewSignedCookie("aabbcc"); err == nil {
		t.Fatal("short key accepted ,  expected error")
	}
}

func TestMintMagicToken_HashStability(t *testing.T) {
	tok, hash, err := MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash should be 32 bytes, got %d", len(hash))
	}
	again := HashMagicToken(tok)
	if string(again) != string(hash) {
		t.Fatal("hash of same token differs from mint hash")
	}
}

func TestMintMagicToken_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, _, err := MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token after %d iterations", i)
		}
		seen[tok] = true
	}
}
