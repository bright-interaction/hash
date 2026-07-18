// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package actiontoken

import (
	"testing"
	"time"
)

func TestMintVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := Claims{Kind: "cr", OrgID: "org", DocID: "doc", TargetID: "cr1", Action: "approve"}
	tok := Mint("secret-key-of-decent-length-xxxx", c, now, time.Hour)
	got, err := Verify("secret-key-of-decent-length-xxxx", tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Kind != "cr" || got.OrgID != "org" || got.DocID != "doc" || got.TargetID != "cr1" || got.Action != "approve" {
		t.Fatalf("claims roundtrip mismatch: %+v", got)
	}
}

func TestVerifyExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok := Mint("k", Claims{Kind: "cr", Action: "deny"}, now, time.Minute)
	if _, err := Verify("k", tok, now.Add(2*time.Minute)); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerifyTamperAndWrongKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok := Mint("k1", Claims{Kind: "cr", Action: "approve"}, now, time.Hour)
	if _, err := Verify("k2", tok, now); err != ErrBadSig {
		t.Fatalf("expected ErrBadSig on wrong key, got %v", err)
	}
	// Flip a payload char.
	bad := []byte(tok)
	bad[0] = bad[0] ^ 0x01
	if _, err := Verify("k1", string(bad), now); err == nil {
		t.Fatal("expected error on tampered token")
	}
}
