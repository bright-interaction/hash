// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill + byte(i)
	}
	return key
}

func TestRoundTripIsVersionedAndRandomized(t *testing.T) {
	box, err := New(testKey(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	aad := []byte("hash/webhook/org/endpoint")
	a, err := box.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := box.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if a[0] != VersionV1 || bytes.Equal(a, b) {
		t.Fatal("secretbox output is unversioned or reused a nonce")
	}
	got, previous, err := box.Open(a, aad)
	if err != nil || previous || !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q, previous=%v, err=%v", got, previous, err)
	}
}

func TestOpenRejectsTamperWrongKeyAndWrongAAD(t *testing.T) {
	box, _ := New(testKey(2), nil)
	blob, err := box.Seal([]byte("secret"), []byte("org-a/endpoint-a"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	wrong, _ := New(testKey(3), nil)
	for name, candidate := range map[string]struct {
		box  *Box
		blob []byte
		aad  []byte
	}{
		"tamper":    {box: box, blob: tampered, aad: []byte("org-a/endpoint-a")},
		"wrong key": {box: wrong, blob: blob, aad: []byte("org-a/endpoint-a")},
		"wrong aad": {box: box, blob: blob, aad: []byte("org-b/endpoint-a")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := candidate.box.Open(candidate.blob, candidate.aad); !errors.Is(err, ErrInvalidCiphertext) {
				t.Fatalf("Open error = %v, want ErrInvalidCiphertext", err)
			}
		})
	}
}

func TestPreviousKeyRotation(t *testing.T) {
	oldKey := testKey(4)
	newKey := testKey(5)
	aad := []byte("bound-row")
	oldBox, _ := New(oldKey, nil)
	oldBlob, err := oldBox.Seal([]byte("verbatim-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	rotating, _ := New(newKey, oldKey)
	plain, previous, err := rotating.Open(oldBlob, aad)
	if err != nil || !previous || string(plain) != "verbatim-secret" {
		t.Fatalf("rotation open = %q, previous=%v, err=%v", plain, previous, err)
	}
	newBlob, err := rotating.Seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	currentOnly, _ := New(newKey, nil)
	if _, previous, err := currentOnly.Open(newBlob, aad); err != nil || previous {
		t.Fatalf("rewrapped open previous=%v err=%v", previous, err)
	}
	if _, _, err := currentOnly.Open(oldBlob, aad); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("old blob opened without previous key: %v", err)
	}
}
