// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package secretbox provides the versioned authenticated-encryption envelope
// used for durable application secrets. Callers supply purpose-specific AAD so
// ciphertext copied to a different database row cannot be opened there.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	VersionV1 byte = 0x01
	keySize        = 32
)

var (
	ErrInvalidKey        = errors.New("secretbox: key must be exactly 32 bytes")
	ErrInvalidCiphertext = errors.New("secretbox: invalid ciphertext")
)

// Box seals with Current and can optionally open data sealed with Previous.
// Open reports whether Previous was used so callers can immediately rewrap the
// value under Current and finish a key rotation without exposing plaintext in
// the database.
type Box struct {
	current  [keySize]byte
	previous *[keySize]byte
}

func New(current, previous []byte) (*Box, error) {
	if len(current) != keySize {
		return nil, ErrInvalidKey
	}
	b := &Box{}
	copy(b.current[:], current)
	if len(previous) > 0 {
		if len(previous) != keySize {
			return nil, ErrInvalidKey
		}
		var p [keySize]byte
		copy(p[:], previous)
		b.previous = &p
	}
	return b, nil
}

// Seal returns version || nonce || AES-256-GCM ciphertext. The supplied AAD is
// authenticated but not stored; Open must receive the exact same bytes.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	if b == nil {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(b.current[:])
	if err != nil {
		return nil, fmt.Errorf("secretbox: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretbox: nonce: %w", err)
	}
	out := make([]byte, 1, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out[0] = VersionV1
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open authenticates and decrypts blob. usedPrevious is true only when the
// current key failed authentication and the optional previous key succeeded.
func (b *Box) Open(blob, aad []byte) (plaintext []byte, usedPrevious bool, err error) {
	if b == nil {
		return nil, false, ErrInvalidKey
	}
	plaintext, err = openWithKey(b.current[:], blob, aad)
	if err == nil {
		return plaintext, false, nil
	}
	if b.previous == nil {
		return nil, false, err
	}
	plaintext, previousErr := openWithKey(b.previous[:], blob, aad)
	if previousErr == nil {
		return plaintext, true, nil
	}
	// Return one stable error without disclosing which configured key was closer
	// to succeeding or echoing any secret/ciphertext bytes.
	return nil, false, ErrInvalidCiphertext
}

func openWithKey(key, blob, aad []byte) ([]byte, error) {
	if len(key) != keySize || len(blob) == 0 || blob[0] != VersionV1 {
		return nil, ErrInvalidCiphertext
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	if len(blob) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	nonce := blob[1 : 1+gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, blob[1+gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}
