// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package webhooksecret

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func keyHex(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw)
}

func generatedSecret(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed ^ byte(i+1)
	}
	return hex.EncodeToString(raw)
}

type memoryRepository struct {
	rows     map[uuid.UUID]endpointRow
	replaces int
}

func newMemoryRepository(rows ...endpointRow) *memoryRepository {
	repo := &memoryRepository{rows: make(map[uuid.UUID]endpointRow, len(rows))}
	for _, row := range rows {
		repo.rows[row.ID] = cloneRow(row)
	}
	return repo
}

func cloneRow(row endpointRow) endpointRow {
	row.Ciphertext = append([]byte(nil), row.Ciphertext...)
	if row.CiphertextPresent && row.Ciphertext == nil {
		row.Ciphertext = []byte{}
	}
	return row
}

func (r *memoryRepository) list(context.Context) ([]endpointRow, error) {
	out := make([]endpointRow, 0, len(r.rows))
	for _, row := range r.rows {
		out = append(out, cloneRow(row))
	}
	return out, nil
}

func (r *memoryRepository) get(_ context.Context, id uuid.UUID) (endpointRow, error) {
	row, ok := r.rows[id]
	if !ok {
		return endpointRow{}, errors.New("not found")
	}
	return cloneRow(row), nil
}

func (r *memoryRepository) replace(_ context.Context, expected endpointRow, ciphertext []byte) (bool, error) {
	row, ok := r.rows[expected.ID]
	if !ok || row.OrgID != expected.OrgID || row.Plaintext != expected.Plaintext || row.CiphertextPresent != expected.CiphertextPresent {
		return false, nil
	}
	if row.CiphertextPresent && string(row.Ciphertext) != string(expected.Ciphertext) {
		return false, nil
	}
	row.Plaintext = ""
	row.Ciphertext = append([]byte(nil), ciphertext...)
	row.CiphertextPresent = true
	r.rows[row.ID] = row
	r.replaces++
	return true, nil
}

func TestSealNewPreservesDisplayedASCIIAndBindsRow(t *testing.T) {
	keys, err := NewKeyringHex(keyHex(1), "")
	if err != nil {
		t.Fatal(err)
	}
	orgID, endpointID := uuid.New(), uuid.New()
	secret := generatedSecret(0x5a)
	ct, err := keys.SealNew(orgID, endpointID, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, previous, err := keys.open(orgID, endpointID, ct)
	if err != nil || previous || got != secret {
		t.Fatalf("open = %q previous=%v err=%v, want exact displayed ASCII", got, previous, err)
	}
	if _, _, err := keys.open(orgID, uuid.New(), ct); err == nil {
		t.Fatal("ciphertext opened under a different endpoint UUID")
	}
	if _, _, err := keys.open(uuid.New(), endpointID, ct); err == nil {
		t.Fatal("ciphertext opened under a different org UUID")
	}
}

func TestBackfillEncryptsAndBlanksLegacyRows(t *testing.T) {
	keys, _ := NewKeyringHex(keyHex(2), "")
	plainID, fallbackID, orgID := uuid.New(), uuid.New(), uuid.New()
	plainSecret := generatedSecret(0x33)
	fallbackSecret := generatedSecret(0x44)
	repo := newMemoryRepository(
		endpointRow{ID: plainID, OrgID: orgID, URL: "https://one.test", Plaintext: plainSecret},
		endpointRow{ID: fallbackID, OrgID: orgID, URL: "https://two.test"},
	)
	manager, err := newManagerWithRepository(keys, fallbackSecret, repo)
	if err != nil {
		t.Fatal(err)
	}
	report, err := manager.Backfill(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Rows != 2 || report.EncryptedLegacy != 2 || report.ClearedPlaintext != 1 {
		t.Fatalf("report = %+v", report)
	}
	for id, want := range map[uuid.UUID]string{plainID: plainSecret, fallbackID: fallbackSecret} {
		row := repo.rows[id]
		if row.Plaintext != "" || !row.CiphertextPresent || len(row.Ciphertext) == 0 {
			t.Fatalf("row %s not atomically encrypted and blanked: %+v", id, row)
		}
		got, _, err := keys.open(orgID, id, row.Ciphertext)
		if err != nil || got != want {
			t.Fatalf("row %s open = %q err=%v, want %q", id, got, err, want)
		}
	}
}

func TestPresentTamperedCiphertextNeverFallsBack(t *testing.T) {
	keys, _ := NewKeyringHex(keyHex(3), "")
	id, orgID := uuid.New(), uuid.New()
	secret := generatedSecret(0x55)
	ct, err := keys.SealNew(orgID, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	repo := newMemoryRepository(endpointRow{
		ID: id, OrgID: orgID, URL: "https://tampered.test",
		Plaintext: secret, Ciphertext: ct, CiphertextPresent: true,
	})
	manager, _ := newManagerWithRepository(keys, generatedSecret(0x66), repo)
	if _, _, err := manager.Endpoint(context.Background(), id); err == nil {
		t.Fatal("tampered ciphertext fell back to plaintext/global key")
	}
	if repo.replaces != 0 {
		t.Fatalf("tampered row was rewritten %d time(s)", repo.replaces)
	}
}

func TestBackfillRewrapsPreviousKeyAndThenOpensCurrentOnly(t *testing.T) {
	oldKeys, _ := NewKeyringHex(keyHex(4), "")
	rotating, _ := NewKeyringHex(keyHex(5), keyHex(4))
	id, orgID := uuid.New(), uuid.New()
	secret := generatedSecret(0x77)
	oldCiphertext, err := oldKeys.SealNew(orgID, id, secret)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryRepository(endpointRow{
		ID: id, OrgID: orgID, URL: "https://rotate.test",
		Ciphertext: oldCiphertext, CiphertextPresent: true,
	})
	manager, _ := newManagerWithRepository(rotating, "", repo)
	report, err := manager.Backfill(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.RewrappedPreviousKey != 1 || repo.replaces != 1 {
		t.Fatalf("report=%+v replaces=%d", report, repo.replaces)
	}
	currentOnly, _ := NewKeyringHex(keyHex(5), "")
	got, previous, err := currentOnly.open(orgID, id, repo.rows[id].Ciphertext)
	if err != nil || previous || got != secret {
		t.Fatalf("current-only open = %q previous=%v err=%v", got, previous, err)
	}
}

func TestBackfillRejectsMismatchedDualWriteAndWeakFallback(t *testing.T) {
	keys, _ := NewKeyringHex(keyHex(6), "")
	id, orgID := uuid.New(), uuid.New()
	ct, _ := keys.SealNew(orgID, id, generatedSecret(0x11))
	repo := newMemoryRepository(endpointRow{
		ID: id, OrgID: orgID, Plaintext: generatedSecret(0x22),
		Ciphertext: ct, CiphertextPresent: true,
	})
	manager, _ := newManagerWithRepository(keys, "", repo)
	if _, err := manager.Backfill(context.Background()); err == nil {
		t.Fatal("mismatched dual-written secret was accepted")
	}
	if _, err := newManagerWithRepository(keys, "changeme", repo); err == nil {
		t.Fatal("weak legacy global secret was accepted")
	}
}

func TestEmptyPresentCiphertextIsNotLegacy(t *testing.T) {
	keys, _ := NewKeyringHex(keyHex(7), "")
	id, orgID := uuid.New(), uuid.New()
	repo := newMemoryRepository(endpointRow{
		ID: id, OrgID: orgID, Ciphertext: []byte{}, CiphertextPresent: true,
	})
	manager, _ := newManagerWithRepository(keys, generatedSecret(0x33), repo)
	if _, _, err := manager.Endpoint(context.Background(), id); err == nil {
		t.Fatal("present empty ciphertext entered legacy fallback")
	}
}
