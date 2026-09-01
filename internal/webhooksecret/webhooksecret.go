// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package webhooksecret owns Hash's per-endpoint webhook signing keys: their
// row-bound encryption, legacy migration, and worker-time resolution.
package webhooksecret

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/secretbox"
)

const aadDomain = "hash/webhook-endpoint-secret/v1\x00"

var ErrConcurrentChange = errors.New("webhook secret: row changed concurrently")

// Keyring holds the dedicated current and optional previous webhook-encryption
// keys. These keys are separate from session, signer-token, and AI keys.
type Keyring struct {
	box *secretbox.Box
}

// Mint creates the 32 random bytes whose lowercase-hex representation is used
// verbatim as a webhook HMAC key by Hash and its receiver.
func Mint() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("webhook secret: generate signing key: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func NewKeyringHex(currentHex, previousHex string) (*Keyring, error) {
	current, err := decodeKey("current", currentHex)
	if err != nil {
		return nil, err
	}
	var previous []byte
	if previousHex != "" {
		previous, err = decodeKey("previous", previousHex)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(current, previous) == 1 {
			return nil, errors.New("webhook secret: current and previous encryption keys must differ")
		}
	}
	box, err := secretbox.New(current, previous)
	if err != nil {
		return nil, err
	}
	return &Keyring{box: box}, nil
}

func decodeKey(label, encoded string) ([]byte, error) {
	if len(encoded) != 64 {
		return nil, fmt.Errorf("webhook secret: %s encryption key must be 64 hex characters", label)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("webhook secret: %s encryption key must encode exactly 32 bytes", label)
	}
	allSame := true
	for i := 1; i < len(raw); i++ {
		if raw[i] != raw[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return nil, fmt.Errorf("webhook secret: %s encryption key has no usable entropy", label)
	}
	return raw, nil
}

// SealNew seals a newly generated 64-character lowercase-hex HMAC key. The
// string bytes are encrypted verbatim: receivers use the displayed ASCII value
// as the HMAC key and must not hex-decode it.
func (k *Keyring) SealNew(orgID, endpointID uuid.UUID, secret string) ([]byte, error) {
	if !IsGeneratedSecret(secret) {
		return nil, errors.New("webhook secret: new signing key must be 32 random bytes encoded as lowercase hex")
	}
	return k.seal(orgID, endpointID, secret)
}

func (k *Keyring) seal(orgID, endpointID uuid.UUID, secret string) ([]byte, error) {
	if k == nil || k.box == nil {
		return nil, errors.New("webhook secret: encryption keyring is unavailable")
	}
	return k.box.Seal([]byte(secret), endpointAAD(orgID, endpointID))
}

func (k *Keyring) open(orgID, endpointID uuid.UUID, ciphertext []byte) (string, bool, error) {
	if k == nil || k.box == nil {
		return "", false, errors.New("webhook secret: encryption keyring is unavailable")
	}
	plain, previous, err := k.box.Open(ciphertext, endpointAAD(orgID, endpointID))
	if err != nil {
		return "", false, fmt.Errorf("webhook secret: authenticate endpoint %s: %w", endpointID, err)
	}
	secret := string(plain)
	if !IsStrongSigningSecret(secret) {
		return "", false, fmt.Errorf("webhook secret: endpoint %s decrypted to an unsafe signing key", endpointID)
	}
	return secret, previous, nil
}

func endpointAAD(orgID, endpointID uuid.UUID) []byte {
	return []byte(aadDomain + orgID.String() + "\x00" + endpointID.String())
}

func IsGeneratedSecret(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && IsStrongSigningSecret(value)
}

// IsStrongSigningSecret accepts historical non-hex HMAC keys only when they
// have at least 32 non-uniform bytes and no surrounding whitespace. It exists
// solely for the legacy backfill; all new secrets pass IsGeneratedSecret.
func IsStrongSigningSecret(value string) bool {
	if len(value) < 32 || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return true
		}
	}
	return false
}

type endpointRow struct {
	ID                uuid.UUID
	OrgID             uuid.UUID
	URL               string
	Plaintext         string
	Ciphertext        []byte
	CiphertextPresent bool
}

type repository interface {
	list(context.Context) ([]endpointRow, error)
	get(context.Context, uuid.UUID) (endpointRow, error)
	replace(context.Context, endpointRow, []byte) (bool, error)
}

type postgresRepository struct {
	pool *pgxpool.Pool
}

func (r postgresRepository) list(ctx context.Context) ([]endpointRow, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, org_id, url, secret, secret_ciphertext,
		secret_ciphertext IS NOT NULL
		FROM webhook_endpoints ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("webhook secret: list endpoints for backfill: %w", err)
	}
	defer rows.Close()
	out := make([]endpointRow, 0)
	for rows.Next() {
		row, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("webhook secret: iterate endpoints for backfill: %w", err)
	}
	return out, nil
}

func (r postgresRepository) get(ctx context.Context, id uuid.UUID) (endpointRow, error) {
	row, err := scanEndpoint(r.pool.QueryRow(ctx, `SELECT id, org_id, url, secret, secret_ciphertext,
		secret_ciphertext IS NOT NULL
		FROM webhook_endpoints WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return endpointRow{}, fmt.Errorf("webhook secret: endpoint %s not found: %w", id, err)
	}
	return row, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanEndpoint(row rowScanner) (endpointRow, error) {
	var out endpointRow
	if err := row.Scan(&out.ID, &out.OrgID, &out.URL, &out.Plaintext, &out.Ciphertext, &out.CiphertextPresent); err != nil {
		return endpointRow{}, err
	}
	// Presence comes from SQL rather than slice nil-ness. An empty-but-present
	// BYTEA is corruption and must fail authentication, never enter fallback,
	// even if a driver represents SQL NULL and empty bytes identically.
	return out, nil
}

func (r postgresRepository) replace(ctx context.Context, expected endpointRow, ciphertext []byte) (bool, error) {
	var rowsAffected int64
	if expected.CiphertextPresent {
		command, err := r.pool.Exec(ctx, `UPDATE webhook_endpoints
			SET secret_ciphertext = $3, secret = ''
			WHERE id = $1 AND org_id = $2 AND secret = $4 AND secret_ciphertext = $5`,
			expected.ID, expected.OrgID, ciphertext, expected.Plaintext, expected.Ciphertext)
		if err != nil {
			return false, fmt.Errorf("webhook secret: persist encrypted endpoint %s: %w", expected.ID, err)
		}
		rowsAffected = command.RowsAffected()
	} else {
		command, err := r.pool.Exec(ctx, `UPDATE webhook_endpoints
			SET secret_ciphertext = $3, secret = ''
			WHERE id = $1 AND org_id = $2 AND secret = $4 AND secret_ciphertext IS NULL`,
			expected.ID, expected.OrgID, ciphertext, expected.Plaintext)
		if err != nil {
			return false, fmt.Errorf("webhook secret: persist encrypted endpoint %s: %w", expected.ID, err)
		}
		rowsAffected = command.RowsAffected()
	}
	return rowsAffected == 1, nil
}

// Manager combines the keyring with PostgreSQL and the optional legacy global
// signing key used only to convert pre-00024 rows whose plaintext column is
// empty. It never uses the legacy value when ciphertext is present.
type Manager struct {
	keys   *Keyring
	legacy string
	repo   repository
}

func NewManager(pool *pgxpool.Pool, keys *Keyring, legacy string) (*Manager, error) {
	if pool == nil || keys == nil {
		return nil, errors.New("webhook secret: pool and keyring are required")
	}
	if legacy != "" && !IsStrongSigningSecret(legacy) {
		return nil, errors.New("webhook secret: HASH_WEBHOOK_SECRET is too weak for legacy migration")
	}
	return &Manager{keys: keys, legacy: legacy, repo: postgresRepository{pool: pool}}, nil
}

func newManagerWithRepository(keys *Keyring, legacy string, repo repository) (*Manager, error) {
	if keys == nil || repo == nil {
		return nil, errors.New("webhook secret: keyring and repository are required")
	}
	if legacy != "" && !IsStrongSigningSecret(legacy) {
		return nil, errors.New("webhook secret: legacy signing key is too weak")
	}
	return &Manager{keys: keys, legacy: legacy, repo: repo}, nil
}

type resolution struct {
	secret            string
	ciphertext        []byte
	write             bool
	legacy            bool
	rewrappedPrevious bool
	clearedPlaintext  bool
}

func (m *Manager) resolve(row endpointRow) (resolution, error) {
	if row.CiphertextPresent {
		secret, previous, err := m.keys.open(row.OrgID, row.ID, row.Ciphertext)
		if err != nil {
			// Deliberately do not inspect row.Plaintext or m.legacy here. A present
			// but unauthentic ciphertext is corruption/tampering, not a migration
			// signal, and falling back would silently weaken the trust boundary.
			return resolution{}, err
		}
		if row.Plaintext != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(row.Plaintext)) != 1 {
			return resolution{}, fmt.Errorf("webhook secret: endpoint %s plaintext/ciphertext mismatch", row.ID)
		}
		out := resolution{
			secret:            secret,
			ciphertext:        append([]byte(nil), row.Ciphertext...),
			write:             previous || row.Plaintext != "",
			rewrappedPrevious: previous,
			clearedPlaintext:  row.Plaintext != "",
		}
		if previous {
			out.ciphertext, err = m.keys.seal(row.OrgID, row.ID, secret)
			if err != nil {
				return resolution{}, err
			}
		}
		return out, nil
	}

	secret := row.Plaintext
	usedLegacyFallback := false
	if secret == "" {
		secret = m.legacy
		usedLegacyFallback = true
	}
	if !IsStrongSigningSecret(secret) {
		return resolution{}, fmt.Errorf("webhook secret: endpoint %s has no strong legacy signing key to migrate", row.ID)
	}
	ciphertext, err := m.keys.seal(row.OrgID, row.ID, secret)
	if err != nil {
		return resolution{}, err
	}
	return resolution{
		secret:           secret,
		ciphertext:       ciphertext,
		write:            true,
		legacy:           usedLegacyFallback || row.Plaintext != "",
		clearedPlaintext: row.Plaintext != "",
	}, nil
}

// Endpoint returns the URL and authenticated signing key needed by the worker.
// A legacy row is converted with one atomic UPDATE before the key is returned.
func (m *Manager) Endpoint(ctx context.Context, id uuid.UUID) (string, string, error) {
	row, err := m.repo.get(ctx, id)
	if err != nil {
		return "", "", err
	}
	row, result, err := m.ensure(ctx, row)
	if err != nil {
		return "", "", err
	}
	return row.URL, result.secret, nil
}

type BackfillReport struct {
	Rows                 int
	EncryptedLegacy      int
	RewrappedPreviousKey int
	ClearedPlaintext     int
}

// Backfill authenticates every existing ciphertext, encrypts every legacy row,
// rewraps values opened with the previous key, and blanks plaintext in the same
// compare-and-swap UPDATE that persists ciphertext. It is idempotent and safe
// for server/worker startup races.
func (m *Manager) Backfill(ctx context.Context) (BackfillReport, error) {
	rows, err := m.repo.list(ctx)
	if err != nil {
		return BackfillReport{}, err
	}
	report := BackfillReport{Rows: len(rows)}
	for _, row := range rows {
		_, result, err := m.ensure(ctx, row)
		if err != nil {
			return report, err
		}
		if result.legacy {
			report.EncryptedLegacy++
		}
		if result.rewrappedPrevious {
			report.RewrappedPreviousKey++
		}
		if result.clearedPlaintext {
			report.ClearedPlaintext++
		}
	}
	return report, nil
}

func (m *Manager) ensure(ctx context.Context, row endpointRow) (endpointRow, resolution, error) {
	for attempt := 0; attempt < 3; attempt++ {
		result, err := m.resolve(row)
		if err != nil {
			return endpointRow{}, resolution{}, err
		}
		if !result.write {
			return row, result, nil
		}
		updated, err := m.repo.replace(ctx, row, result.ciphertext)
		if err != nil {
			return endpointRow{}, resolution{}, err
		}
		if updated {
			row.Ciphertext = append([]byte(nil), result.ciphertext...)
			row.CiphertextPresent = true
			row.Plaintext = ""
			return row, result, nil
		}
		row, err = m.repo.get(ctx, row.ID)
		if err != nil {
			return endpointRow{}, resolution{}, err
		}
	}
	return endpointRow{}, resolution{}, ErrConcurrentChange
}
