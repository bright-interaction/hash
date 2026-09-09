// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command storagecheck proves the configured object-storage encryption data
// path and owns the narrowly scoped first-install estate claim ceremony. It is
// mutating and intentionally separate from the non-mutating /ready endpoint.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	bootstrapEstateIntentPath   = "/run/hash-bootstrap-estate/intent.json"
	bootstrapEstateReceiptPath  = "/run/hash-bootstrap-estate-receipt/receipt.json"
	bootstrapEstateInventorySQL = "/run/hash-release/recovery-object-inventory.sql"
	bootstrapEstateMaxJSON      = 16 << 10
	bootstrapEstateMaxSQL       = 1 << 20
)

func main() {
	mode, err := run()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hash-storage-check:", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "hash-storage-check:", mode, "passed")
}

func run() (string, error) {
	claimBootstrapEstate := flag.Bool(
		"claim-bootstrap-estate",
		false,
		"claim or resume the fixed first-install marker from the durable pre-PUT intent",
	)
	verifyBootstrapEstate := flag.Bool(
		"verify-bootstrap-estate",
		false,
		"exhaustively verify the exact intent/receipt-bound first-install marker",
	)
	verifyBootstrapEstateMarker := flag.Bool(
		"verify-bootstrap-estate-marker",
		false,
		"verify only the exact retained marker after candidate cutover (requires separate canonical DB/object inventory)",
	)
	verifyCandidateCutoverEstate := flag.Bool(
		"verify-candidate-cutover-estate",
		false,
		"verify exact marker plus exhaustive canonical DB-referenced provider estate after an interrupted candidate cutover",
	)
	timeout := flag.Duration("timeout", time.Minute, "overall object-storage check timeout")
	flag.Parse()
	if flag.NArg() != 0 {
		return "", errors.New("unexpected positional arguments")
	}
	selectedModes := 0
	for _, selected := range []bool{*claimBootstrapEstate, *verifyBootstrapEstate, *verifyBootstrapEstateMarker, *verifyCandidateCutoverEstate} {
		if selected {
			selectedModes++
		}
	}
	if selectedModes > 1 {
		return "", errors.New("bootstrap estate modes are mutually exclusive")
	}
	if *timeout <= 0 {
		return "", errors.New("timeout must be positive")
	}

	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("configuration: %w", err)
	}
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(rootCtx, *timeout)
	defer cancel()

	store, err := storage.New(ctx, storage.Config{
		Endpoint:               cfg.S3Endpoint,
		Region:                 cfg.S3Region,
		Bucket:                 cfg.S3Bucket,
		AccessKey:              cfg.S3AccessKey,
		SecretKey:              cfg.S3SecretKey,
		UseSSL:                 cfg.S3UseSSL,
		SSEMode:                cfg.S3SSEMode,
		SSECKeyFile:            cfg.S3SSECKeyFile,
		SSECKeySHA256:          cfg.S3SSECKeySHA256,
		BucketLookup:           cfg.S3BucketLookup,
		RequireObjectLock:      !config.IsLocalDevelopment(cfg.PublicURL),
		RequireExistingBucket:  true,
		SkipTransientLifecycle: true,
	})
	if err != nil {
		return "", fmt.Errorf("initialize exact runtime storage: %w", err)
	}

	if *claimBootstrapEstate || *verifyBootstrapEstate || *verifyBootstrapEstateMarker || *verifyCandidateCutoverEstate {
		var intent storage.BootstrapEstateIntent
		if err := readExactPrivateJSON(bootstrapEstateIntentPath, &intent); err != nil {
			return "", fmt.Errorf("read durable bootstrap estate intent: %w", err)
		}
		if err := intent.Validate(); err != nil {
			return "", fmt.Errorf("validate durable bootstrap estate intent: %w", err)
		}
		if *claimBootstrapEstate {
			if _, err := store.ReconcileBootstrapEstate(ctx, intent, writeBootstrapEstateReceiptCreateOnly); err != nil {
				return "", err
			}
			return "fixed bootstrap estate claim", nil
		}
		var receipt storage.BootstrapEstateReceipt
		if err := readExactPrivateJSON(bootstrapEstateReceiptPath, &receipt); err != nil {
			return "", fmt.Errorf("read final bootstrap estate receipt: %w", err)
		}
		if *verifyCandidateCutoverEstate {
			references, err := loadCandidateCutoverReferences(ctx, cfg.DBURL, bootstrapEstateInventorySQL)
			if err != nil {
				return "", errors.New("load canonical candidate-cutover object references")
			}
			if err := store.VerifyBootstrapEstateWithReferences(ctx, intent, receipt, references); err != nil {
				return "", err
			}
			return "canonical candidate-cutover storage estate verification", nil
		}
		if *verifyBootstrapEstateMarker {
			if err := store.VerifyBootstrapEstateMarker(ctx, intent, receipt); err != nil {
				return "", err
			}
			return "exact post-cutover bootstrap estate marker verification", nil
		}
		if err := store.VerifyBootstrapEstate(ctx, intent, receipt); err != nil {
			return "", err
		}
		return "exact bootstrap estate verification", nil
	}

	if err := store.CheckDataPlane(ctx); err != nil {
		return "", err
	}
	return "encrypted PUT/GET/HEAD/DELETE", nil
}

func readExactRegularFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxBytes {
		return nil, errors.New("bounded regular file metadata is invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open regular file without following links")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open regular file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("regular file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(raw) < 1 || int64(len(raw)) > maxBytes {
		clear(raw)
		return nil, errors.New("read bounded regular file")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		clear(raw)
		return nil, errors.New("regular file changed while reading")
	}
	return raw, nil
}

func loadCandidateCutoverReferences(ctx context.Context, dsn, inventoryPath string) ([]storage.BootstrapEstateReference, error) {
	query, err := readExactRegularFile(inventoryPath, bootstrapEstateMaxSQL)
	if err != nil {
		return nil, err
	}
	defer clear(query)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, errors.New("initialize canonical inventory database connection")
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, errors.New("begin canonical inventory snapshot")
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := validateCandidateCutoverBlockEvidence(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, string(query))
	if err != nil {
		return nil, errors.New("query canonical storage inventory")
	}
	defer rows.Close()
	references := make([]storage.BootstrapEstateReference, 0)
	for rows.Next() {
		var (
			keyBase64, keyJSON, classes, owners, orgIDs  string
			expectedSHA, expectedVersion, expectedRetain string
			hashConflict, legal, versionConflict, legacy bool
			referenceCount                               int64
		)
		if err := rows.Scan(&keyBase64, &keyJSON, &classes, &owners, &orgIDs,
			&expectedSHA, &hashConflict, &legal, &referenceCount, &expectedVersion,
			&versionConflict, &legacy, &expectedRetain); err != nil {
			return nil, errors.New("decode canonical storage inventory row")
		}
		_ = keyJSON
		_ = classes
		_ = owners
		_ = orgIDs
		if hashConflict || versionConflict || legacy || referenceCount < 1 {
			return nil, errors.New("canonical storage inventory contains a conflict or legacy lookup")
		}
		keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil || base64.StdEncoding.EncodeToString(keyBytes) != keyBase64 || !utf8.Valid(keyBytes) {
			clear(keyBytes)
			return nil, errors.New("canonical storage inventory contains an invalid key")
		}
		reference := storage.BootstrapEstateReference{Key: string(keyBytes), LegalEvidence: legal}
		clear(keyBytes)
		if expectedVersion != "-" {
			reference.VersionID = expectedVersion
		}
		if expectedSHA != "-" {
			if len(expectedSHA) != 64 || expectedSHA != strings.ToLower(expectedSHA) {
				return nil, errors.New("canonical storage inventory contains an invalid digest")
			}
			digest, err := hex.DecodeString(expectedSHA)
			if err != nil || len(digest) != 32 {
				clear(digest)
				return nil, errors.New("canonical storage inventory contains an invalid digest")
			}
			reference.SHA256 = digest
			if reference.VersionID == "" {
				clear(digest)
				return nil, errors.New("candidate-cutover digest reference lacks an exact provider VersionId")
			}
		}
		if expectedRetain != "-" {
			retainUntil, err := time.Parse(time.RFC3339, expectedRetain)
			if err != nil || retainUntil.Location() != time.UTC || retainUntil.Nanosecond() != 0 ||
				retainUntil.Format(time.RFC3339) != expectedRetain {
				return nil, errors.New("canonical storage inventory contains an invalid retention deadline")
			}
			reference.RetainUntil = retainUntil
		}
		if legal != (expectedRetain != "-") {
			return nil, errors.New("canonical storage inventory legal classification lacks an exact retention deadline")
		}
		references = append(references, reference)
	}
	if rows.Err() != nil {
		return nil, errors.New("canonical storage inventory did not complete")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("finish canonical storage inventory snapshot")
	}
	return references, nil
}

func validateCandidateCutoverBlockEvidence(ctx context.Context, tx pgx.Tx) error {
	const query = `
WITH frozen_documents AS (
    SELECT d.id
      FROM documents d
     WHERE d.status IN ('sent','in_progress','changes_requested','finalizing','completed','declined','voided','expired')
        OR (d.status = 'sealing' AND EXISTS (
            SELECT 1
              FROM send_sealing_intents si
             WHERE si.document_id = COALESCE(d.parent_envelope_id, d.id)
               AND si.org_id = d.org_id
               AND si.retention_started_at IS NOT NULL
        ))
)
SELECT d.blocks_json
  FROM documents d
  JOIN frozen_documents frozen ON frozen.id = d.id
 WHERE d.blocks_json IS NOT NULL
UNION ALL
SELECT v.block_tree_json
  FROM document_versions v
  JOIN frozen_documents frozen ON frozen.id = v.document_id
 WHERE v.block_tree_json IS NOT NULL`
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return errors.New("query immutable block-evidence inventory")
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return errors.New("decode immutable block-evidence inventory")
		}
		tree, err := blocks.ParseCanonicalTree(raw)
		clear(raw)
		if err != nil {
			return errors.New("candidate-cutover immutable block evidence is not canonical")
		}
		if err := blocks.ValidateImmutableSigningEvidence(tree); err != nil {
			return errors.New("candidate-cutover immutable block evidence contains unsupported or unpinned content")
		}
	}
	if rows.Err() != nil {
		return errors.New("immutable block-evidence inventory did not complete")
	}
	return nil
}

func readExactPrivateJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("private JSON file metadata is invalid")
	}
	before, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(before.Uid) != os.Geteuid() || before.Nlink != 1 || info.Size() < 2 || info.Size() > bootstrapEstateMaxJSON {
		return errors.New("private JSON file identity is invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open private JSON file without following links")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("open private JSON file")
	}
	defer file.Close()
	afterInfo, err := file.Stat()
	if err != nil {
		return errors.New("inspect opened private JSON file")
	}
	after, ok := afterInfo.Sys().(*syscall.Stat_t)
	if !ok || before.Dev != after.Dev || before.Ino != after.Ino || after.Nlink != 1 ||
		int(after.Uid) != os.Geteuid() || afterInfo.Mode().Perm() != 0o600 || afterInfo.Size() != info.Size() {
		return errors.New("private JSON file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, bootstrapEstateMaxJSON+1))
	if err != nil || len(raw) > bootstrapEstateMaxJSON {
		clear(raw)
		return errors.New("read bounded private JSON file")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("decode private JSON file")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("private JSON file contains trailing data")
	}
	return nil
}

func writeBootstrapEstateReceiptCreateOnly(receipt storage.BootstrapEstateReceipt) error {
	return writeBootstrapEstateReceiptCreateOnlyAt(bootstrapEstateReceiptPath, receipt)
}

func writeBootstrapEstateReceiptCreateOnlyAt(path string, receipt storage.BootstrapEstateReceipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("bootstrap estate receipt directory metadata is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("bootstrap estate receipt directory identity is invalid")
	}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return errors.New("encode bootstrap estate receipt")
	}
	raw = append(raw, '\n')
	defer clear(raw)
	fd, err := syscall.Open(path,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("create final bootstrap estate receipt exactly once")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("create final bootstrap estate receipt")
	}
	written, writeErr := file.Write(raw)
	if writeErr == nil && written != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("durably write final bootstrap estate receipt")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return errors.New("open bootstrap estate receipt directory for durability")
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("durably publish final bootstrap estate receipt")
	}
	var readback storage.BootstrapEstateReceipt
	if err := readExactPrivateJSON(path, &readback); err != nil || readback != receipt {
		return errors.New("final bootstrap estate receipt readback changed")
	}
	return nil
}
