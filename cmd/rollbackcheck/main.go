// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command rollbackcheck is the fail-closed boundary before a Hash deployment
// can restart a previous application image. The candidate server and worker
// must already be stopped. It rejects every durable sealing/finalization state
// that only the candidate lifecycle contract may know how to resume.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	hashdb "github.com/bright-interaction/hash/internal/db"
)

type rollbackResult struct {
	Safe                bool  `json:"safe"`
	Complete            bool  `json:"complete"`
	SealingDocuments    int64 `json:"sealing_documents"`
	SendIntents         int64 `json:"send_sealing_intents"`
	FinalizingDocuments int64 `json:"finalizing_documents"`
	FinalizationIntents int64 `json:"document_finalization_intents"`
}

type lawfulBasisCutoverResult struct {
	Safe                         bool  `json:"safe"`
	Complete                     bool  `json:"complete"`
	ActiveDocuments              int64 `json:"active_documents"`
	MissingMatchingConfirmations int64 `json:"missing_matching_confirmations"`
}

type article13CutoverResult struct {
	Safe                   bool  `json:"safe"`
	Complete               bool  `json:"complete"`
	ActiveDocuments        int64 `json:"active_documents"`
	MissingMatchingMarkers int64 `json:"missing_matching_markers"`
}

type firstInstallDatabaseResult struct {
	Safe                    bool  `json:"safe"`
	Complete                bool  `json:"complete"`
	PublicApplicationTables int64 `json:"public_application_tables"`
}

type firstInstallSchemaResult struct {
	Safe                   bool  `json:"safe"`
	Complete               bool  `json:"complete"`
	EmptyEstateRequired    bool  `json:"empty_estate_required"`
	GooseStateExact        bool  `json:"goose_state_exact"`
	EmbeddedMigrations     int64 `json:"embedded_migrations"`
	AppliedMigrations      int64 `json:"applied_migrations"`
	StaticSeedExact        bool  `json:"static_seed_exact"`
	NonemptyBusinessTables int64 `json:"nonempty_business_tables"`
	LifecycleIntents       int64 `json:"lifecycle_intents"`
}

const lawfulBasisCutoverArg = "--lawful-basis-cutover"
const article13CutoverArg = "--article13-cutover"
const firstInstallDatabaseArg = "--first-install-database"
const firstInstallSchemaArg = "--first-install-schema-applied"
const firstInstallCandidateArg = "--first-install-candidate-estate"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := os.Getenv("HASH_DB_URL")
	if dsn == "" {
		_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: HASH_DB_URL is required")
		os.Exit(2)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: database configuration is invalid")
		os.Exit(2)
	}
	defer pool.Close()
	if len(os.Args) == 2 && os.Args[1] == article13CutoverArg {
		result, verifyErr := verifyArticle13CutoverBoundary(ctx, pool)
		if verifyErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: Article 13 cutover inventory could not be verified")
			os.Exit(2)
		}
		encodeResult(result)
		if !result.Safe || !result.Complete {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == lawfulBasisCutoverArg {
		result, verifyErr := verifyLawfulBasisCutoverBoundary(ctx, pool)
		if verifyErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: lawful-basis cutover inventory could not be verified")
			os.Exit(2)
		}
		encodeResult(result)
		if !result.Safe || !result.Complete {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == firstInstallDatabaseArg {
		result, verifyErr := verifyFirstInstallDatabase(ctx, pool)
		if verifyErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: first-install database state could not be verified")
			os.Exit(2)
		}
		encodeResult(result)
		if !result.Safe || !result.Complete {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && (os.Args[1] == firstInstallSchemaArg || os.Args[1] == firstInstallCandidateArg) {
		requireEmptyEstate := os.Args[1] == firstInstallSchemaArg
		result, verifyErr := verifyFirstInstallSchema(ctx, pool, os.Args[2], requireEmptyEstate)
		if verifyErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: first-install schema state could not be verified")
			os.Exit(2)
		}
		encodeResult(result)
		if !result.Safe || !result.Complete {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: unsupported mode")
		os.Exit(2)
	}
	result, err := verifyRollbackBoundary(ctx, pool)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: rollback boundary could not be verified")
		os.Exit(2)
	}
	encodeResult(result)
	if !result.Safe || !result.Complete {
		os.Exit(1)
	}
}

// verifyFirstInstallDatabase accepts only a genuinely unused Hash database:
// no ordinary/partitioned table exists in public, including neither documents
// nor Goose's migration ledger. A containerless recovery estate is therefore
// never mistaken for a first installation merely because no image is running.
func verifyFirstInstallDatabase(ctx context.Context, db rollbackQuerier) (firstInstallDatabaseResult, error) {
	var result firstInstallDatabaseResult
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const query = `
SELECT count(*)::bigint
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p')`
	if err := tx.QueryRow(ctx, query).Scan(&result.PublicApplicationTables); err != nil { //nolint:rawsql -- release-only catalog inventory
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	result.Safe = result.PublicApplicationTables == 0
	return result, nil
}

// verifyFirstInstallSchema is the resumable half of the one-time production
// bootstrap contract. Goose must record precisely the migrations embedded in
// this exact image and that tree must match the release-manifest digest. Before
// first candidate startup, every application table must also remain empty
// except the migration ledger and three billing-plan seeds. After the durable
// exact-candidate-cutover phase, requireEmptyEstate is false: legitimate rows
// are preserved and the deployment re-runs its lawful-basis and audit gates
// before restarting the same exact lifecycle contract.
func verifyFirstInstallSchema(ctx context.Context, db rollbackQuerier, expectedDigest string, requireEmptyEstate bool) (firstInstallSchemaResult, error) {
	result := firstInstallSchemaResult{EmptyEstateRequired: requireEmptyEstate}
	if len(expectedDigest) != 64 {
		return result, fmt.Errorf("invalid expected migration digest")
	}
	if _, err := hex.DecodeString(expectedDigest); err != nil || expectedDigest != strings.ToLower(expectedDigest) {
		return result, fmt.Errorf("invalid expected migration digest")
	}
	embeddedDigest, embeddedVersions, err := hashdb.EmbeddedMigrationsIdentity()
	if err != nil {
		return result, err
	}
	if embeddedDigest != expectedDigest {
		return result, fmt.Errorf("embedded migrations do not match the approved release")
	}
	result.EmbeddedMigrations = int64(len(embeddedVersions))

	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Goose is an append-only event ledger. Compare the latest event for every
	// positive version with the complete embedded version set; checking MAX()
	// alone would accept a missing or rolled-back intermediate migration.
	const gooseQuery = `
SELECT version_id, is_applied
FROM (
    SELECT DISTINCT ON (version_id) version_id, is_applied, id
    FROM goose_db_version
    WHERE version_id > 0
    ORDER BY version_id, id DESC
) latest
ORDER BY version_id`
	rows, err := tx.Query(ctx, gooseQuery) //nolint:rawsql -- release-only Goose ledger inventory
	if err != nil {
		return result, err
	}
	var appliedVersions []int64
	allApplied := true
	for rows.Next() {
		var version int64
		var applied bool
		if err := rows.Scan(&version, &applied); err != nil {
			rows.Close()
			return result, err
		}
		if !applied {
			allApplied = false
		}
		appliedVersions = append(appliedVersions, version)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	result.AppliedMigrations = int64(len(appliedVersions))
	result.GooseStateExact = allApplied && equalMigrationVersions(appliedVersions, embeddedVersions)

	const tablesQuery = `
SELECT c.relname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p')
  AND c.relname NOT IN ('goose_db_version', 'billing_plans')
ORDER BY c.relname`
	tableRows, err := tx.Query(ctx, tablesQuery) //nolint:rawsql -- release-only catalog inventory
	if err != nil {
		return result, err
	}
	var tableNames []string
	for tableRows.Next() {
		var tableName string
		if err := tableRows.Scan(&tableName); err != nil {
			tableRows.Close()
			return result, err
		}
		tableNames = append(tableNames, tableName)
	}
	if err := tableRows.Err(); err != nil {
		tableRows.Close()
		return result, err
	}
	tableRows.Close()
	for _, tableName := range tableNames {
		query := "SELECT EXISTS (SELECT 1 FROM " + pgx.Identifier{"public", tableName}.Sanitize() + " LIMIT 1)"
		var nonempty bool
		if err := tx.QueryRow(ctx, query).Scan(&nonempty); err != nil { //nolint:rawsql -- identifier is pgx-quoted catalog output
			return result, err
		}
		if nonempty {
			result.NonemptyBusinessTables++
		}
	}

	const seedQuery = `
SELECT count(*) = 3
   AND count(*) FILTER (WHERE slug IN ('free', 'pro', 'enterprise')) = 3
FROM billing_plans`
	if err := tx.QueryRow(ctx, seedQuery).Scan(&result.StaticSeedExact); err != nil { //nolint:rawsql -- release-only seed inventory
		return result, err
	}
	const intentsQuery = `
SELECT (SELECT count(*)::bigint FROM send_sealing_intents)
     + (SELECT count(*)::bigint FROM document_finalization_intents)`
	if err := tx.QueryRow(ctx, intentsQuery).Scan(&result.LifecycleIntents); err != nil { //nolint:rawsql -- release-only lifecycle inventory
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	result.Safe = firstInstallSchemaSafe(result, requireEmptyEstate)
	return result, nil
}

func firstInstallSchemaSafe(result firstInstallSchemaResult, requireEmptyEstate bool) bool {
	return result.GooseStateExact && result.StaticSeedExact &&
		(!requireEmptyEstate || (result.NonemptyBusinessTables == 0 && result.LifecycleIntents == 0))
}

func equalMigrationVersions(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func encodeResult(result any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "rollbackcheck: encode result")
		os.Exit(2)
	}
}

type rollbackQuerier interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func verifyRollbackBoundary(ctx context.Context, db rollbackQuerier) (rollbackResult, error) {
	var result rollbackResult
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const query = `
SELECT (SELECT count(*)::bigint FROM documents WHERE status = 'sealing'),
       (SELECT count(*)::bigint FROM send_sealing_intents),
       (SELECT count(*)::bigint FROM documents WHERE status = 'finalizing'),
       (SELECT count(*)::bigint FROM document_finalization_intents)`
	if err := tx.QueryRow(ctx, query).Scan(
		&result.SealingDocuments,
		&result.SendIntents,
		&result.FinalizingDocuments,
		&result.FinalizationIntents,
	); err != nil { //nolint:rawsql -- release-only read from one snapshot
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	result.Safe = result.SealingDocuments == 0 && result.SendIntents == 0 &&
		result.FinalizingDocuments == 0 && result.FinalizationIntents == 0
	return result, nil
}

// verifyLawfulBasisCutoverBoundary inventories every non-terminal ceremony
// that a server, signer, sealing worker, or finalization worker can continue.
// It is deliberately read-only: a documents.lawful_basis value inherited from
// the historic database default is not evidence of a controller instruction
// and must never be converted into a confirmation by deployment automation.
func verifyLawfulBasisCutoverBoundary(ctx context.Context, db rollbackQuerier) (lawfulBasisCutoverResult, error) {
	var result lawfulBasisCutoverResult
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const query = `
SELECT count(*)::bigint,
       count(*) FILTER (
           WHERE c.document_id IS NULL
              OR c.org_id IS DISTINCT FROM d.org_id
              OR c.lawful_basis IS DISTINCT FROM d.lawful_basis
       )::bigint
FROM documents d
LEFT JOIN document_lawful_basis_confirmations c ON c.document_id = d.id
WHERE d.deleted_at IS NULL
	AND d.parent_envelope_id IS NULL
	AND d.status IN ('sealing','sent','in_progress','finalizing','changes_requested')`
	if err := tx.QueryRow(ctx, query).Scan(
		&result.ActiveDocuments,
		&result.MissingMatchingConfirmations,
	); err != nil { //nolint:rawsql -- release-only inventory from one read-only snapshot
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	result.Safe = result.MissingMatchingConfirmations == 0
	return result, nil
}

// verifyArticle13CutoverBoundary independently re-runs migration 00061's
// active-ceremony assertion after migrations and before candidate writers are
// allowed to start. Every envelope child is checked independently because each
// child has its own document.sent marker and evidence stream.
func verifyArticle13CutoverBoundary(ctx context.Context, db rollbackQuerier) (article13CutoverResult, error) {
	var result article13CutoverResult
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const query = `
SELECT count(*)::bigint,
       count(*) FILTER (
           WHERE d.sent_at IS NULL
              OR d.article13_notice_epoch_at IS DISTINCT FROM d.sent_at
              OR d.article13_notice_schema = ''
              OR marker.payload_json IS NULL
              OR marker.recipient_id IS NOT NULL
              OR octet_length(marker.row_hash) IS DISTINCT FROM 32
              OR NOT hash_article13_marker_matches(
                    marker.payload_json,
                    marker.payload_hashed,
                    d.article13_notice_schema,
                    d.sent_at
                 )
       )::bigint
FROM documents d
LEFT JOIN LATERAL (
    SELECT e.payload_json, e.payload_hashed, e.row_hash, e.recipient_id
    FROM events e
    WHERE e.document_id = d.id
      AND e.org_id = d.org_id
      AND e.kind = 'document.sent'
    ORDER BY e.created_at DESC, e.id DESC
    LIMIT 1
) marker ON TRUE
WHERE d.deleted_at IS NULL
  AND d.status IN ('sent','in_progress','changes_requested')`
	if err := tx.QueryRow(ctx, query).Scan(&result.ActiveDocuments, &result.MissingMatchingMarkers); err != nil { //nolint:rawsql -- release-only active ceremony inventory
		return result, err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	result.Safe = result.MissingMatchingMarkers == 0
	return result, nil
}
