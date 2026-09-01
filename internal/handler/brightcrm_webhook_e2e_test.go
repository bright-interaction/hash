// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
)

type brightCRME2ESource struct {
	calls int
}

func TestBrightCRMWebhookRollsBackEveryTenantAndReceiptWhenLaterAuditFails(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)

	sourceRef := "deal-atomic-" + uuid.NewString()
	orgIDs := make([]uuid.UUID, 0, 2)
	docs := make([]*generated.Document, 0, 2)
	for i := 0; i < 2; i++ {
		org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Atomic CRM " + uuid.NewString(), Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		user, err := q.CreateUser(ctx, generated.CreateUserParams{
			OrgID: org.ID, Email: uuid.NewString() + "@brightcrm-atomic.test", Name: "Owner", Role: "owner",
			ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID: org.ID, Name: "Atomic CRM draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
			VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{
			DocumentID: doc.ID, VariableName: "amount", SourceKind: string(resolver.SourceCRMDeal),
			SourceRef: sourceRef, SourcePath: "amount", Fallback: "",
		}); err != nil {
			t.Fatal(err)
		}
		orgIDs = append(orgIDs, org.ID)
		docs = append(docs, doc)
	}
	sort.Slice(orgIDs, func(i, j int) bool { return orgIDs[i].String() < orgIDs[j].String() })

	crmSource := &brightCRME2ESource{}
	res := resolver.New(q, crmSource)
	for _, doc := range docs {
		if _, _, err := res.Resolve(ctx, doc, resolver.ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if crmSource.calls != 2 {
		t.Fatalf("initial source fetches = %d, want 2", crmSource.calls)
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	functionName := "hash_test_fail_brightcrm_" + suffix
	triggerName := "hash_test_fail_brightcrm_trigger_" + suffix
	failingOrg := orgIDs[1]
	ddl := fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.kind = 'webhook.received' AND NEW.org_id = '%s'::uuid THEN
				RAISE EXCEPTION 'synthetic later-tenant audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`,
		functionName, failingOrg, triggerName, functionName)
	if _, err := pool.Exec(ctx, ddl); err != nil { //nolint:rawsql // isolated synthetic E2E fault injection
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+triggerName+" ON events") //nolint:rawsql
		_, _ = pool.Exec(context.Background(), "DROP FUNCTION IF EXISTS "+functionName+"()")       //nolint:rawsql
	}()

	secret := "brightcrm-atomic-secret-with-sufficient-entropy"
	deliveryID := "wh_" + suffix
	body := `{"id":"` + deliveryID + `","event":"DEAL_UPDATED","data":{"id":"` + sourceRef + `"}}`
	server := &Server{Queries: q, Pool: pool, Resolver: res, Audit: audit.New(q, pool), BrightCRMWebhookSecret: secret}
	response := postBrightCRM(t, server, body, currentBrightCRMSignature(secret, body))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("partial audit failure status = %d, want 503: %s", response.Code, response.Body.String())
	}
	for i, orgID := range orgIDs {
		events, err := q.ListRecentEventsByOrg(ctx, generated.ListRecentEventsByOrgParams{OrgID: orgID, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 0 {
			t.Fatalf("org %d retained %d partial audit rows after rollback", i, len(events))
		}
	}
	deliveryCorrelation := brightCRMAuditCorrelation(secret, "delivery-id", []byte(deliveryID))
	var receiptCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM brightcrm_webhook_receipts WHERE delivery_correlation = $1`, deliveryCorrelation).Scan(&receiptCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if receiptCount != 0 {
		t.Fatalf("failed atomic delivery retained %d receipt rows", receiptCount)
	}
	for _, doc := range docs {
		if _, _, err := res.Resolve(ctx, doc, resolver.ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if crmSource.calls != 2 {
		t.Fatalf("failed transaction invalidated cache; source calls = %d, want 2", crmSource.calls)
	}
}

func (*brightCRME2ESource) Kind() resolver.SourceKind { return resolver.SourceCRMDeal }

func (s *brightCRME2ESource) Fetch(_ context.Context, ref resolver.Ref) (string, error) {
	s.calls++
	return "value-for-" + ref.Source, nil
}

func TestBrightCRMWebhookAuditsEveryAffectedTenantBeforeInvalidation(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	sourceRef := "deal-sensitive-" + uuid.NewString()
	docs := make([]*generated.Document, 0, 2)
	orgIDs := make([]uuid.UUID, 0, 2)
	for i := 0; i < 2; i++ {
		org, err := q.CreateOrg(ctx, generated.CreateOrgParams{
			Name: "BrightCRM inbound audit " + uuid.NewString(), Plan: "pro",
		})
		if err != nil {
			t.Fatal(err)
		}
		user, err := q.CreateUser(ctx, generated.CreateUserParams{
			OrgID: org.ID, Email: uuid.NewString() + "@brightcrm-audit.test",
			Name: "Webhook Owner", Role: "owner",
			ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID: org.ID, Name: "CRM-backed draft",
			BlocksJson:    json.RawMessage(`{"version":1,"blocks":[]}`),
			VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{
			DocumentID: doc.ID, VariableName: "deal_amount", SourceKind: string(resolver.SourceCRMDeal),
			SourceRef: sourceRef, SourcePath: "amount", Fallback: "",
		}); err != nil {
			t.Fatal(err)
		}
		docs = append(docs, doc)
		orgIDs = append(orgIDs, org.ID)
	}
	planTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = planTx.Rollback(context.Background()) }()
	if _, err := planTx.Exec(ctx, "SET LOCAL enable_seqscan = off"); err != nil { //nolint:rawsql // force index visibility in the contract test
		t.Fatal(err)
	}
	planRows, err := planTx.Query(ctx, `EXPLAIN (FORMAT TEXT)
		SELECT DISTINCT d.org_id
		FROM document_variable_bindings AS b
		JOIN documents AS d ON d.id = b.document_id
		WHERE b.source_kind = $1 AND b.source_ref = $2
		  AND d.status = 'draft' AND d.deleted_at IS NULL
		ORDER BY d.org_id`, string(resolver.SourceCRMDeal), sourceRef) //nolint:rawsql
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for planRows.Next() {
		var line string
		if err := planRows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := planRows.Err(); err != nil {
		t.Fatal(err)
	}
	planRows.Close()
	if !strings.Contains(plan.String(), "idx_var_bindings_source_lookup") {
		t.Fatalf("BrightCRM source lookup does not use its composite index:\n%s", plan.String())
	}
	if err := planTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	crmSource := &brightCRME2ESource{}
	res := resolver.New(q, crmSource)
	for _, doc := range docs {
		if _, _, err := res.Resolve(ctx, doc, resolver.ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if crmSource.calls != 2 {
		t.Fatalf("initial source fetches = %d, want 2", crmSource.calls)
	}

	secret := "brightcrm-e2e-secret-with-sufficient-entropy"
	server := &Server{
		Queries: q, Pool: pool, Resolver: res, Audit: audit.New(q, pool),
		BrightCRMWebhookSecret: secret, PublicURL: "https://hash.test",
	}
	deliveryID := "wh_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	body := `{"id":"` + deliveryID + `","event":"DEAL_UPDATED","data":{"id":"` + sourceRef + `"}}`
	header := currentBrightCRMSignature(secret, body)
	response := postBrightCRM(t, server, body, header)
	if response.Code != 200 {
		t.Fatalf("webhook status = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"invalidated_count":2`) {
		t.Fatalf("webhook did not invalidate both tenant cache entries: %s", response.Body.String())
	}

	for i, orgID := range orgIDs {
		events, err := q.ListRecentEventsByOrg(ctx, generated.ListRecentEventsByOrgParams{OrgID: orgID, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Kind != audit.KindWebhookReceived {
			t.Fatalf("org %d inbound audit events = %#v", i, events)
		}
		payload := string(events[0].PayloadHashed)
		if strings.Contains(payload, sourceRef) || !strings.Contains(payload, "source_ref_correlation") ||
			strings.Contains(payload, "source_ref_sha256") {
			t.Fatalf("org %d audit payload leaks source ref or lacks digest: %s", i, payload)
		}
	}

	// Bind a third tenant only after the original event was committed. A retry
	// must use the receipt's audited tenant snapshot, not today's bindings;
	// otherwise this tenant's cache could be mutated without a ledger entry.
	lateOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{
		Name: "Late BrightCRM binding " + uuid.NewString(), Plan: "pro",
	})
	if err != nil {
		t.Fatal(err)
	}
	lateUser, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: lateOrg.ID, Email: uuid.NewString() + "@brightcrm-late.test",
		Name: "Late Owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	lateDoc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: lateOrg.ID, Name: "Late CRM-backed draft",
		BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), SenderID: lateUser.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{
		DocumentID: lateDoc.ID, VariableName: "deal_amount", SourceKind: string(resolver.SourceCRMDeal),
		SourceRef: sourceRef, SourcePath: "amount", Fallback: "",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := res.Resolve(ctx, lateDoc, resolver.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	if crmSource.calls != 3 {
		t.Fatalf("late tenant cache warmup calls = %d, want 3", crmSource.calls)
	}
	docs = append(docs, lateDoc)

	// BrightCRM rebuilds its informational timestamp on retry while preserving
	// the stable id and semantic event/data payload.
	retryBody := `{"id":"` + deliveryID + `","event":"DEAL_UPDATED","timestamp":"2026-08-31T12:00:01Z","data":{"id":"` + sourceRef + `"}}`
	replay := postBrightCRM(t, server, retryBody, currentBrightCRMSignature(secret, retryBody))
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"duplicate":true`) {
		t.Fatalf("stable delivery replay was not acknowledged as duplicate: %d %s", replay.Code, replay.Body.String())
	}
	if !strings.Contains(replay.Body.String(), `"invalidated_count":0`) {
		t.Fatalf("retry invalidated a tenant outside the audited snapshot: %s", replay.Body.String())
	}
	for i, orgID := range orgIDs {
		events, err := q.ListRecentEventsByOrg(ctx, generated.ListRecentEventsByOrgParams{OrgID: orgID, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("org %d replay amplified immutable audit rows to %d", i, len(events))
		}
	}
	lateEvents, err := q.ListRecentEventsByOrg(ctx, generated.ListRecentEventsByOrgParams{OrgID: lateOrg.ID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(lateEvents) != 0 {
		t.Fatalf("late-bound tenant unexpectedly received %d historical audit rows", len(lateEvents))
	}

	for _, doc := range docs {
		if _, _, err := res.Resolve(ctx, doc, resolver.ResolveOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if crmSource.calls != 5 {
		t.Fatalf("source fetches after audited-snapshot retry = %d, want 5", crmSource.calls)
	}
}
