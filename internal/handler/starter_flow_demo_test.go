// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build demo

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// TestStarterAndDocFromTemplate exercises the non-developer path over real HTTP
// handlers + the live DB: seed the built-in services-agreement starter as a
// template, then create a document from it and confirm the template content
// (clauses + both tables) was actually copied into the new document. This guards
// the two gaps fixed this round: document-from-template used to seed an empty
// doc, and there was no way to get the starter into a tenant's library.
//
//	HASH_E2E_DB_URL=... go test -tags demo ./internal/handler/ -run TestStarterAndDocFromTemplate -v
func TestStarterAndDocFromTemplate(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(migConn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	_ = migConn.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	q := generated.New(pool)
	srv := &Server{Queries: q, Audit: audit.New(q, pool)}

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Starter Test AB", Plan: "pro"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@demo.example", Name: "Tester", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatalf("user: %v", err)
	}

	authCtx := context.WithValue(ctx, auth.UserIDKey, user.ID)
	authCtx = context.WithValue(authCtx, auth.OrgIDKey, org.ID)
	authCtx = context.WithValue(authCtx, auth.RoleKey, "owner")
	authCtx = context.WithValue(authCtx, auth.EmailKey, user.Email)

	// 1. Seed the starter as a template.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/starter", strings.NewReader(`{"key":"services-agreement-sv"}`)).WithContext(authCtx)
	req.Header.Set("Content-Type", "application/json")
	srv.handleCreateStarterTemplate(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed starter: got %d, body %s", rr.Code, rr.Body.String())
	}
	var tpl struct {
		ID         string `json:"id"`
		SourceKind string `json:"source_kind"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &tpl); err != nil {
		t.Fatalf("decode template: %v", err)
	}
	if tpl.SourceKind != "blocks" || tpl.ID == "" {
		t.Fatalf("unexpected template: %+v", tpl)
	}

	// 2. Create a document from that template (omit blocks/vars; server copies).
	rr2 := httptest.NewRecorder()
	body := `{"name":"Avtal X","source_kind":"blocks","template_id":"` + tpl.ID + `"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/documents", strings.NewReader(body)).WithContext(authCtx)
	req2.Header.Set("Content-Type", "application/json")
	srv.handleCreateDocument(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("create doc: got %d, body %s", rr2.Code, rr2.Body.String())
	}
	docBody := rr2.Body.String()

	// The template content must have been copied: two tables + a clause + the
	// variable defaults (price), not an empty document.
	tableCount := strings.Count(docBody, `"type":"table"`)
	if tableCount < 2 {
		t.Fatalf("expected the template's tables copied into the document, got %d\nbody: %s", tableCount, docBody[:min(len(docBody), 400)])
	}
	for _, want := range []string{"Ansvarsbegr", `"price"`, "Bilaga 1", "signature_field"} {
		if !strings.Contains(docBody, want) {
			t.Fatalf("document missing copied content %q", want)
		}
	}
	t.Logf("starter -> template -> document OK: %d tables, clauses + variables copied", tableCount)
}
