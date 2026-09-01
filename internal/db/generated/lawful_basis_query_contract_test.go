// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestLawfulBasisConfirmationIsExplicitDraftGuardedAndRollbackCompatible(t *testing.T) {
	query := strings.ToLower(confirmDocumentLawfulBasis)
	for _, required := range []string{
		"update documents",
		"d.status = 'draft'",
		"d.deleted_at is null",
		"join users u",
		"u.org_id = o.id",
		"controller_name",
		"controller_contact",
		"insert into document_lawful_basis_confirmations",
		"on conflict (document_id) do update",
		"returning",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("lawful-basis confirmation query is missing %q:\n%s", required, confirmDocumentLawfulBasis)
		}
	}

	migration, err := os.ReadFile("../migrations/00052_explicit_lawful_basis.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(migration))
	if !strings.Contains(sql, "create table document_lawful_basis_confirmations") {
		t.Fatal("lawful-basis migration must persist explicit controller confirmation separately")
	}
	if strings.Contains(sql, "alter table documents") || strings.Contains(sql, "lawful_basis_confirmed_at") {
		t.Fatal("lawful-basis migration must not change the documents row shape used by the rollback binary")
	}
	snapshotMigration, err := os.ReadFile("../migrations/00056_frozen_controller_disclosure.sql")
	if err != nil {
		t.Fatal(err)
	}
	snapshotSQL := strings.ToLower(string(snapshotMigration))
	for _, required := range []string{"add column controller_name", "add column controller_contact", "check (lawful_basis = 'contract')"} {
		if !strings.Contains(snapshotSQL, required) {
			t.Fatalf("controller snapshot migration is missing %q", required)
		}
	}
}

func TestLawfulBasisLookupBindsConfirmationToLiveDocumentAndOrganization(t *testing.T) {
	query := strings.ToLower(getDocumentLawfulBasisConfirmation)
	for _, required := range []string{
		"join documents d on d.id = c.document_id and d.org_id = c.org_id",
		"c.document_id = $1",
		"c.org_id = $2",
		"d.deleted_at is null",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("lawful-basis lookup is missing %q:\n%s", required, getDocumentLawfulBasisConfirmation)
		}
	}
}
