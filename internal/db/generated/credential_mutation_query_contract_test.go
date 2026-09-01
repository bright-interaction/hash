// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestCredentialAndWebhookDeletesReturnExactRowIdentity(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		binding string
	}{
		{name: "api key", query: deleteAPIKey, binding: "user_id = $2"},
		{name: "webhook", query: deleteWebhookEndpoint, binding: "org_id = $2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := strings.ToLower(tt.query)
			if !strings.Contains(query, "delete from") || !strings.Contains(query, strings.ToLower(tt.binding)) {
				t.Fatalf("delete query does not preserve its ownership binding:\n%s", tt.query)
			}
			if !strings.Contains(query, "returning id") {
				t.Fatalf("delete query must return the deleted row id so a missing id becomes pgx.ErrNoRows:\n%s", tt.query)
			}
		})
	}
}

func TestAPIKeyClaimRechecksExpiryAfterSecretVerification(t *testing.T) {
	raw, err := os.ReadFile("../queries/orgs.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"-- name: claimapikeyuse :one",
		"update api_keys",
		"expires_at is null or expires_at > now()",
		"returning id",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("org API-key claim is missing %q", required)
		}
	}
}

func TestOIDCEmailAdoptionUsesCasefoldedUniqueIdentityAndOneWaySubjectBinding(t *testing.T) {
	orgQueries, err := os.ReadFile("../queries/orgs.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../migrations/00051_casefold_user_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	queries := strings.ToLower(string(orgQueries))
	for _, required := range []string{
		"where lower(email) = lower($1)",
		"-- name: binduserzitadelsub :one",
		"zitadel_sub is null or zitadel_sub = $2",
		"returning *",
	} {
		if !strings.Contains(queries, required) {
			t.Fatalf("OIDC identity query contract is missing %q", required)
		}
	}
	if !strings.Contains(strings.ToLower(string(migration)), "unique index users_email_casefold_unique_idx on users (lower(email))") {
		t.Fatal("OIDC identity migration must enforce case-insensitive email uniqueness")
	}
}
