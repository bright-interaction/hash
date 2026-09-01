-- +goose Up

-- OIDC email claims are case-insensitive identifiers in Hash. Enforce the same
-- invariant under concurrent first-login provisioning. If an upgraded database
-- contains case-only duplicates this intentionally fails the release migration
-- so an operator can resolve account ownership rather than auto-merge tenants.
CREATE UNIQUE INDEX users_email_casefold_unique_idx ON users (lower(email));

-- +goose Down
DROP INDEX IF EXISTS users_email_casefold_unique_idx;
