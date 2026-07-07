-- +goose Up
-- Store the EXACT bytes that row_hash commits to, in a BYTEA column, so
-- chain verification is immune to JSONB key-order/whitespace normalization
-- on read-back. The old code hashed Go json.Marshal bytes but stored them in
-- a JSONB column; Postgres re-serializes JSONB on read, so the verifier
-- recomputed over different bytes and reported FALSE TAMPERING on every
-- payload-bearing row. BYTEA round-trips byte-exactly, removing JSONB from
-- the hashing path entirely. Purely additive: payload_json stays for the
-- timeline UI; existing rows keep NULL payload_hashed and are reported as
-- "legacy / pre-canonical" by the verifier rather than as tampered.
ALTER TABLE events ADD COLUMN payload_hashed BYTEA;

-- +goose Down
ALTER TABLE events DROP COLUMN payload_hashed;
