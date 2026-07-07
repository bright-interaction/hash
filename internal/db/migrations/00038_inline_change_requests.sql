-- +goose Up
-- Inline change requests: a signer marks a span of text and proposes a change,
-- anchored to its block. The sender approves or denies each one. The org-level
-- change_approval_mode decides what approve does: 'accept' records acceptance
-- for the sender to apply during Revise; 'auto_apply' replaces the marked text
-- with the proposed text immediately.
ALTER TABLE orgs ADD COLUMN change_approval_mode TEXT NOT NULL DEFAULT 'accept'
    CHECK (change_approval_mode IN ('accept','auto_apply'));

ALTER TABLE change_requests ADD COLUMN block_id TEXT NOT NULL DEFAULT '';
ALTER TABLE change_requests ADD COLUMN quote TEXT NOT NULL DEFAULT '';
ALTER TABLE change_requests ADD COLUMN context TEXT NOT NULL DEFAULT '';
ALTER TABLE change_requests ADD COLUMN proposed TEXT NOT NULL DEFAULT '';
ALTER TABLE change_requests ADD COLUMN resolution TEXT;
ALTER TABLE change_requests ADD CONSTRAINT change_requests_resolution_check
    CHECK (resolution IS NULL OR resolution IN ('approved','denied'));

-- +goose Down
ALTER TABLE change_requests DROP CONSTRAINT change_requests_resolution_check;
ALTER TABLE change_requests DROP COLUMN resolution;
ALTER TABLE change_requests DROP COLUMN proposed;
ALTER TABLE change_requests DROP COLUMN context;
ALTER TABLE change_requests DROP COLUMN quote;
ALTER TABLE change_requests DROP COLUMN block_id;
ALTER TABLE orgs DROP COLUMN change_approval_mode;
