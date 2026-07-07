-- +goose Up
-- Stop the soft-delete purge worker from snapping the org audit hash chain.
-- events.document_id was ON DELETE CASCADE, so hard-deleting a purged
-- document removed its interior events rows and broke every downstream
-- prev_hash link in that org's chain, also destroying legally-retained (7y)
-- audit records. Switch to ON DELETE SET NULL so the events row (org_id,
-- kind, payload, prev_hash, row_hash) survives a document purge and the
-- chain stays verifiable. Matches the existing SET NULL pattern on
-- ai_completion_audit / compliance_meta / data_subject_requests doc refs.
ALTER TABLE events DROP CONSTRAINT events_document_id_fkey;
ALTER TABLE events
    ADD CONSTRAINT events_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE events DROP CONSTRAINT events_document_id_fkey;
ALTER TABLE events
    ADD CONSTRAINT events_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE;
