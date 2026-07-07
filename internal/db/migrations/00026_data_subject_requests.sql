-- +goose Up
-- GDPR Articles 15-22: data subject rights.
--
-- Signers + senders can request access (Art. 15), rectification (16),
-- erasure (17), restriction (18), portability (20), or objection (21).
-- The privacy policy at /legal/privacy promises these without a wired
-- endpoint; this table + the new /sign/{token}/dsr and /api/v1/dsr
-- routes close that gap.
--
-- Erasure under Art. 17(3)(e) is bounded by legal-retention overrides
-- (signed PDFs must be kept for tax + evidentiary purposes), so the
-- "fulfilled" workflow ANONYMIZES the recipients row (replaces name +
-- email with a redaction marker) rather than deleting the document
-- itself. The signed PDF + audit cert stay intact; the audit trail
-- gets a per-row redaction stamp so the chain of custody remains
-- verifiable.

CREATE TABLE data_subject_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    document_id     UUID REFERENCES documents(id) ON DELETE SET NULL,
    recipient_id    UUID REFERENCES recipients(id) ON DELETE SET NULL,
    subject_email   TEXT NOT NULL,
    subject_name    TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL
                    CHECK (kind IN ('access','rectification','erasure','restriction','portability','objection')),
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','in_progress','fulfilled','denied','withdrawn')),
    requested_via   TEXT NOT NULL DEFAULT 'signer'
                    CHECK (requested_via IN ('signer','sender','dpo','imported')),
    requested_note  TEXT NOT NULL DEFAULT '',
    resolution_note TEXT NOT NULL DEFAULT '',
    fulfilled_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    fulfilled_at    TIMESTAMPTZ,
    due_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '30 days'),
    payload_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_dsr_org_status ON data_subject_requests(org_id, status);
CREATE INDEX idx_dsr_subject_email ON data_subject_requests(lower(subject_email));
CREATE INDEX idx_dsr_due ON data_subject_requests(due_at) WHERE status IN ('open','in_progress');

-- +goose Down
DROP TABLE data_subject_requests;
