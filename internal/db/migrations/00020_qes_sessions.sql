-- +goose Up

-- v1.1: QES signing sessions. When a document's routing_tier is QES, the
-- signer is redirected to a QTSP (Idura / Signicat / Scrive) to perform
-- a Qualified Electronic Signature under eIDAS Article 26. The QTSP
-- callback carries an identity assertion + a signature certificate
-- chained to a trusted root; we persist the whole assertion here so the
-- audit cert + evidence bundle can reproduce it for forensic review.
--
-- The session is one-shot: created when the signer clicks "Sign with
-- BankID", flipped to completed when the QTSP callback validates, and
-- linked to the signatures row so the existing sign engine can fan-out
-- envelope completion + emit completed_* emails the same way SES/AES
-- documents do.

CREATE TABLE qes_signing_sessions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id              UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id             UUID NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
    org_id                   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider                 TEXT NOT NULL,          -- 'idura' | 'signicat' | 'scrive' | 'mock'
    provider_session_id      TEXT NOT NULL,          -- opaque ID returned by the QTSP
    status                   TEXT NOT NULL DEFAULT 'pending',
                              -- pending | redirected | completed | failed | expired
    redirect_url             TEXT,                   -- where the signer was sent
    callback_secret          TEXT NOT NULL,          -- HMAC secret to verify the QTSP callback
    identity_assertion_json  JSONB,                  -- canonical id+cert chain from the QTSP
    signature_b64            TEXT,                   -- detached signature from the QTSP
    cert_chain_pem           TEXT,                   -- X.509 chain that signed the assertion
    failure_reason           TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at             TIMESTAMPTZ,
    expires_at               TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '1 hour')
);

CREATE INDEX idx_qes_sessions_doc ON qes_signing_sessions(document_id);
CREATE INDEX idx_qes_sessions_recipient ON qes_signing_sessions(recipient_id);
CREATE INDEX idx_qes_sessions_provider_session ON qes_signing_sessions(provider, provider_session_id);

-- +goose Down

DROP INDEX idx_qes_sessions_provider_session;
DROP INDEX idx_qes_sessions_recipient;
DROP INDEX idx_qes_sessions_doc;
DROP TABLE qes_signing_sessions;
