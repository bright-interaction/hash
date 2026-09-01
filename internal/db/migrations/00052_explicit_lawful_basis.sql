-- +goose Up
-- A lawful-basis enum default is a software default, not an instruction from
-- the customer/controller. Record explicit confirmation separately so adding
-- this control remains rollback-compatible with an older Hash binary whose
-- generated SELECT * document scanner knows the existing documents shape.
--
-- There is no lawful way to infer a controller's instruction for ceremonies
-- created by an older binary. The deploy workflow must quiesce old writers
-- before migrations; this inventory assertion then refuses the cutover until
-- every pre-control active ceremony has been completed/terminated or handled
-- through an explicit controller remediation procedure.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM documents
        WHERE status IN ('sealing','sent','in_progress','finalizing','changes_requested')
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'explicit lawful-basis cutover requires zero active pre-control ceremonies';
    END IF;
END $$;
-- +goose StatementEnd

CREATE TABLE document_lawful_basis_confirmations (
    document_id UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    lawful_basis TEXT NOT NULL
        CHECK (lawful_basis IN ('contract','legal_obligation','vital_interests','public_task','legitimate_interests','consent')),
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    via TEXT NOT NULL CHECK (via IN ('rest','mcp','worker','test','demo'))
);

CREATE INDEX idx_document_lawful_basis_confirmations_org
    ON document_lawful_basis_confirmations(org_id, confirmed_at DESC);

-- +goose Down
DROP TABLE IF EXISTS document_lawful_basis_confirmations;
