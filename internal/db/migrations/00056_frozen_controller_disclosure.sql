-- +goose Up
-- Article 13 controller identity must describe the controller at the time the
-- ceremony was sent. Reading the current organization name later is mutable,
-- and the platform operator's privacy address is not the controller contact.
--
-- Migrations 00052..00056 ship as one release and application processes only
-- start after every migration succeeds. A non-empty confirmation table here
-- therefore means an intermediate/partial release wrote legal instructions
-- without the disclosure snapshot; inventing that historical identity would
-- be unsafe, so require explicit operator remediation instead.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM document_lawful_basis_confirmations) THEN
        RAISE EXCEPTION 'controller-disclosure cutover requires explicit remediation of pre-snapshot lawful-basis confirmations';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE document_lawful_basis_confirmations
    ADD COLUMN controller_name TEXT NOT NULL
        CHECK (btrim(controller_name) <> ''),
    ADD COLUMN controller_contact TEXT NOT NULL
        CHECK (btrim(controller_contact) <> '');

-- Hash currently has evidence to support only the contract/requested
-- pre-contractual-steps workflow. Other Article 6 bases need basis-specific
-- product evidence (for example consent withdrawal or a legitimate-interest
-- assessment) before the UI may represent that they apply.
ALTER TABLE document_lawful_basis_confirmations
    DROP CONSTRAINT document_lawful_basis_confirmations_lawful_basis_check,
    ADD CONSTRAINT document_lawful_basis_confirmations_lawful_basis_check
        CHECK (lawful_basis = 'contract');

-- +goose Down
ALTER TABLE document_lawful_basis_confirmations
    DROP CONSTRAINT document_lawful_basis_confirmations_lawful_basis_check,
    ADD CONSTRAINT document_lawful_basis_confirmations_lawful_basis_check
        CHECK (lawful_basis IN ('contract','legal_obligation','vital_interests','public_task','legitimate_interests','consent')),
    DROP COLUMN controller_contact,
    DROP COLUMN controller_name;
