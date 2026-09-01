-- +goose Up
-- Block documents support named parties such as client/provider. Keep the
-- reserved routing roles (cc/viewer) while allowing a bounded canonical role
-- alphabet that both authoring and lifecycle code validate identically.
ALTER TABLE recipients DROP CONSTRAINT recipients_role_check;
ALTER TABLE recipients ADD CONSTRAINT recipients_role_check
    CHECK (role ~ '^[a-z][a-z0-9_-]{0,63}$');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM recipients
        WHERE role NOT IN ('signer','approver','cc','viewer')
    ) THEN
        RAISE EXCEPTION 'cannot roll back custom recipient roles while custom-role recipients exist';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE recipients DROP CONSTRAINT recipients_role_check;
ALTER TABLE recipients ADD CONSTRAINT recipients_role_check
    CHECK (role IN ('signer','approver','cc','viewer'));
