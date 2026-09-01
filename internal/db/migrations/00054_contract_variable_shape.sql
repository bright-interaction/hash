-- +goose Up
-- Contract variables have one lossless representation throughout authoring,
-- resolution, signing, and evidence: an object whose keys are supported
-- variable names and whose values are strings. Numeric JSON values cannot be
-- repaired safely here because their authored lexical form may already have
-- been lost; inventory them and abort so the controller can remediate them
-- explicitly before cutover.

-- The original templates default was an empty array. Its only possible
-- meaning is "no variables", so this exact legacy value can be normalized
-- without inventing contractual content. Apply the same safe normalization to
-- documents/versions in case an old import copied that default downstream.
UPDATE templates
SET variables_json = '{}'::jsonb
WHERE variables_json = '[]'::jsonb;

UPDATE documents
SET variables_json = '{}'::jsonb
WHERE variables_json = '[]'::jsonb;

UPDATE document_versions
SET variables_json = '{}'::jsonb
WHERE variables_json = '[]'::jsonb;

ALTER TABLE templates
    ALTER COLUMN variables_json SET DEFAULT '{}'::jsonb;

-- +goose StatementBegin
CREATE FUNCTION hash_contract_variables_valid(candidate JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
STRICT
AS $$
    SELECT CASE
        WHEN jsonb_typeof(candidate) <> 'object' THEN FALSE
        ELSE NOT EXISTS (
            SELECT 1
            FROM jsonb_each(candidate) AS entry(key, value)
            WHERE entry.key !~ '^[A-Za-z_][A-Za-z0-9_.]*$'
               OR jsonb_typeof(entry.value) <> 'string'
        )
    END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM templates WHERE NOT hash_contract_variables_valid(variables_json)) THEN
        RAISE EXCEPTION 'contract variable cutover requires explicit remediation of invalid template variables_json rows';
    END IF;
    IF EXISTS (SELECT 1 FROM documents WHERE NOT hash_contract_variables_valid(variables_json)) THEN
        RAISE EXCEPTION 'contract variable cutover requires explicit remediation of invalid document variables_json rows';
    END IF;
    IF EXISTS (SELECT 1 FROM document_versions WHERE NOT hash_contract_variables_valid(variables_json)) THEN
        RAISE EXCEPTION 'contract variable cutover requires explicit remediation of invalid document-version variables_json rows';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE templates
    ADD CONSTRAINT templates_contract_variables_shape
    CHECK (hash_contract_variables_valid(variables_json));

ALTER TABLE documents
    ADD CONSTRAINT documents_contract_variables_shape
    CHECK (hash_contract_variables_valid(variables_json));

ALTER TABLE document_versions
    ADD CONSTRAINT document_versions_contract_variables_shape
    CHECK (hash_contract_variables_valid(variables_json));

-- +goose Down
ALTER TABLE document_versions DROP CONSTRAINT IF EXISTS document_versions_contract_variables_shape;
ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_contract_variables_shape;
ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_contract_variables_shape;
DROP FUNCTION IF EXISTS hash_contract_variables_valid(JSONB);
ALTER TABLE templates ALTER COLUMN variables_json SET DEFAULT '[]'::jsonb;
