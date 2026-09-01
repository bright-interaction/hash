-- +goose Up

-- Feed replays and concurrent worker/manual runs must not create duplicate
-- compliance findings for the same authoritative update and target. Retain the
-- earliest row from upgraded databases before enforcing the invariant.
WITH ranked_document_flags AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY org_id, document_id, update_ref
               ORDER BY CASE status
                            WHEN 'open' THEN 0
                            WHEN 'acknowledged' THEN 1
                            ELSE 2
                        END,
                        raised_at,
                        id
           ) AS duplicate_rank
    FROM compliance_flags
    WHERE document_id IS NOT NULL
)
DELETE FROM compliance_flags f
USING ranked_document_flags ranked
WHERE f.id = ranked.id
  AND ranked.duplicate_rank > 1;

WITH ranked_template_flags AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY org_id, template_id, update_ref
               ORDER BY CASE status
                            WHEN 'open' THEN 0
                            WHEN 'acknowledged' THEN 1
                            ELSE 2
                        END,
                        raised_at,
                        id
           ) AS duplicate_rank
    FROM compliance_flags
    WHERE template_id IS NOT NULL
)
DELETE FROM compliance_flags f
USING ranked_template_flags ranked
WHERE f.id = ranked.id
  AND ranked.duplicate_rank > 1;

CREATE UNIQUE INDEX compliance_flags_document_update_unique_idx
    ON compliance_flags(org_id, document_id, update_ref)
    WHERE document_id IS NOT NULL;

CREATE UNIQUE INDEX compliance_flags_template_update_unique_idx
    ON compliance_flags(org_id, template_id, update_ref)
    WHERE template_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS compliance_flags_template_update_unique_idx;
DROP INDEX IF EXISTS compliance_flags_document_update_unique_idx;
