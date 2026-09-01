-- name: ConfirmDocumentLawfulBasis :one
WITH controller AS (
    SELECT o.id AS org_id,
           btrim(o.name) AS controller_name,
           btrim(u.email) AS controller_contact
    FROM orgs o
    JOIN users u
      ON u.id = sqlc.narg(confirmed_by)
     AND u.org_id = o.id
    WHERE o.id = sqlc.arg(org_id)
      AND btrim(o.name) <> ''
      AND btrim(u.email) <> ''
), updated AS (
    UPDATE documents d
    SET lawful_basis = sqlc.arg(lawful_basis),
        updated_at = now()
    FROM controller c
    WHERE d.id = sqlc.arg(document_id)
      AND d.org_id = c.org_id
      AND d.status = 'draft'
      AND d.deleted_at IS NULL
    RETURNING d.id, d.org_id, d.lawful_basis,
              c.controller_name, c.controller_contact
)
INSERT INTO document_lawful_basis_confirmations (
    document_id, org_id, lawful_basis, confirmed_by, via,
    controller_name, controller_contact
)
SELECT id, org_id, lawful_basis, sqlc.narg(confirmed_by), sqlc.arg(via),
       controller_name, controller_contact
FROM updated
ON CONFLICT (document_id) DO UPDATE
SET lawful_basis = EXCLUDED.lawful_basis,
    confirmed_at = now(),
    confirmed_by = EXCLUDED.confirmed_by,
    via = EXCLUDED.via,
    controller_name = EXCLUDED.controller_name,
    controller_contact = EXCLUDED.controller_contact
WHERE document_lawful_basis_confirmations.org_id = EXCLUDED.org_id
RETURNING *;

-- name: GetDocumentLawfulBasisConfirmation :one
SELECT c.*
FROM document_lawful_basis_confirmations c
JOIN documents d ON d.id = c.document_id AND d.org_id = c.org_id
WHERE c.document_id = $1 AND c.org_id = $2 AND d.deleted_at IS NULL;
