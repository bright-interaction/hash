-- name: InsertProposal :one
INSERT INTO document_proposals (
    document_id, org_id, recipient_id, proposed_by, block_id,
    proposal_kind, proposed_text, rationale, diff_json,
    ai_assisted, parent_id
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11
) RETURNING *;

-- name: ListProposalsByDocument :many
SELECT * FROM document_proposals
WHERE document_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: SetProposalStatus :one
UPDATE document_proposals
   SET status     = $3,
       updated_at = now()
 WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: SetDocumentNegotiationEnabled :exec
UPDATE documents
   SET negotiation_enabled = $3,
       updated_at = now()
 WHERE id = $1 AND org_id = $2;

-- name: SetDocumentBilingualTarget :exec
UPDATE documents
   SET bilingual_target_lang = $3,
       updated_at = now()
 WHERE id = $1 AND org_id = $2;
