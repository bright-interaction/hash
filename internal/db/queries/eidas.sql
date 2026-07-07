-- name: InsertEIDASRule :one
INSERT INTO eidas_routing_rules (
    org_id, name, priority, predicate_json, required_tier, reason, active
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: UpdateEIDASRule :one
UPDATE eidas_routing_rules
   SET name          = $3,
       priority      = $4,
       predicate_json = $5,
       required_tier = $6,
       reason        = $7,
       active        = $8,
       updated_at    = now()
 WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteEIDASRule :exec
DELETE FROM eidas_routing_rules WHERE id = $1 AND org_id = $2;

-- name: GetEIDASRule :one
SELECT * FROM eidas_routing_rules WHERE id = $1 AND org_id = $2;

-- name: ListEIDASRules :many
SELECT * FROM eidas_routing_rules
WHERE org_id = $1
ORDER BY active DESC, priority ASC, created_at ASC;

-- name: ListActiveEIDASRules :many
SELECT * FROM eidas_routing_rules
WHERE org_id = $1 AND active = TRUE
ORDER BY priority ASC, created_at ASC;

-- name: SetDocumentRoutingTier :exec
UPDATE documents
   SET routing_tier = $3,
       updated_at   = now()
 WHERE id = $1 AND org_id = $2;
