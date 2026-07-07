-- name: UpsertVariableBinding :one
INSERT INTO document_variable_bindings (
    document_id, variable_name, source_kind, source_ref, source_path, fallback
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (document_id, variable_name) DO UPDATE SET
    source_kind = EXCLUDED.source_kind,
    source_ref  = EXCLUDED.source_ref,
    source_path = EXCLUDED.source_path,
    fallback    = EXCLUDED.fallback,
    updated_at  = now()
RETURNING *;

-- name: ListVariableBindings :many
SELECT * FROM document_variable_bindings
WHERE document_id = $1
ORDER BY variable_name ASC;

-- name: DeleteVariableBinding :exec
DELETE FROM document_variable_bindings
WHERE document_id = $1 AND variable_name = $2;

-- name: UpdateVariableBindingResolved :exec
UPDATE document_variable_bindings
   SET last_value    = $3,
       last_resolved = now(),
       last_error    = '',
       updated_at    = now()
 WHERE document_id = $1 AND variable_name = $2;

-- name: UpdateVariableBindingError :exec
UPDATE document_variable_bindings
   SET last_error    = $3,
       last_resolved = now(),
       updated_at    = now()
 WHERE document_id = $1 AND variable_name = $2;
