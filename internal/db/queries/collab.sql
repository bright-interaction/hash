-- name: GetCollabDocState :one
SELECT * FROM collab_doc_states WHERE document_id = $1;

-- name: UpsertCollabDocState :one
INSERT INTO collab_doc_states (
    document_id, ydoc_state, state_size, update_count, last_user_id
) VALUES (
    $1, $2, $3, $4, $5
)
ON CONFLICT (document_id) DO UPDATE SET
    ydoc_state   = EXCLUDED.ydoc_state,
    state_size   = EXCLUDED.state_size,
    update_count = collab_doc_states.update_count + EXCLUDED.update_count,
    last_user_id = COALESCE(EXCLUDED.last_user_id, collab_doc_states.last_user_id),
    updated_at   = now()
RETURNING *;
