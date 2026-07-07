-- name: CreateComment :one
INSERT INTO document_comments (document_id, recipient_id, user_id, author_name, author_side, body)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListComments :many
SELECT * FROM document_comments
WHERE document_id = $1
ORDER BY created_at ASC;
