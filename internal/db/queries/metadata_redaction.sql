-- name: UpdateMetadataRedactionReport :exec
UPDATE documents
   SET metadata_redaction_report = $2,
       updated_at                = now()
 WHERE id = $1;

