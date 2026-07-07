-- +goose Up
-- A shared comment thread per document so the sender and the signer can ask and
-- answer questions in-product. Either side can post; the other side is emailed.
CREATE TABLE document_comments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id   UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id  UUID REFERENCES recipients(id) ON DELETE SET NULL,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    author_name   TEXT NOT NULL,
    author_side   TEXT NOT NULL CHECK (author_side IN ('sender','signer')),
    body          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_document_comments_document ON document_comments(document_id, created_at);

-- +goose Down
DROP TABLE document_comments;
