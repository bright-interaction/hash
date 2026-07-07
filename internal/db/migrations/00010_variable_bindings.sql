-- +goose Up

-- Phase 8.2: variable resolver v2. Document variables can now bind to live
-- external sources (BrightCRM deal, BrightCRM contact, SVAR scanner finding,
-- Hash org setting) instead of being static k/v in documents.variables_json.
-- Snapshot freeze on send still materializes resolved values into the version
-- row so historical content reproduces exactly.
--
-- Source kinds:
--   static          literal value pinned in documents.variables_json (today)
--   crm.deal        live from BrightCRM, source_path is a JSONPath like 'deal.amount'
--   crm.contact     live from BrightCRM contact
--   scanner.finding live from SVAR scanner
--   org.setting     read from the local hash org / branding row
--   agent.computed  resolved by the caller at render time (no remote fetch)

CREATE TABLE document_variable_bindings (
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    variable_name   TEXT NOT NULL,
    source_kind     TEXT NOT NULL CHECK (source_kind IN ('static','crm.deal','crm.contact','scanner.finding','org.setting','agent.computed')),
    source_ref      TEXT NOT NULL DEFAULT '',  -- e.g. deal_id, contact_id, scan_id; empty for source kinds that don't need a target id
    source_path     TEXT NOT NULL DEFAULT '',  -- e.g. "amount", "name", "critical_count"
    fallback        TEXT NOT NULL DEFAULT '',
    last_value      TEXT NOT NULL DEFAULT '',  -- last successfully-resolved value (for cache + UI display)
    last_resolved   TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, variable_name)
);

CREATE INDEX idx_var_bindings_doc ON document_variable_bindings(document_id);

-- +goose Down

DROP TABLE document_variable_bindings;
