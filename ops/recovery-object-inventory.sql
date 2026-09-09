-- SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
-- Copyright (c) Bright Interaction
--
-- Canonical Hash database -> object-storage recovery inventory.
--
-- Run this against the isolated recovered database with psql. The first
-- column is a single-line base64 encoding of the exact object key so recovery
-- tooling never misparses whitespace or punctuation in an image storage_key.
-- object_key_json is the human-readable, JSON-escaped form. A key referenced
-- by several rows/classes is intentionally collapsed into one inventory row;
-- reference_classes and owners retain its provenance.

WITH RECURSIVE
document_retention(document_id, legal_evidence, expected_retain_until) AS (
	SELECT d.id,
	       CASE
	         -- Sealing is reversible until the durable retention-start marker.
	         -- Envelope children have no intent of their own: their root
	         -- envelope's intent is the sole legal deadline for the ceremony.
	         WHEN d.status = 'sealing' THEN root_intent.started_retain_until IS NOT NULL
	         WHEN d.status IN ('sent', 'in_progress', 'changes_requested', 'finalizing',
	                           'completed', 'declined', 'voided', 'expired') THEN true
	         ELSE false
	       END,
	       CASE
	         WHEN d.status = 'sealing' THEN root_intent.started_retain_until
	         WHEN d.status IN ('sent', 'in_progress', 'changes_requested', 'finalizing',
	                           'completed', 'declined', 'voided', 'expired') THEN
	           GREATEST(
	             d.finalization_retain_until,
	             hash_evidence_retain_until(d.article13_notice_epoch_at, 7),
	             root_intent.started_retain_until
	           )
	         ELSE NULL::timestamptz
	       END
	  FROM documents d
	  LEFT JOIN LATERAL (
	      SELECT max(si.retain_until) AS started_retain_until
	        FROM send_sealing_intents si
	       WHERE si.document_id = COALESCE(d.parent_envelope_id, d.id)
	         AND si.org_id = d.org_id
	         AND si.retention_started_at IS NOT NULL
	  ) root_intent ON true
),
block_roots(reference_class, owner_type, owner_id, org_id, legal_evidence, expected_retain_until, tree) AS (
	SELECT 'document_block_image', 'document', d.id::text, d.org_id,
	       retention.legal_evidence, retention.expected_retain_until, d.blocks_json
	  FROM documents d
	  JOIN document_retention retention ON retention.document_id = d.id
	 WHERE d.blocks_json IS NOT NULL
	   AND NOT (d.status = 'draft' AND d.deleted_at IS NOT NULL)
    UNION ALL
	    SELECT 'template_block_image', 'template', t.id::text, t.org_id,
	           false, NULL::timestamptz, t.blocks_json
      FROM templates t
     WHERE t.blocks_json IS NOT NULL
    UNION ALL
	    SELECT 'document_version_block_image', 'document_version', v.id::text, v.org_id,
	           retention.legal_evidence, retention.expected_retain_until, v.block_tree_json
	  FROM document_versions v
	  JOIN documents d ON d.id = v.document_id
	  JOIN document_retention retention ON retention.document_id = d.id
	 WHERE v.block_tree_json IS NOT NULL
	   AND NOT (d.status = 'draft' AND d.deleted_at IS NOT NULL)
),
block_nodes(reference_class, owner_type, owner_id, org_id, legal_evidence, expected_retain_until, node) AS (
	    SELECT r.reference_class, r.owner_type, r.owner_id, r.org_id, r.legal_evidence, r.expected_retain_until, b.node
      FROM block_roots r
      CROSS JOIN LATERAL jsonb_array_elements(
          CASE WHEN jsonb_typeof(r.tree -> 'blocks') = 'array'
               THEN r.tree -> 'blocks' ELSE '[]'::jsonb END
      ) AS b(node)
    UNION ALL
	    SELECT n.reference_class, n.owner_type, n.owner_id, n.org_id, n.legal_evidence, n.expected_retain_until, child.node
      FROM block_nodes n
      CROSS JOIN LATERAL jsonb_array_elements(
          CASE WHEN jsonb_typeof(n.node -> 'content') = 'array'
               THEN n.node -> 'content' ELSE '[]'::jsonb END
      ) AS child(node)
),
branding_urls(reference_class, owner_type, owner_id, org_id, logo_url) AS (
    SELECT 'org_branding_logo', 'org_branding', b.org_id::text, b.org_id, b.logo_url
      FROM org_branding b
     WHERE b.logo_url <> ''
    UNION ALL
    SELECT 'document_branding_logo', 'document_branding', b.document_id::text, d.org_id, b.logo_url
      FROM document_branding_override b
      JOIN documents d ON d.id = b.document_id
     WHERE b.logo_url IS NOT NULL AND b.logo_url <> ''
),
branding_objects AS (
    -- Hash-hosted logos are exposed as /branding/logo/<org UUID>.<ext>, while
    -- their stable bucket key is branding/<org UUID>/logo.<ext>. Keep matching
    -- old absolute Hash hostnames after a disaster; the route path is the
    -- durable identity. External logo URLs without this exact route are not S3
    -- objects and therefore do not belong in this inventory.
    SELECT u.reference_class, u.owner_type, u.owner_id, u.org_id,
           'branding/' || lower((m.parts)[1]) || '/logo' || lower((m.parts)[2]) AS object_key,
           NULL::text AS expected_sha256,
           NULL::text AS expected_version_id,
           false AS version_pin_required,
           false AS legacy_version_lookup_allowed,
	           false AS legal_evidence,
	           NULL::timestamptz AS expected_retain_until
      FROM branding_urls u
      CROSS JOIN LATERAL regexp_match(
          u.logo_url,
          '/branding/logo/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\.(?:png|jpg|jpeg|svg))(?:[?#].*)?$',
          'i'
      ) AS m(parts)
),
object_references(reference_class, owner_type, owner_id, org_id, object_key, expected_sha256, expected_version_id, version_pin_required, legacy_version_lookup_allowed, legal_evidence, expected_retain_until) AS (
	SELECT 'document_rendered_pdf', 'document', d.id::text, d.org_id,
	       d.rendered_pdf_key, encode(d.rendered_pdf_sha, 'hex'), d.rendered_pdf_version_id,
	       d.evidence_version_pins_required,
	       NOT d.evidence_version_pins_required AND d.rendered_pdf_version_id IS NULL,
	       retention.legal_evidence, retention.expected_retain_until
	  FROM documents d
	  JOIN document_retention retention ON retention.document_id = d.id
	 WHERE d.rendered_pdf_key IS NOT NULL
	   AND NOT (d.status = 'draft' AND d.deleted_at IS NOT NULL)
    UNION ALL
	SELECT 'document_source_pdf', 'document', d.id::text, d.org_id,
	       d.pdf_storage_key, encode(d.pdf_sha256, 'hex'), d.pdf_storage_version_id,
	       d.evidence_version_pins_required,
	       NOT d.evidence_version_pins_required AND d.pdf_storage_version_id IS NULL,
	       retention.legal_evidence, retention.expected_retain_until
	  FROM documents d
	  JOIN document_retention retention ON retention.document_id = d.id
	 WHERE d.pdf_storage_key IS NOT NULL
	   AND NOT (d.status = 'draft' AND d.deleted_at IS NOT NULL)
    UNION ALL
    SELECT 'document_final_pdf', 'document', d.id::text, d.org_id,
           d.final_pdf_key, encode(d.final_pdf_sha, 'hex'), d.final_pdf_version_id,
           d.evidence_version_pins_required,
           NOT d.evidence_version_pins_required AND d.final_pdf_version_id IS NULL,
	           true, d.finalization_retain_until
	  FROM documents d
	 WHERE d.final_pdf_key IS NOT NULL
	   AND d.parent_envelope_id IS NULL
	UNION ALL
	SELECT 'document_audit_certificate', 'document', d.id::text, d.org_id,
	       d.audit_cert_key,
	       COALESCE(encode(d.audit_cert_sha256, 'hex'), CASE
	         -- Current certificates are content-addressed. Promote the digest
	         -- encoded in the key into an expected object checksum so a
	         -- shadow/tampered version cannot pass a recovery check. Historical
	         -- audit.pdf keys carry no digest and remain existence-only.
	         WHEN d.audit_cert_key ~ '/audit-[0-9a-fA-F]{64}\.pdf$'
	         THEN lower(substring(d.audit_cert_key FROM 'audit-([0-9a-fA-F]{64})\.pdf$'))
	         ELSE NULL
	       END),
	       d.audit_cert_version_id,
	       d.evidence_version_pins_required,
	       NOT d.evidence_version_pins_required AND d.audit_cert_version_id IS NULL,
	       true, d.finalization_retain_until
	  FROM documents d
	 WHERE d.audit_cert_key IS NOT NULL
	   AND d.parent_envelope_id IS NULL
	UNION ALL
	-- A finalizing document has committed the exact staged artifact identities
	-- only in its durable intent. Those bytes are required to resume retention
	-- and publish completion after recovery, so a snapshot that inventories only
	-- documents would silently omit the most crash-sensitive object set.
	SELECT 'finalization_intent_final_pdf', 'document_finalization_intent', i.document_id::text, i.org_id,
	       i.final_pdf_key, encode(i.final_pdf_sha256, 'hex'), i.final_pdf_version_id,
	       i.evidence_version_pins_required,
	       NOT i.evidence_version_pins_required AND i.final_pdf_version_id IS NULL,
	       true, i.retain_until
	  FROM document_finalization_intents i
	UNION ALL
	SELECT 'finalization_intent_audit_certificate', 'document_finalization_intent', i.document_id::text, i.org_id,
	       i.audit_cert_key, encode(i.audit_cert_sha256, 'hex'), i.audit_cert_version_id,
	       i.evidence_version_pins_required,
	       NOT i.evidence_version_pins_required AND i.audit_cert_version_id IS NULL,
	       true, i.retain_until
	  FROM document_finalization_intents i
	UNION ALL
	SELECT 'finalization_intent_audit_payload', 'document_finalization_intent', i.document_id::text, i.org_id,
	       i.audit_payload_key, encode(i.audit_payload_sha256, 'hex'), i.audit_payload_version_id,
	       i.evidence_version_pins_required,
	       NOT i.evidence_version_pins_required AND i.audit_payload_version_id IS NULL,
	       true, i.retain_until
	  FROM document_finalization_intents i
	UNION ALL
	SELECT 'finalization_intent_audit_signature', 'document_finalization_intent', i.document_id::text, i.org_id,
	       i.audit_signature_key, encode(i.audit_signature_sha256, 'hex'), i.audit_signature_version_id,
	       i.evidence_version_pins_required,
	       NOT i.evidence_version_pins_required AND i.audit_signature_version_id IS NULL,
	       true, i.retain_until
	  FROM document_finalization_intents i
	    UNION ALL
	    SELECT 'template_source_pdf', 'template', t.id::text, t.org_id,
           t.pdf_storage_key, encode(t.pdf_sha256, 'hex'), t.pdf_storage_version_id,
           t.evidence_version_pin_required,
           NOT t.evidence_version_pin_required AND t.pdf_storage_version_id IS NULL,
	           false, NULL::timestamptz
      FROM templates t WHERE t.pdf_storage_key IS NOT NULL
    UNION ALL
    SELECT 'signature_image', 'signature', s.id::text, d.org_id,
           s.image_storage_key, encode(s.image_sha256, 'hex'), s.image_version_id,
           s.image_version_pin_required,
           NOT s.image_version_pin_required AND s.image_version_id IS NULL,
	           retention.legal_evidence, retention.expected_retain_until
      FROM signatures s
      JOIN documents d ON d.id = s.document_id
	  JOIN document_retention retention ON retention.document_id = d.id
    UNION ALL
    SELECT n.reference_class, n.owner_type, n.owner_id, n.org_id,
	           n.node #>> '{attrs,storage_key}', NULL, NULL,
	           n.legal_evidence, false,
	           n.legal_evidence, n.expected_retain_until
      FROM block_nodes n
     WHERE n.node ->> 'type' = 'image'
       AND NULLIF(n.node #>> '{attrs,storage_key}', '') IS NOT NULL
	UNION ALL
	SELECT 'document_audit_payload', 'document', d.id::text, d.org_id,
	       d.audit_payload_key, encode(d.audit_payload_sha256, 'hex'), d.audit_payload_version_id,
	       d.evidence_version_pins_required,
	       NOT d.evidence_version_pins_required AND d.audit_payload_version_id IS NULL,
	       true, d.finalization_retain_until
	  FROM documents d
	 WHERE d.audit_payload_key IS NOT NULL
	   AND d.parent_envelope_id IS NULL
	UNION ALL
	SELECT 'document_audit_signature', 'document', d.id::text, d.org_id,
	       d.audit_signature_key, encode(d.audit_signature_sha256, 'hex'), d.audit_signature_version_id,
	       d.evidence_version_pins_required,
	       NOT d.evidence_version_pins_required AND d.audit_signature_version_id IS NULL,
	       true, d.finalization_retain_until
	  FROM documents d
	 WHERE d.audit_signature_key IS NOT NULL
	   AND d.parent_envelope_id IS NULL
	UNION ALL
	-- Pre-00044 rows do not persist the sidecars' own keys/digests. Derive the
	-- historical names only so recovery reports the legacy object explicitly;
	-- the verifier treats this existence-only class as unverified and fails the
	-- gate until the evidence is remediated, never as a valid modern fallback.
	SELECT 'legacy_derived_audit_payload', 'document', d.id::text, d.org_id,
	       regexp_replace(d.audit_cert_key, '\.pdf$', '.payload.txt'), NULL, NULL, false, false, true,
	       d.finalization_retain_until
	  FROM documents d
	 WHERE d.audit_cert_key IS NOT NULL
	   AND d.audit_payload_key IS NULL
	   AND d.parent_envelope_id IS NULL
	UNION ALL
	SELECT 'legacy_derived_audit_signature', 'document', d.id::text, d.org_id,
	       regexp_replace(d.audit_cert_key, '\.pdf$', '.signature.txt'), NULL, NULL, false, false, true,
	       d.finalization_retain_until
	  FROM documents d
	 WHERE d.audit_cert_key IS NOT NULL
	   AND d.audit_signature_key IS NULL
	   AND d.parent_envelope_id IS NULL
    UNION ALL
    SELECT reference_class, owner_type, owner_id, org_id,
           object_key, expected_sha256, expected_version_id,
	           version_pin_required, legacy_version_lookup_allowed, legal_evidence, expected_retain_until
      FROM branding_objects
),
normalised AS (
    SELECT reference_class, owner_type, owner_id, org_id,
           object_key, NULLIF(lower(expected_sha256), '') AS expected_sha256,
           CASE WHEN NULLIF(btrim(expected_version_id), '') IS NULL
                THEN NULL ELSE expected_version_id END AS expected_version_id,
           version_pin_required, legacy_version_lookup_allowed,
	           legal_evidence, expected_retain_until
      FROM object_references
     WHERE NULLIF(object_key, '') IS NOT NULL
),
inventory AS (
    SELECT object_key,
           string_agg(DISTINCT reference_class, ',' ORDER BY reference_class) AS reference_classes,
           string_agg(DISTINCT owner_type || ':' || owner_id, ',' ORDER BY owner_type || ':' || owner_id) AS owners,
           string_agg(DISTINCT org_id::text, ',' ORDER BY org_id::text) AS org_ids,
           min(expected_sha256) FILTER (WHERE expected_sha256 IS NOT NULL) AS expected_sha256,
           count(DISTINCT expected_sha256) FILTER (WHERE expected_sha256 IS NOT NULL) > 1 AS hash_conflict,
           min(expected_version_id) FILTER (WHERE expected_version_id IS NOT NULL) AS expected_version_id,
           count(DISTINCT expected_version_id) FILTER (WHERE expected_version_id IS NOT NULL) > 1
             OR bool_or(version_pin_required AND expected_version_id IS NULL)
             OR coalesce(bool_or(btrim(expected_version_id) = 'hash:unversioned-development'), false)
             OR coalesce(bool_or(expected_version_id IS NOT NULL AND octet_length(expected_version_id) > 1024), false) AS version_conflict,
           CASE
             WHEN count(expected_version_id) FILTER (WHERE expected_version_id IS NOT NULL) <> 0 THEN false
             ELSE coalesce(bool_and(legacy_version_lookup_allowed)
                    FILTER (WHERE expected_sha256 IS NOT NULL), false)
           END AS legacy_version_lookup_allowed,
	           bool_or(legal_evidence) AS legal_evidence,
	           max(expected_retain_until) AS expected_retain_until,
	           count(*) AS reference_count
      FROM normalised
     GROUP BY object_key
)
SELECT replace(encode(convert_to(object_key, 'UTF8'), 'base64'), E'\n', '') AS object_key_b64,
       to_json(object_key)::text AS object_key_json,
       reference_classes,
       owners,
       org_ids,
       coalesce(expected_sha256, '-') AS expected_sha256,
       hash_conflict,
       legal_evidence,
       reference_count,
       coalesce(expected_version_id, '-') AS expected_version_id,
	       version_conflict,
	       legacy_version_lookup_allowed,
	       coalesce(to_char(expected_retain_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '-') AS expected_retain_until
  FROM inventory
 ORDER BY object_key;
