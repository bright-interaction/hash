import { test, expect, type APIRequestContext } from '@playwright/test';
import { writeFile } from 'node:fs/promises';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.6: PandaDoc-style multi-document envelopes. Tests cover the
// CRUD lifecycle (create, attach, detach, reorder, list) and the
// frozen-child content commitments that the audit cert binds via ed25519.

test.describe('multi-document envelopes (Phase 8.6)', () => {
  test('tools/list contains the envelope tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'create_envelope',
      'promote_to_envelope',
      'attach_to_envelope',
      'detach_from_envelope',
      'reorder_envelope_children',
      'list_envelope_children',
      'get_envelope_manifest'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('create_envelope bundles two existing drafts', async ({ request }) => {
    const ts = Date.now();
    const childA = await tool(request, 'create_document', {
      name: `Child A ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'a', type: 'paragraph', text: 'Master Agreement.' }] }
    });
    const childB = await tool(request, 'create_document', {
      name: `Child B ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'b', type: 'paragraph', text: 'DPA.' }] }
    });
    const env = await tool(request, 'create_envelope', {
      name: `Envelope ${ts}`,
      child_ids: [childA.id, childB.id]
    });
    expect(env.is_envelope).toBe(true);
    expect(env.status).toBe('draft');

    const children = await tool(request, 'list_envelope_children', { envelope_id: env.id });
    expect(children.count).toBe(2);
    expect(children.children.map((c: { id: string }) => c.id)).toEqual([childA.id, childB.id]);
    expect(children.children[0].envelope_position).toBe(1);
    expect(children.children[1].envelope_position).toBe(2);
  });

  test('detach + reorder reshape the envelope', async ({ request }) => {
    const ts = Date.now();
    const a = await tool(request, 'create_document', {
      name: `R-A ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const b = await tool(request, 'create_document', {
      name: `R-B ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const c = await tool(request, 'create_document', {
      name: `R-C ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const env = await tool(request, 'create_envelope', {
      name: `Reorder envelope ${ts}`,
      child_ids: [a.id, b.id, c.id]
    });
    // Detach the middle child.
    await tool(request, 'detach_from_envelope', { child_id: b.id });
    let children = await tool(request, 'list_envelope_children', { envelope_id: env.id });
    expect(children.count).toBe(2);
    // Reverse order via reorder.
    await tool(request, 'reorder_envelope_children', {
      envelope_id: env.id,
      child_id_order: [c.id, a.id]
    });
    children = await tool(request, 'list_envelope_children', { envelope_id: env.id });
    expect(children.children.map((x: { id: string }) => x.id)).toEqual([c.id, a.id]);
  });

  test('manifest hash changes when a child set changes', async ({ request }) => {
    const ts = Date.now();
    const a = await tool(request, 'create_document', {
      name: `M-A ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const env = await tool(request, 'create_envelope', {
      name: `Manifest envelope ${ts}`,
      child_ids: [a.id]
    });
    const m1 = await tool(request, 'get_envelope_manifest', { envelope_id: env.id });
    expect(m1.envelope_id).toBe(env.id);
    expect(m1.entries.length).toBe(1);
    expect(typeof m1.manifest_sha256).toBe('string');
    expect(m1.manifest_sha256).toMatch(/^[0-9a-f]{64}$/);

    const b = await tool(request, 'create_document', {
      name: `M-B ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'attach_to_envelope', { envelope_id: env.id, child_id: b.id });

    const m2 = await tool(request, 'get_envelope_manifest', { envelope_id: env.id });
    expect(m2.entries.length).toBe(2);
    expect(m2.manifest_sha256).not.toBe(m1.manifest_sha256);
  });

  test('create_envelope refuses empty child list', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/call', {
      name: 'create_envelope',
      arguments: { name: 'empty', child_ids: [] }
    });
    expect(res.result.isError).toBe(true);
  });

  test('attach_to_envelope refuses a non-envelope parent', async ({ request }) => {
    const ts = Date.now();
    const plain = await tool(request, 'create_document', {
      name: `Not an envelope ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const child = await tool(request, 'create_document', {
      name: `Child ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'attach_to_envelope',
      arguments: { envelope_id: plain.id, child_id: child.id }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/envelope/i);
  });

  test('send fails closed when a required child signing role is unassigned', async ({ request }) => {
    const unique = `envelope-role-gate-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const signerChild = await tool(request, 'create_document', {
      name: `Role gate signer ${unique}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'required-signer', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    const approverChild = await tool(request, 'create_document', {
      name: `Role gate approver ${unique}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'required-approver', type: 'signature_field', attrs: { recipient_role: 'approver' } }]
      }
    });
    const envelope = await tool(request, 'create_envelope', {
      name: `Role-gated envelope ${unique}`,
      child_ids: [signerChild.id, approverChild.id]
    });
    await tool(request, 'add_recipient', {
      document_id: envelope.id,
      role: 'signer',
      email: `only-signer-${unique}@example.com`,
      name: 'Only Signer'
    });

    const res = await rpcRaw(request, 'tools/call', {
      name: 'send_document',
      arguments: { document_id: envelope.id, lawful_basis: 'contract' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/no recipient assigned.*approver/i);
    expect((await tool(request, 'get_document', { id: envelope.id })).status).toBe('draft');
  });

  test('empty-shell envelope completes only after child signer + approver and renders both signed children', async ({ page, request }) => {
    test.setTimeout(120_000);
    const unique = `envelope-sign-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const childA = await tool(request, 'create_document', {
      name: `Envelope MSA ${unique}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'msa-proof', type: 'paragraph', text: `ENVELOPE MSA CONTENT ${unique}` },
          { id: 'msa-signer', type: 'signature_field', attrs: { recipient_role: 'signer' } }
        ]
      }
    });
    const childB = await tool(request, 'create_document', {
      name: `Envelope DPA ${unique}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'dpa-proof', type: 'paragraph', text: `ENVELOPE DPA CONTENT ${unique}` },
          {
            id: 'dpa-approval-callout',
            type: 'callout',
            attrs: { tone: 'info' },
            content: [
              { id: 'dpa-approver', type: 'signature_field', attrs: { recipient_role: 'approver' } }
            ]
          }
        ]
      }
    });
    const envelope = await tool(request, 'create_envelope', {
      name: `Envelope signing proof ${unique}`,
      child_ids: [childA.id, childB.id]
    });
    // The wrapper remains genuinely empty: all legal content and required
    // roles are discovered recursively from the two child trees.
    await tool(request, 'add_recipient', {
      document_id: envelope.id,
      role: 'signer',
      email: `signer-${unique}@example.com`,
      name: 'Envelope Signer'
    });
    await tool(request, 'add_recipient', {
      document_id: envelope.id,
      role: 'approver',
      email: `approver-${unique}@example.com`,
      name: 'Envelope Approver'
    });
    const sent = await tool(request, 'send_document', { document_id: envelope.id, lawful_basis: 'contract' });
    expect(sent.links).toHaveLength(2);
    const paths = Object.fromEntries(
      sent.links.map((link: { role: string; url: string }) => [link.role, new URL(link.url).pathname])
    ) as Record<string, string>;

    await page.goto(paths.signer);
    await acknowledgePrivacyNotice(page);
    await expect(page.getByText(`ENVELOPE MSA CONTENT ${unique}`, { exact: true })).toBeVisible();
    await expect(page.getByText(`ENVELOPE DPA CONTENT ${unique}`, { exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Type your full name')).toHaveValue('Envelope Signer');
    await page.getByRole('button', { name: 'Adopt and sign' }).click();
    await page.getByRole('button', { name: 'Sign with this signature' }).click();
    await expect(page.getByRole('heading', { name: 'Signed', exact: true })).toBeVisible({ timeout: 45_000 });
    await expect(page.getByText('The document will finalise once all parties have signed.')).toBeVisible();
    expect((await request.get(`${paths.signer}/final-pdf`)).status()).toBe(404);
    expect((await tool(request, 'get_document', { id: envelope.id })).status).toBe('in_progress');

    await page.goto(paths.approver);
    await acknowledgePrivacyNotice(page);
    await expect(page.getByText(`ENVELOPE MSA CONTENT ${unique}`, { exact: true })).toBeVisible();
    await expect(page.getByText(`ENVELOPE DPA CONTENT ${unique}`, { exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Type your full name')).toHaveValue('Envelope Approver');
    await page.getByRole('button', { name: 'Adopt and sign' }).click();
    await page.getByRole('button', { name: 'Sign with this signature' }).click();
    await expect(page.getByRole('heading', { name: 'Signed', exact: true })).toBeVisible({ timeout: 45_000 });

    const finalPDFPath = await completedArtifactPath(page);
    expect(finalPDFPath).not.toBe(`${paths.approver}/final-pdf`);
    const pdf = await request.get(finalPDFPath);
    expect(pdf.status()).toBe(200);
    const pdfBytes = await pdf.body();
    expect(pdfBytes.subarray(0, 5).toString()).toBe('%PDF-');
    if (process.env.HASH_E2E_ENVELOPE_PDF_OUT) {
      await writeFile(process.env.HASH_E2E_ENVELOPE_PDF_OUT, pdfBytes);
    }

    const completed = await tool(request, 'get_document', { id: envelope.id });
    expect(completed.status).toBe('completed');
    const children = await tool(request, 'list_envelope_children', { envelope_id: envelope.id });
    expect(children.children.map((c: { status: string }) => c.status)).toEqual(['completed', 'completed']);
    expect(children.children.every((c: { final_pdf_ready: boolean }) => c.final_pdf_ready)).toBe(true);
    const childArtifactHashes = children.children.map((c: { final_pdf_sha256: string }) => c.final_pdf_sha256);
    expect(new Set(childArtifactHashes).size).toBe(1);
    expect(childArtifactHashes[0]).toMatch(/^[0-9a-f]{64}$/);

    const manifest = await tool(request, 'get_envelope_manifest', { envelope_id: envelope.id });
    expect(manifest.schema_version).toBe(2);
    expect(manifest.entries).toHaveLength(2);
    for (const entry of manifest.entries) {
      expect(entry.status).toBe('completed');
      expect(entry.content_snapshot_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.final_pdf_sha256).toBeUndefined();
    }
    expect(manifest.manifest_sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

async function acknowledgePrivacyNotice(page: import('@playwright/test').Page) {
  const notice = page.getByRole('dialog', { name: 'Before you respond: how we handle your data' });
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('fixed 7-year evidence-retention policy');
  await notice.getByRole('button', { name: 'I understand, continue' }).click();
  await expect(notice).toBeHidden();
}

async function completedArtifactPath(page: import('@playwright/test').Page) {
  const link = page.getByRole('link', { name: 'Download signed PDF' });
  await expect(link).toHaveAttribute('href', /^\/sign\/[A-Za-z0-9_-]+\/final-pdf$/);
  const href = await link.getAttribute('href');
  if (!href) throw new Error('completed artifact link has no href');
  return href;
}

async function rpcRaw(request: APIRequestContext, method: string, params: unknown) {
  const res = await request.post('/mcp', {
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    data: { jsonrpc: '2.0', id: 1, method, params }
  });
  if (res.status() !== 200) {
    throw new Error(`MCP HTTP ${res.status()}: ${await res.text()}`);
  }
  return res.json();
}

async function tool(request: APIRequestContext, name: string, args: unknown) {
  const res = await rpcRaw(request, 'tools/call', { name, arguments: args });
  if (res.error) throw new Error(`rpc error: ${JSON.stringify(res.error)}`);
  if (res.result.isError) throw new Error(`tool error: ${res.result.content[0].text}`);
  return JSON.parse(res.result.content[0].text);
}
