import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.6: PandaDoc-style multi-document envelopes. Tests cover the
// CRUD lifecycle (create, attach, detach, reorder, list) and the
// manifest hash that the audit cert binds via ed25519.

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
});

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
