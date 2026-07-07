import { test, expect } from '@playwright/test';

// MCP integration tests. Require a seeded API key whose plaintext is
// HASH_E2E_API_KEY (defaulting to the seed used by the dev compose
// + CI seed script). Test skips if the key is not configured.

const API_KEY = process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

test.describe('MCP authoring loop', () => {
  test('rpc envelope responds to initialize', async ({ request }) => {
    const res = await rpc(request, 'initialize', {});
    expect(res.error).toBeFalsy();
    expect(res.result.serverInfo.name).toBe('hash');
    expect(res.result.protocolVersion).toBe('2025-03-26');
  });

  test('tools/list returns the full week-2 catalogue', async ({ request }) => {
    const res = await rpc(request, 'tools/list', {});
    expect(res.error).toBeFalsy();
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'create_document', 'set_document_blocks',
      'import_html', 'import_markdown',
      'append_block', 'delete_block', 'reorder_blocks',
      'add_signature_field', 'add_recipient', 'set_variables',
      'list_templates', 'get_template', 'list_documents', 'get_document',
      'search_documents', 'list_recipients', 'get_document_events', 'get_org_metrics'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('block schema resource exposes all block types', async ({ request }) => {
    const res = await rpc(request, 'resources/read', { uri: 'hash://schema/blocks' });
    expect(res.error).toBeFalsy();
    const body = JSON.parse(res.result.contents[0].text);
    expect(body.version).toBe(1);
    // 20 block types per the schema (heading..raw_html).
    expect(body.types.length).toBeGreaterThanOrEqual(20);
  });

  test('agent end-to-end: create_document → add_recipient → add_signature_field → get_document', async ({ request }) => {
    // Step 1: create
    const created = await tool(request, 'create_document', {
      name: 'E2E NDA',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'h1', type: 'heading', attrs: { level: 1 }, text: 'NDA' },
          { id: 'p1', type: 'paragraph', text: 'Between {{provider.name}} and {{client.name}}.' }
        ]
      }
    });
    const docID = created.id;
    expect(docID).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.status).toBe('draft');

    // Step 2: recipient
    const recipient = await tool(request, 'add_recipient', {
      document_id: docID,
      role: 'signer',
      email: 'e2e@example.com',
      name: 'E2E Signer'
    });
    expect(recipient.email).toBe('e2e@example.com');

    // Step 3: signature field
    await tool(request, 'add_signature_field', {
      document_id: docID,
      recipient_role: 'client',
      label: 'Client signature'
    });

    // Step 4: re-read and assert the tree now has 3 blocks
    const fetched = await tool(request, 'get_document', { id: docID });
    expect(fetched.status).toBe('draft');
    const tree = fetched.blocks_json as { blocks: Array<{ type: string }> };
    expect(tree.blocks.length).toBe(3);
    expect(tree.blocks[2].type).toBe('signature_field');
  });

  test('cross-tenant guard: random uuid returns isError', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/call', {
      name: 'get_document',
      arguments: { id: '00000000-0000-0000-0000-000000000000' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('document not found');
  });

  test('malformed agent input: unknown block type returns precise error', async ({ request }) => {
    // Need a doc to append to first.
    const doc = await tool(request, 'create_document', {
      name: 'Malformed test', source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'append_block',
      arguments: { document_id: doc.id, block: { type: 'not_a_real_type', text: 'x' } }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/unknown block type/);
  });

  test('import_markdown replaces the block tree', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Markdown import test', source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'import_markdown', {
      document_id: doc.id,
      markdown: '# Imported title\n\nA paragraph.\n\n- one\n- two\n'
    });
    const fetched = await tool(request, 'get_document', { id: doc.id });
    const tree = fetched.blocks_json as { blocks: Array<{ type: string }> };
    expect(tree.blocks.find((b) => b.type === 'heading')).toBeTruthy();
    expect(tree.blocks.find((b) => b.type === 'bullet_list')).toBeTruthy();
  });
});

// ── helpers ─────────────────────────────────────────────────────────────

async function rpc<T = any>(
  request: ReturnType<typeof test.extend>['extend'] extends never ? never : any,
  method: string,
  params: unknown
): Promise<{ result: T; error?: { code: number; message: string } }> {
  return rpcRaw(request, method, params);
}

async function rpcRaw(request: any, method: string, params: unknown) {
  const res = await request.post('/mcp', {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json'
    },
    data: { jsonrpc: '2.0', id: 1, method, params }
  });
  if (res.status() !== 200) {
    throw new Error(`MCP HTTP ${res.status()}: ${await res.text()}`);
  }
  return res.json();
}

// tool() unwraps tools/call responses: returns the parsed JSON from
// content[0].text, throwing if isError is set.
async function tool(request: any, name: string, args: unknown) {
  const res = await rpcRaw(request, 'tools/call', { name, arguments: args });
  if (res.error) {
    throw new Error(`rpc error: ${JSON.stringify(res.error)}`);
  }
  if (res.result.isError) {
    throw new Error(`tool error: ${res.result.content[0].text}`);
  }
  return JSON.parse(res.result.content[0].text);
}
