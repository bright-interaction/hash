import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 9.2: smart eIDAS tier escalation. Rules + preview + per-doc tier
// override + the send-time guard.

test.describe('eIDAS routing rules (Phase 9.2)', () => {
  test('tools/list contains the eidas tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'list_eidas_rules',
      'create_eidas_rule',
      'delete_eidas_rule',
      'seed_swedish_eidas_defaults',
      'preview_eidas_rules',
      'set_document_routing_tier'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('seed_swedish_eidas_defaults is idempotent', async ({ request }) => {
    const first = await tool(request, 'seed_swedish_eidas_defaults', {});
    expect(first.count).toBeGreaterThanOrEqual(3);
    const before = first.count;
    const second = await tool(request, 'seed_swedish_eidas_defaults', {});
    expect(second.count).toBe(before);
  });

  test('preview_eidas_rules returns AES for 200k SEK', async ({ request }) => {
    await tool(request, 'seed_swedish_eidas_defaults', {});
    const out = await tool(request, 'preview_eidas_rules', {
      amount: 200000,
      current_tier: 'SES'
    });
    expect(out.required_tier).toBe('AES');
    expect(out.would_block).toBe(true);
    expect(out.matched_rules.length).toBeGreaterThan(0);
  });

  test('preview_eidas_rules returns QES for 2M SEK', async ({ request }) => {
    await tool(request, 'seed_swedish_eidas_defaults', {});
    const out = await tool(request, 'preview_eidas_rules', {
      amount: 2000000,
      current_tier: 'AES'
    });
    expect(out.required_tier).toBe('QES');
    expect(out.would_block).toBe(true);
  });

  test('preview returns SES when no rule matches', async ({ request }) => {
    await tool(request, 'seed_swedish_eidas_defaults', {});
    const out = await tool(request, 'preview_eidas_rules', {
      amount: 5000,
      current_tier: 'SES'
    });
    expect(out.required_tier).toBe('SES');
    expect(out.would_block).toBe(false);
  });

  test('set_document_routing_tier rejects invalid values', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Tier test ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'set_document_routing_tier',
      arguments: { document_id: doc.id, routing_tier: 'PLATINUM' }
    });
    expect(res.result.isError).toBe(true);
  });

  test('set_document_routing_tier accepts AES', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Tier test 2 ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const out = await tool(request, 'set_document_routing_tier', {
      document_id: doc.id,
      routing_tier: 'AES'
    });
    expect(out.routing_tier).toBe('AES');
  });

  test('create_eidas_rule rejects invalid required_tier', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/call', {
      name: 'create_eidas_rule',
      arguments: {
        name: 'bad',
        predicate_json: { field: 'amount', op: '>=', value: 1 },
        required_tier: 'GOLD'
      }
    });
    expect(res.result.isError).toBe(true);
  });

  test('create_eidas_rule then delete', async ({ request }) => {
    const r = await tool(request, 'create_eidas_rule', {
      name: `E2E rule ${Date.now()}`,
      priority: 50,
      predicate_json: { field: 'amount', op: '>=', value: 99 },
      required_tier: 'AES',
      reason: 'e2e test'
    });
    expect(r.required_tier).toBe('AES');
    const del = await tool(request, 'delete_eidas_rule', { rule_id: r.id });
    expect(del.deleted).toBe(r.id);
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
