import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// eIDAS routing remains visible for migration and inspection, but this release
// is deliberately SES-only. Active AES/QES rules, historic defaults, and
// document tier escalation must all fail closed.

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

  test('seed_swedish_eidas_defaults fails closed', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/call', {
      name: 'seed_swedish_eidas_defaults',
      arguments: {}
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('Swedish defaults are unavailable');
  });

  test('inactive AES rules are retained but never affect routing', async ({ request }) => {
    const rule = await tool(request, 'create_eidas_rule', {
      name: `Inactive AES E2E ${Date.now()}`,
      priority: 50,
      predicate_json: { field: 'amount', op: '>=', value: 1 },
      required_tier: 'AES',
      reason: 'migration-only fixture',
      active: false
    });
    const out = await tool(request, 'preview_eidas_rules', {
      amount: 200000,
      current_tier: 'SES'
    });
    expect(out.required_tier).toBe('SES');
    expect(out.would_block).toBe(false);
    expect(out.matched_rules.map((r: { id: string }) => r.id)).not.toContain(rule.id);
    await tool(request, 'delete_eidas_rule', { rule_id: rule.id });
  });

  test('active AES/QES rules are rejected', async ({ request }) => {
    for (const required_tier of ['AES', 'QES']) {
      const res = await rpcRaw(request, 'tools/call', {
        name: 'create_eidas_rule',
        arguments: {
          name: `Unavailable ${required_tier} ${Date.now()}`,
          priority: 50,
          predicate_json: { field: 'amount', op: '>=', value: 1 },
          required_tier,
          reason: 'must fail closed',
          active: true
        }
      });
      expect(res.result.isError).toBe(true);
      expect(res.result.content[0].text).toContain('active AES/QES routing rules are unavailable');
    }
  });

  test('active SES rules remain available', async ({ request }) => {
    const variable = `e2e_gate_${Date.now()}`;
    const rule = await tool(request, 'create_eidas_rule', {
      name: `SES E2E ${Date.now()}`,
      priority: 50,
      predicate_json: { field: `variables.${variable}`, op: '==', value: 'yes' },
      required_tier: 'SES',
      reason: 'SES-only routing fixture',
      active: true
    });
    const out = await tool(request, 'preview_eidas_rules', {
      variables: { [variable]: 'yes' },
      current_tier: 'SES'
    });
    expect(out.required_tier).toBe('SES');
    expect(out.would_block).toBe(false);
    expect(out.matched_rules.map((r: { id: string }) => r.id)).toContain(rule.id);
    await tool(request, 'delete_eidas_rule', { rule_id: rule.id });
  });

  test('preview returns SES when no rule matches', async ({ request }) => {
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

  test('set_document_routing_tier rejects unavailable AES without relabelling document', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Tier test 2 ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'set_document_routing_tier',
      arguments: {
        document_id: doc.id,
        routing_tier: 'AES'
      }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('AES and QES are unavailable');
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

  test('create inactive higher-tier rule then delete', async ({ request }) => {
    const r = await tool(request, 'create_eidas_rule', {
      name: `E2E rule ${Date.now()}`,
      priority: 50,
      predicate_json: { field: 'amount', op: '>=', value: 99 },
      required_tier: 'AES',
      reason: 'e2e test',
      active: false
    });
    expect(r.required_tier).toBe('AES');
    expect(r.active).toBe(false);
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
