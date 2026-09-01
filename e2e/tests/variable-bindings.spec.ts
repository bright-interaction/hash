import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.2: variable resolver v2. Static values, agent overrides, and bound
// sources (BrightCRM/SVAR/org.setting) all resolve through one chain.
// Snapshot freeze on send materializes resolved values into the document's
// variables_json so post-send renders never re-fetch.

test.describe('variable bindings (Phase 8.2)', () => {
  test('tools/list contains the 8.2 binding tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'list_variable_bindings',
      'bind_variable_to_crm_deal',
      'bind_variable_to_crm_contact',
      'bind_variable_to_scanner_finding',
      'bind_variable_to_org_setting',
      'unbind_variable',
      'preview_resolved_variables'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('preview_resolved_variables shows static values for unbound vars', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Static vars ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'set_variables', {
      document_id: doc.id,
      variables: { client_name: 'Acme AB', amount: 'SEK 50,000' }
    });
    const preview = await tool(request, 'preview_resolved_variables', {
      document_id: doc.id
    });
    expect(preview.variables.client_name).toBe('Acme AB');
    expect(preview.variables.amount).toBe('SEK 50,000');
    expect(preview.frozen).toBe(false);
  });

  test('agent_overrides win over static values', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Override test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'set_variables', {
      document_id: doc.id,
      variables: { tier: 'starter' }
    });
    const preview = await tool(request, 'preview_resolved_variables', {
      document_id: doc.id,
      agent_overrides: { tier: 'enterprise' }
    });
    expect(preview.variables.tier).toBe('enterprise');
  });

  test('bind_variable_to_org_setting resolves locally', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Org bind test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const binding = await tool(request, 'bind_variable_to_org_setting', {
      document_id: doc.id,
      variable: 'org_name',
      path: 'org.name'
    });
    expect(binding.source_kind).toBe('org.setting');
    expect(binding.source_path).toBe('org.name');

    const preview = await tool(request, 'preview_resolved_variables', {
      document_id: doc.id
    });
    expect(preview.variables.org_name).toBeTruthy();
    const orgRow = preview.report.find((r: { variable: string }) => r.variable === 'org_name');
    expect(orgRow.resolved_from).toBe('source');
  });

  test('bind to CRM deal returns ErrNotConfigured fallback when creds absent', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'CRM bind unconfigured',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'bind_variable_to_crm_deal', {
      document_id: doc.id,
      variable: 'deal_amount',
      deal_id: 'deal_test',
      path: 'deal.amount',
      fallback: 'TBD'
    });
    const preview = await tool(request, 'preview_resolved_variables', {
      document_id: doc.id
    });
    // No creds in test env => binding errors, fallback used.
    expect(preview.variables.deal_amount).toBe('TBD');
    const row = preview.report.find((r: { variable: string }) => r.variable === 'deal_amount');
    expect(row.resolved_from).toBe('fallback');
  });

  test('list_variable_bindings returns every binding with last_value', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'List bindings',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'bind_variable_to_org_setting', {
      document_id: doc.id,
      variable: 'org_name',
      path: 'org.name'
    });
    await tool(request, 'bind_variable_to_org_setting', {
      document_id: doc.id,
      variable: 'org_id',
      path: 'org.id'
    });
    // Force resolution so last_value gets populated.
    await tool(request, 'preview_resolved_variables', { document_id: doc.id });

    const list = await tool(request, 'list_variable_bindings', {
      document_id: doc.id
    });
    expect(list.count).toBe(2);
    const names = list.bindings.map((b: { variable: string }) => b.variable).sort();
    expect(names).toEqual(['org_id', 'org_name']);
    expect(list.bindings.every((b: { last_value: string }) => b.last_value !== '')).toBe(true);
  });

  test('unbind_variable removes the binding', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Unbind test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'bind_variable_to_org_setting', {
      document_id: doc.id,
      variable: 'org_name',
      path: 'org.name'
    });
    await tool(request, 'unbind_variable', {
      document_id: doc.id,
      variable: 'org_name'
    });
    const list = await tool(request, 'list_variable_bindings', {
      document_id: doc.id
    });
    expect(list.count).toBe(0);
  });

  test('bindings refuse on non-draft documents', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Bind freeze guard',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: `bind-freeze-${Date.now()}@example.com`,
      name: 'Binding Freeze Guard'
    });
    await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'bind_variable_to_org_setting',
      arguments: { document_id: doc.id, variable: 'x', path: 'org.name' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/frozen|status/i);
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
