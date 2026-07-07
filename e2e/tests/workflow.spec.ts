import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

const MAILHOG = process.env.HASH_MAILHOG_URL || 'http://127.0.0.1:8025';

// Week 7: agent-driven workflow tools (send, void, remind, set_expiry,
// attach_metadata). These tests prove the moat: an agent can drive a
// document end-to-end via MCP, no REST + no session cookie.

test.describe('MCP workflow write tools', () => {
  test('tools/list contains the new workflow tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'send_document',
      'void_document',
      'remind_recipient',
      'set_expiry',
      'attach_metadata'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('send_document on a draft with no signers fails cleanly', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'No-signer test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'p', type: 'paragraph', text: 'hi' }] }
    });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'send_document',
      arguments: { document_id: doc.id }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('signer');
  });

  test('full agent workflow: create -> add_recipient -> send -> mailhog has invite', async ({ request }) => {
    const before = await mailCount(request);

    // Step 1: author
    const doc = await tool(request, 'create_document', {
      name: `Workflow E2E ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'h', type: 'heading', attrs: { level: 1 }, text: 'NDA' },
          { id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }
        ]
      }
    });
    expect(doc.status).toBe('draft');

    // Step 2: recipient
    const recipientEmail = `wf-${Date.now()}@example.com`;
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: recipientEmail,
      name: 'Workflow Test'
    });

    // Step 3: send
    const sendResult = await tool(request, 'send_document', { document_id: doc.id });
    expect(sendResult.status).toBe('sent');
    expect(Array.isArray(sendResult.links)).toBe(true);
    expect(sendResult.links.length).toBe(1);
    expect(sendResult.links[0].url).toMatch(/\/sign\//);

    // Step 4: invite email shows up in mailhog within 3 seconds.
    let after = before;
    for (let i = 0; i < 30 && after === before; i++) {
      await new Promise((r) => setTimeout(r, 100));
      after = await mailCount(request);
    }
    expect(after).toBeGreaterThan(before);
  });

  test('void_document on a sent doc cancels it', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Void test',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    await tool(request, 'add_recipient', {
      document_id: doc.id, role: 'signer', email: 'void@example.com', name: 'V'
    });
    await tool(request, 'send_document', { document_id: doc.id });
    const voided = await tool(request, 'void_document', {
      document_id: doc.id, reason: 'agent recall'
    });
    expect(voided.status).toBe('voided');

    const fetched = await tool(request, 'get_document', { id: doc.id });
    expect(fetched.status).toBe('voided');
  });

  test('void_document on an already-completed doc fails (state-machine guard)', async ({ request }) => {
    // Drafts are voidable (sender changed their mind). The guard is for
    // already-finalised states. Simulate by directly setting status.
    const doc = await tool(request, 'create_document', {
      name: 'Void-completed guard',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    // Void it once (draft -> voided) so the next attempt hits the guard.
    await tool(request, 'void_document', { document_id: doc.id, reason: 'first' });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'void_document',
      arguments: { document_id: doc.id, reason: 'second' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/already finalised/);
  });

  test('attach_metadata round-trips through get_document', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Meta test',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'attach_metadata', {
      document_id: doc.id,
      key: 'brightcrm_deal_id',
      value: 'deal_4f2c9e8a'
    });
    const fetched = await tool(request, 'get_document', { id: doc.id });
    const meta = fetched.metadata as Record<string, string>;
    expect(meta.brightcrm_deal_id).toBe('deal_4f2c9e8a');
  });

  test('set_expiry rejects past timestamps', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Expiry guard',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const past = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const res = await rpcRaw(request, 'tools/call', {
      name: 'set_expiry',
      arguments: { document_id: doc.id, expires_at: past }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toContain('future');
  });

  test('set_expiry accepts a future timestamp', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Expiry happy path',
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const future = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await tool(request, 'set_expiry', { document_id: doc.id, expires_at: future });
    const fetched = await tool(request, 'get_document', { id: doc.id });
    expect(fetched.expires_at).toBeTruthy();
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

async function mailCount(request: APIRequestContext): Promise<number> {
  const res = await request.get(`${MAILHOG}/api/v2/messages`);
  if (res.status() !== 200) return 0;
  const body = await res.json();
  return body.count ?? body.total ?? body.items?.length ?? 0;
}
