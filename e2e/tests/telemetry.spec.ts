import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Signer analytics fail closed until Hash has a persisted, notice-versioned
// consent and withdrawal flow. Historical engagement data remains readable,
// but the public signer endpoint must reject every submission without writing
// any raw events or engagement rollups.

test.describe('retired signer telemetry', () => {
  test('historical engagement read tools remain available', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('get_document_engagement');
    expect(names).toContain('get_document_telemetry_stream');
  });

  test('telemetry endpoint returns 410 and does not persist submitted events', async ({ request }) => {
    test.setTimeout(60_000);
    const { token, docId } = await setupSentDoc(request);

    const res = await request.post(`/sign/${token}/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        events: [
          { kind: 'session.start' },
          { kind: 'block.viewed', block_id: 'h', payload: { dwell_ms: 1200 } },
          { kind: 'block.viewed', block_id: 'p', payload: { dwell_ms: 3400 } },
          { kind: 'page.scroll', payload: { scroll_y: 200, scroll_pct: 0.4 } },
          { kind: 'interaction.click', block_id: 's', payload: { tag: 'button' } }
        ]
      }
    });
    expect(res.status()).toBe(410);
    expect(await res.json()).toMatchObject({ error: 'signer analytics are disabled' });

    // Single-recipient telemetry reads are privacy-gated before completion.
    // Sign the document to expose the underlying rows, then prove that the
    // rejected POST wrote neither raw telemetry nor an engagement summary.
    await signDoc(request, token);

    const stream = await tool(request, 'get_document_telemetry_stream', { document_id: docId });
    expect(stream).toMatchObject({ privacy_gated: false, events: [] });

    const engagement = await tool(request, 'get_document_engagement', { document_id: docId });
    expect(engagement).toMatchObject({ privacy_gated: false, blocks: [] });
  });

  test('telemetry fails closed before token or payload validation', async ({ request }) => {
    const res = await request.post(`/sign/this-is-not-a-real-token/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        events: Array.from({ length: 250 }, (_, i) => ({
          kind: 'NOT_A_KIND',
          payload: { scroll_y: i, junk: 'a'.repeat(8 * 1024) }
        }))
      }
    });
    expect(res.status()).toBe(410);
    expect(await res.json()).toMatchObject({ error: 'signer analytics are disabled' });
  });
});

// Helpers

async function setupSentDoc(request: APIRequestContext): Promise<{ token: string; docId: string }> {
  const doc = await tool(request, 'create_document', {
    name: `Telemetry e2e ${Date.now()}`,
    source_kind: 'blocks',
    blocks_json: {
      version: 1,
      blocks: [
        { id: 'h', type: 'heading', attrs: { level: 1 }, text: 'NDA' },
        { id: 'p', type: 'paragraph', text: 'Body clause.' },
        { id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }
      ]
    }
  });
  await tool(request, 'add_recipient', {
    document_id: doc.id,
    role: 'signer',
    email: `tel-${Date.now()}@example.com`,
    name: 'Telemetry Test'
  });
  const send = await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
  const url: string = send.links[0].url;
  const token = url.split('/sign/')[1];
  return { token, docId: doc.id };
}

async function signDoc(request: APIRequestContext, token: string) {
  const context = await request.get(`/sign/${token}`);
  if (!context.ok()) {
    throw new Error(`load signer context failed: ${context.status()} ${await context.text()}`);
  }
  const noticeDigest = (await context.json())?.privacy?.notice_digest;
  if (typeof noticeDigest !== 'string' || !/^[0-9a-f]{64}$/.test(noticeDigest)) {
    throw new Error('signer context did not provide a valid privacy notice digest');
  }
  const res = await request.post(`/sign/${token}/sign`, {
    headers: {
      'Content-Type': 'application/json',
      'X-Hash-Notice-Digest': noticeDigest
    },
    data: { typed_name: 'Test User', font: 'Caveat' }
  });
  if (!res.ok()) {
    throw new Error(`sign failed: ${res.status()} ${await res.text()}`);
  }
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
