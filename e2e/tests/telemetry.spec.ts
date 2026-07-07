import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.3: signer telemetry pipeline. /sign/{token}/telemetry accepts
// batched IntersectionObserver/scroll/click/session events. Privacy:
// country-only ip_geo, ua_class only. Per-document engagement rollups +
// raw timeline expose sender-side reads (gated on multi-recipient OR
// fully signed).

test.describe('signer telemetry (Phase 8.3)', () => {
  test('tools/list contains the engagement read tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('get_document_engagement');
    expect(names).toContain('get_document_telemetry_stream');
  });

  test('telemetry endpoint accepts a batch and persists events', async ({ request }) => {
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
    expect(res.status()).toBe(204);

    // Verify via timeline (privacy-gated for single-recipient docs until
    // they sign, so we sign it first to unlock the read).
    await signDoc(request, token);

    const tl = await tool(request, 'get_document_telemetry_stream', { document_id: docId });
    expect(tl.privacy_gated).toBe(false);
    const kinds = tl.events.map((e: { kind: string }) => e.kind);
    expect(kinds).toContain('block.viewed');
    expect(kinds).toContain('page.scroll');
  });

  test('telemetry rejects invalid kinds and oversize payloads silently', async ({ request }) => {
    const { token } = await setupSentDoc(request);
    const res = await request.post(`/sign/${token}/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        events: [
          { kind: 'NOT_A_KIND', block_id: 'x' },
          { kind: 'block.viewed', block_id: 'big', payload: { junk: 'a'.repeat(8 * 1024) } },
          { kind: 'session.start' }
        ]
      }
    });
    // Still 204; invalid rows are silently skipped, the valid session.start
    // gets through.
    expect(res.status()).toBe(204);
  });

  test('telemetry rejects oversized batch', async ({ request }) => {
    const { token } = await setupSentDoc(request);
    const events = Array.from({ length: 250 }, (_, i) => ({
      kind: 'page.scroll',
      payload: { scroll_y: i }
    }));
    const res = await request.post(`/sign/${token}/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: { events }
    });
    expect(res.status()).toBe(400);
  });

  test('telemetry rejects unknown token', async ({ request }) => {
    const res = await request.post(`/sign/this-is-not-a-real-token/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: { events: [{ kind: 'session.start' }] }
    });
    expect(res.status()).toBe(404);
  });

  test('engagement is privacy-gated until the single recipient signs', async ({ request }) => {
    const { token, docId } = await setupSentDoc(request);
    // Inject some block.viewed events.
    await request.post(`/sign/${token}/telemetry`, {
      headers: { 'Content-Type': 'application/json' },
      data: {
        events: [
          { kind: 'block.viewed', block_id: 'h', payload: { dwell_ms: 1000 } }
        ]
      }
    });
    // Pre-sign: gated.
    const gated = await tool(request, 'get_document_engagement', { document_id: docId });
    expect(gated.privacy_gated).toBe(true);
    expect(gated.blocks).toEqual([]);

    // Sign, then ungated.
    await signDoc(request, token);
    const ungated = await tool(request, 'get_document_engagement', { document_id: docId });
    expect(ungated.privacy_gated).toBe(false);
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
  const send = await tool(request, 'send_document', { document_id: doc.id });
  const url: string = send.links[0].url;
  const token = url.split('/sign/')[1];
  return { token, docId: doc.id };
}

async function signDoc(request: APIRequestContext, token: string) {
  const res = await request.post(`/sign/${token}/sign`, {
    headers: { 'Content-Type': 'application/json' },
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
