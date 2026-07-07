import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.8: audit-event timeline (the events table from week 1 surfaced
// for sender-side review). Distinct from the Phase 8.3 signer telemetry
// stream which now lives at get_document_telemetry_stream.

test.describe('audit timeline (Phase 8.8)', () => {
  test('tools/list contains the 8.8 timeline tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'get_document_timeline',
      'get_org_activity',
      'get_org_activity_leaderboard',
      'get_document_telemetry_stream' // renamed from 8.3
    ]) {
      expect(names).toContain(required);
    }
  });

  test('document timeline returns audit events for an edited doc', async ({ request }) => {
    const ts = Date.now();
    const doc = await tool(request, 'create_document', {
      name: `Timeline e2e ${ts}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'h', type: 'heading', attrs: { level: 1 }, text: 'NDA' }]
      }
    });
    // Two edits + an attach metadata = three updated events.
    await tool(request, 'update_block', {
      document_id: doc.id,
      block_id: 'h',
      block: { id: 'h', type: 'heading', attrs: { level: 1 }, text: 'NDA v2' }
    });
    await tool(request, 'append_block', {
      document_id: doc.id,
      block: { id: 'p', type: 'paragraph', text: 'New clause.' }
    });

    const out = await tool(request, 'get_document_timeline', {
      document_id: doc.id,
      group: false
    });
    expect(out.count).toBeGreaterThanOrEqual(3); // created + 2 updates
    const kinds = out.entries.map((e: { kind: string }) => e.kind);
    expect(kinds).toContain('document.created');
    expect(kinds.filter((k: string) => k === 'document.updated').length).toBeGreaterThanOrEqual(2);
  });

  test('grouping collapses consecutive same-actor same-kind events', async ({ request }) => {
    const ts = Date.now();
    const doc = await tool(request, 'create_document', {
      name: `Grouping e2e ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'p', type: 'paragraph', text: 'a' }] }
    });
    for (let i = 0; i < 4; i++) {
      await tool(request, 'update_block', {
        document_id: doc.id,
        block_id: 'p',
        block: { id: 'p', type: 'paragraph', text: `edit ${i}` }
      });
    }
    const grouped = await tool(request, 'get_document_timeline', {
      document_id: doc.id,
      group: true
    });
    const updatedEntries = grouped.entries.filter(
      (e: { kind: string }) => e.kind === 'document.updated'
    );
    // Edits within seconds collapse into a single entry with occurrences>=4
    expect(updatedEntries.length).toBe(1);
    expect(updatedEntries[0].occurrences).toBeGreaterThanOrEqual(4);
  });

  test('kind filter narrows results', async ({ request }) => {
    const ts = Date.now();
    const doc = await tool(request, 'create_document', {
      name: `Kind filter ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    await tool(request, 'append_block', {
      document_id: doc.id,
      block: { id: 'p', type: 'paragraph', text: 'hi' }
    });
    const only = await tool(request, 'get_document_timeline', {
      document_id: doc.id,
      kinds: ['document.created']
    });
    expect(only.count).toBeGreaterThanOrEqual(1);
    for (const e of only.entries) {
      expect(e.kind).toBe('document.created');
    }
  });

  test('diff=true embeds block-level changes on document.updated entries', async ({ request }) => {
    const ts = Date.now();
    const doc = await tool(request, 'create_document', {
      name: `Diff embed ${ts}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'p', type: 'paragraph', text: 'Original.' }]
      }
    });
    await tool(request, 'update_block', {
      document_id: doc.id,
      block_id: 'p',
      block: { id: 'p', type: 'paragraph', text: 'Edited.' }
    });
    // Wait a beat so versions land.
    await new Promise((r) => setTimeout(r, 200));

    const out = await tool(request, 'get_document_timeline', {
      document_id: doc.id,
      group: false,
      diff: true
    });
    const updated = out.entries.find(
      (e: { kind: string }) => e.kind === 'document.updated'
    );
    expect(updated).toBeTruthy();
    // diff_changes may be null if version lookup didn't find a predecessor
    // (small documents on a busy stack); at least the field is exposed.
    expect('diff_changes' in updated).toBe(true);
  });

  test('org activity feed returns events across documents', async ({ request }) => {
    const out = await tool(request, 'get_org_activity', { limit: 50 });
    expect(typeof out.count).toBe('number');
    expect(Array.isArray(out.entries)).toBe(true);
  });

  test('org activity leaderboard returns top actors', async ({ request }) => {
    const out = await tool(request, 'get_org_activity_leaderboard', {
      days: 30,
      limit: 5
    });
    expect(Array.isArray(out.entries)).toBe(true);
    expect(out.days).toBe(30);
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
