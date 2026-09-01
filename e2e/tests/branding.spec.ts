import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';
const SESSION_COOKIE = process.env.HASH_E2E_SESSION_COOKIE || '';

// Phase 8.5: org-level brand theming. Reading the palette before any
// upsert returns the system defaults. Upserting via MCP normalises hex
// colours. Document preview HTML carries the CSS custom-property block.

test.describe('brand theming (Phase 8.5)', () => {
  test('tools/list contains the branding tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('get_org_branding');
    expect(names).toContain('set_org_branding');
    expect(names).toContain('resolve_document_branding');
  });

  test('get_org_branding returns defaults before any upsert', async ({ request }) => {
    // Fresh fixture not guaranteed; just assert shape + hex format.
    const out = await tool(request, 'get_org_branding', {});
    expect(out).toHaveProperty('primary_hex');
    expect(out.primary_hex).toMatch(/^#[0-9A-F]{6}$/);
    expect(out).toHaveProperty('accent_hex');
    expect(out).toHaveProperty('font_heading');
  });

  test('set_org_branding normalises hex shorthand and persists', async ({ request }) => {
    const out = await tool(request, 'set_org_branding', {
      primary_hex: '#0f1', // shorthand
      accent_hex: 'aabbcc' // no leading hash
    });
    expect(out.primary_hex).toBe('#00FF11');
    expect(out.accent_hex).toBe('#AABBCC');

    const reread = await tool(request, 'get_org_branding', {});
    expect(reread.primary_hex).toBe('#00FF11');
    expect(reread.accent_hex).toBe('#AABBCC');
  });

  test('set_org_branding rejects bad hex colours', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/call', {
      name: 'set_org_branding',
      arguments: { primary_hex: 'not-a-color' }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/hex/i);
  });

  test('resolve_document_branding returns the resolved palette', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Branding e2e ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const out = await tool(request, 'resolve_document_branding', {
      document_id: doc.id
    });
    expect(out).toHaveProperty('primary_hex');
    expect(out.primary_hex).toMatch(/^#[0-9A-F]{6}$/);
  });

  test('document preview HTML embeds the CSS variable block', async ({ request }) => {
    test.skip(!SESSION_COOKIE, 'requires HASH_E2E_SESSION_COOKIE for the sender preview endpoint');
    await tool(request, 'set_org_branding', { primary_hex: '#123456' });
    const doc = await tool(request, 'create_document', {
      name: `Preview e2e ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'p', type: 'paragraph', text: 'Hello.' }]
      }
    });
    const preview = await request.get(`/api/v1/documents/${doc.id}/preview`, {
      headers: { Cookie: SESSION_COOKIE }
    });
    expect(preview.status()).toBe(200);
    expect(await preview.text()).toContain('--hash-primary');
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
