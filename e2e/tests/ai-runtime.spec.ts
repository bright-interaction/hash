import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.4: AI runtime foundation. We don't fire real LLM completions
// in e2e (the runtime is wired but providers may be unconfigured in CI).
// Status + prompt-list reads prove the runtime is mounted and the three
// built-in prompts ship.

test.describe('AI runtime status (Phase 8.4)', () => {
  test('tools/list contains the AI status tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('ai_runtime_status');
    expect(names).toContain('ai_list_prompts');
  });

  test('ai_runtime_status reports configured runtime', async ({ request }) => {
    const status = await tool(request, 'ai_runtime_status', {});
    expect(status).toHaveProperty('shield_active');
    expect(status).toHaveProperty('providers');
    expect(status).toHaveProperty('default');
    expect(status).toHaveProperty('embedder');
    expect(status).toHaveProperty('prompt_count');
    expect(typeof status.shield_active).toBe('boolean');
    expect(Array.isArray(status.providers)).toBe(true);
    expect(status.prompt_count).toBeGreaterThanOrEqual(3);
  });

  test('ai_list_prompts returns the three built-in templates', async ({ request }) => {
    const out = await tool(request, 'ai_list_prompts', {});
    const names = out.prompts.map((p: { name: string }) => p.name).sort();
    expect(names).toEqual(
      expect.arrayContaining([
        'bilingual_equivalence',
        'negotiation_counter',
        'signer_clarifier'
      ])
    );
    for (const p of out.prompts) {
      expect(p.latest_version).toBeGreaterThanOrEqual(1);
      expect(typeof p.description).toBe('string');
      expect(p.description.length).toBeGreaterThan(0);
    }
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
