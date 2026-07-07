import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';
const SESSION_COOKIE = process.env.HASH_E2E_SESSION_COOKIE || '';

// v1.1: per-document scoped agent tokens. Sender mints a token bound
// to one document. The token authenticates MCP calls but cannot be
// used to read any other document in the same org.

test.describe('per-document agent tokens (v1.1)', () => {
  test.skip(!SESSION_COOKIE, 'requires HASH_E2E_SESSION_COOKIE for the sender-side mint endpoint');

  test('mint -> use -> wrong-doc rejected -> revoke -> dead', async ({ request }) => {
    // Bootstrap two documents via the org-wide API key path.
    const ts = Date.now();
    const docA = await tool(request, 'create_document', {
      name: `Token A ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'p', type: 'paragraph', text: 'A body' }] }
    });
    const docB = await tool(request, 'create_document', {
      name: `Token B ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [{ id: 'p', type: 'paragraph', text: 'B body' }] }
    });

    // Mint a token bound to docA via the session-authed REST endpoint.
    const mintRes = await request.post(`/api/v1/documents/${docA.id}/agent-tokens`, {
      headers: { Cookie: SESSION_COOKIE, 'Content-Type': 'application/json' },
      data: { name: 'e2e-test', ttl_hours: 1, max_uses: 50 }
    });
    expect(mintRes.status()).toBe(201);
    const minted = await mintRes.json();
    expect(typeof minted.token).toBe('string');
    expect(minted.token.startsWith('mth_')).toBe(true);
    expect(minted.prefix.length).toBe(8);

    // Using the doc-scoped token, reading docA should succeed.
    const readBoundRes = await request.post('/mcp', {
      headers: { Authorization: `Bearer ${minted.token}`, 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'get_document', arguments: { id: docA.id } }
      }
    });
    expect(readBoundRes.status()).toBe(200);
    const readBound = await readBoundRes.json();
    expect(readBound.result.isError ?? false).toBe(false);

    // Using the doc-scoped token to read docB should be refused.
    const readOtherRes = await request.post('/mcp', {
      headers: { Authorization: `Bearer ${minted.token}`, 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0', id: 2, method: 'tools/call',
        params: { name: 'get_document', arguments: { id: docB.id } }
      }
    });
    const readOther = await readOtherRes.json();
    expect(readOther.result.isError).toBe(true);
    expect(readOther.result.content[0].text).toMatch(/scoped to a different document/i);

    // list_documents under the scoped token returns ONLY the bound doc.
    const listRes = await request.post('/mcp', {
      headers: { Authorization: `Bearer ${minted.token}`, 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0', id: 3, method: 'tools/call',
        params: { name: 'list_documents', arguments: {} }
      }
    });
    const listBody = await listRes.json();
    const listed = JSON.parse(listBody.result.content[0].text);
    expect(listed.count).toBe(1);
    expect(listed.documents[0].id).toBe(docA.id);

    // Revoke the token. The revoke endpoint takes the token's id from
    // the mint response.
    const revokeRes = await request.delete(`/api/v1/agent-tokens/${minted.id}`, {
      headers: { Cookie: SESSION_COOKIE }
    });
    expect(revokeRes.status()).toBe(204);

    // After revoke the token can no longer authenticate.
    const afterRes = await request.post('/mcp', {
      headers: { Authorization: `Bearer ${minted.token}`, 'Content-Type': 'application/json' },
      data: {
        jsonrpc: '2.0', id: 4, method: 'tools/call',
        params: { name: 'get_document', arguments: { id: docA.id } }
      }
    });
    expect(afterRes.status()).toBe(401);
  });

  test('list_agent_tokens shows the minted token without exposing plaintext', async ({ request }) => {
    const ts = Date.now();
    const doc = await tool(request, 'create_document', {
      name: `List tokens ${ts}`,
      source_kind: 'blocks',
      blocks_json: { version: 1, blocks: [] }
    });
    const mintRes = await request.post(`/api/v1/documents/${doc.id}/agent-tokens`, {
      headers: { Cookie: SESSION_COOKIE, 'Content-Type': 'application/json' },
      data: { name: 'list-test', ttl_hours: 1 }
    });
    expect(mintRes.status()).toBe(201);
    const minted = await mintRes.json();

    const listRes = await request.get(`/api/v1/documents/${doc.id}/agent-tokens`, {
      headers: { Cookie: SESSION_COOKIE }
    });
    expect(listRes.status()).toBe(200);
    const body = await listRes.json();
    const found = body.tokens.find((t: { id: string }) => t.id === minted.id);
    expect(found).toBeTruthy();
    expect(found.prefix).toBe(minted.prefix);
    expect(found.token).toBeUndefined(); // plaintext is never returned again
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
