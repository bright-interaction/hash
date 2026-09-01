import { test, expect, type APIRequestContext } from '@playwright/test';

const API_KEY =
  process.env.HASH_E2E_API_KEY ||
  'mth_deadbeef_TESTKEYFORINTEGRATIONTESTINGONLY12345AAAAAAA';

// Phase 8.1: document versioning + diff engine. Every state-changing edit
// snapshots a new version. Agents see the same history humans see in the
// timeline UI (Phase 8.8) so the negotiation copilot (Phase 11.2) can ground
// counter-clause suggestions in the actual change history.

test.describe('document versioning (Phase 8.1)', () => {
  test('tools/list contains the version tools', async ({ request }) => {
    const res = await rpcRaw(request, 'tools/list', {});
    const names = res.result.tools.map((t: { name: string }) => t.name);
    for (const required of [
      'list_document_versions',
      'diff_document_versions',
      'restore_document_version'
    ]) {
      expect(names).toContain(required);
    }
  });

  test('every authoring edit produces a new version', async ({ request }) => {
    // Step 1: create. The handler snapshots one initial version after
    // create_document because the create itself is a write.
    const doc = await tool(request, 'create_document', {
      name: `Versioning E2E ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'h', type: 'heading', attrs: { level: 1 }, text: 'Initial' }]
      }
    });

    // Step 2: edit the title. Snapshot v2.
    await tool(request, 'set_document_blocks', {
      document_id: doc.id,
      blocks_json: {
        version: 1,
        blocks: [{ id: 'h', type: 'heading', attrs: { level: 1 }, text: 'After first edit' }]
      }
    });

    // Step 3: append a paragraph. Snapshot v3.
    await tool(request, 'append_block', {
      document_id: doc.id,
      block: { id: 'p', type: 'paragraph', text: 'A new clause.' }
    });

    const list = await tool(request, 'list_document_versions', { document_id: doc.id });
    expect(list.count).toBeGreaterThanOrEqual(3);
    expect(list.versions[0].version_no).toBeGreaterThan(list.versions[1].version_no);

    // Latest version's blocks_json reflects the appended paragraph.
    const latest = list.versions[0];
    const latestTree = latest.blocks_json;
    expect(latestTree.blocks.some((b: { id: string }) => b.id === 'p')).toBe(true);
  });

  test('diff between v1 and latest captures the changes', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Diff E2E ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [
          { id: 'h', type: 'heading', attrs: { level: 1 }, text: 'Title' },
          { id: 'p1', type: 'paragraph', text: 'Original wording.' }
        ]
      }
    });

    // Modify p1; add p2; remove nothing.
    await tool(request, 'update_block', {
      document_id: doc.id,
      block_id: 'p1',
      block: { id: 'p1', type: 'paragraph', text: 'Edited wording.' }
    });
    await tool(request, 'append_block', {
      document_id: doc.id,
      block: { id: 'p2', type: 'paragraph', text: 'Brand new clause.' }
    });

    // Default diff (no args) compares latest-1 vs latest, which is the
    // most recent change in isolation. Use explicit from=1 to get the
    // full delta from the initial state.
    const diff = await tool(request, 'diff_document_versions', {
      document_id: doc.id,
      from: 1
    });
    expect(diff.changes.length).toBeGreaterThan(0);
    const kinds = diff.changes.map((c: { kind: string }) => c.kind);
    expect(kinds).toContain('modified');
    expect(kinds).toContain('added');

    const counts = diff.counts;
    expect(counts.added).toBeGreaterThanOrEqual(1);
    expect(counts.modified).toBeGreaterThanOrEqual(1);
  });

  test('restore_document_version brings back historical content', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: `Restore E2E ${Date.now()}`,
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 'p', type: 'paragraph', text: 'Original.' }]
      }
    });

    // Make a destructive edit.
    await tool(request, 'update_block', {
      document_id: doc.id,
      block_id: 'p',
      block: { id: 'p', type: 'paragraph', text: 'Replaced.' }
    });

    // Restore to v1 (the very first snapshot).
    const restored = await tool(request, 'restore_document_version', {
      document_id: doc.id,
      target_version: 1
    });
    expect(restored.restored_from_v).toBe(1);

    // Latest version now has v1's content but is a NEW version_no
    // because Restore snapshots the action.
    const list = await tool(request, 'list_document_versions', { document_id: doc.id });
    const latest = list.versions[0];
    expect(latest.created_via).toBe('restore');
    const tree = latest.blocks_json;
    expect(tree.blocks[0].text).toBe('Original.');
  });

  test('restore refuses on non-draft documents', async ({ request }) => {
    const doc = await tool(request, 'create_document', {
      name: 'Restore guard',
      source_kind: 'blocks',
      blocks_json: {
        version: 1,
        blocks: [{ id: 's', type: 'signature_field', attrs: { recipient_role: 'signer' } }]
      }
    });
    // Reach a non-draft through the supported lifecycle; draft -> voided is
    // intentionally rejected by the production state machine.
    await tool(request, 'add_recipient', {
      document_id: doc.id,
      role: 'signer',
      email: `restore-guard-${Date.now()}@example.com`,
      name: 'Restore Guard'
    });
    await tool(request, 'send_document', { document_id: doc.id, lawful_basis: 'contract' });
    const res = await rpcRaw(request, 'tools/call', {
      name: 'restore_document_version',
      arguments: { document_id: doc.id, target_version: 1 }
    });
    expect(res.result.isError).toBe(true);
    expect(res.result.content[0].text).toMatch(/draft|status/i);
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
