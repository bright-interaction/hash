<script lang="ts">
  import { onMount } from 'svelte';
  import { createAPIKey, deleteAPIKey, listAPIKeys, type APIKeyResponse } from '$lib/api/client';
  import { Copy, Key, Plus, Trash2 } from 'lucide-svelte';

  let keys = $state<APIKeyResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  let showCreate = $state(false);
  let newName = $state('');
  let scopes = $state<{ read: boolean; authoring: boolean; workflow: boolean }>({
    read: true, authoring: true, workflow: true
  });
  let creating = $state(false);
  let mintedPlaintext = $state<string | null>(null);

  async function refresh() {
    loading = true;
    try {
      const res = await listAPIKeys();
      keys = res.api_keys;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  async function create() {
    if (!newName.trim()) return;
    creating = true;
    error = null;
    try {
      const selected: string[] = [];
      if (scopes.read) selected.push('read');
      if (scopes.authoring) selected.push('write:authoring');
      if (scopes.workflow) selected.push('write:workflow');
      const res = await createAPIKey({ name: newName.trim(), scopes: selected });
      mintedPlaintext = res.plaintext ?? null;
      newName = '';
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      creating = false;
    }
  }

  async function revoke(id: string) {
    if (!confirm('Revoke this API key? This is permanent.')) return;
    try {
      await deleteAPIKey(id);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function copyPlaintext() {
    if (mintedPlaintext) navigator.clipboard.writeText(mintedPlaintext);
  }
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">Settings · Developer</p>
      <h1 class="page-title">API keys</h1>
    </div>
    <button class="btn btn-primary" onclick={() => (showCreate = true)}>
      <Plus class="size-4" /> Mint key
    </button>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Hash API keys authenticate the standalone e-signature endpoint at
    <code class="font-mono text-xs">/api/automation/v1/signature-requests</code> and, when your plan includes it,
    the MCP endpoint at <code class="font-mono text-xs">/mcp</code>. Automation signature requests require both
    <code class="font-mono text-xs">write:authoring</code> and <code class="font-mono text-xs">write:workflow</code>.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  {#if mintedPlaintext}
    <div class="card p-5 mb-6 border border-success">
      <p class="font-mono uppercase tracking-widest text-xs text-text-muted mb-2">New key, save now</p>
      <p class="text-sm mb-3">
        Hash only shows the full key once. Copy it before navigating away.
      </p>
      <div class="flex items-center gap-2">
        <code class="flex-1 p-2 bg-bg-elevated rounded font-mono text-xs break-all">{mintedPlaintext}</code>
        <button class="btn btn-secondary" onclick={copyPlaintext}>
          <Copy class="size-4" /> Copy
        </button>
      </div>
      <button class="btn btn-secondary mt-3" onclick={() => (mintedPlaintext = null)}>I saved it</button>
    </div>
  {/if}

  {#if showCreate}
    <div class="card p-5 mb-6">
      <h3 class="font-display font-extralight text-lg mb-3">Mint API key</h3>
      <input
        type="text"
        bind:value={newName}
        placeholder="Name (e.g. Reactor bridge)"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-4"
      />
      <div class="space-y-2 mb-4">
        <p class="text-xs text-text-muted font-mono uppercase tracking-widest">Scopes</p>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.read} />
          <span>read</span>
          <span class="text-text-muted text-xs">(list/get documents, templates, events)</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.authoring} />
          <span>write:authoring</span>
          <span class="text-text-muted text-xs">(create documents; required for automation)</span>
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={scopes.workflow} />
          <span>write:workflow</span>
          <span class="text-text-muted text-xs">(send documents; required for automation)</span>
        </label>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={create} disabled={creating || !newName.trim()}>
          {creating ? 'Minting…' : 'Mint key'}
        </button>
        <button class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if keys.length === 0}
    <div class="card p-12 text-center">
      <Key class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">No API keys yet</p>
      <p class="text-text-secondary text-sm mt-2">Mint your first key for automation or MCP access.</p>
    </div>
  {:else}
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Name</th>
            <th class="text-left px-4 py-3 font-medium">Prefix</th>
            <th class="text-left px-4 py-3 font-medium">Scopes</th>
            <th class="text-left px-4 py-3 font-medium">Last used</th>
            <th class="text-right px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each keys as k (k.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3">{k.name}</td>
              <td class="px-4 py-3 font-mono text-xs">mth_{k.key_prefix}_…</td>
              <td class="px-4 py-3">
                <div class="flex gap-1 flex-wrap">
                  {#each k.scopes as sc (sc)}
                    <span class="px-1.5 py-0.5 rounded bg-bg-elevated text-xs font-mono">{sc}</span>
                  {/each}
                </div>
              </td>
              <td class="px-4 py-3 text-text-muted text-xs">
                {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'never'}
              </td>
              <td class="px-4 py-3 text-right">
                <button class="text-danger hover:underline text-xs inline-flex items-center gap-1" onclick={() => revoke(k.id)}>
                  <Trash2 class="size-3" /> Revoke
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
