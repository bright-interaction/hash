<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listDocAgentTokens,
    mintDocAgentToken,
    revokeDocAgentToken,
    type DocAgentToken,
  } from '$lib/api/client';
  import { KeyRound, Plus, Trash2, Copy } from 'lucide-svelte';

  type Props = {
    documentID: string;
  };

  let { documentID }: Props = $props();

  let tokens = $state<DocAgentToken[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  let showCreate = $state(false);
  let scopes = $state({ read: true, write: false, sign: false });
  let ttlDays = $state(30);
  let minting = $state(false);
  let revealed = $state<{ token: string; prefix: string } | null>(null);
  let copied = $state(false);

  async function refresh() {
    loading = true;
    try {
      const res = await listDocAgentTokens(documentID);
      tokens = res.tokens ?? [];
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function mint() {
    minting = true;
    error = null;
    try {
      const scopeList: string[] = [];
      if (scopes.read) scopeList.push('read');
      if (scopes.write) scopeList.push('write:authoring');
      if (scopes.sign) scopeList.push('write:workflow');
      const t = await mintDocAgentToken(documentID, scopeList, ttlDays);
      if (t.token) {
        revealed = { token: t.token, prefix: t.prefix };
        copied = false;
      }
      showCreate = false;
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      minting = false;
    }
  }

  async function revoke(id: string) {
    if (!confirm('Revoke this token? Any in-flight agent call using it will fail with 401.')) return;
    try {
      await revokeDocAgentToken(id);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <KeyRound class="size-4" /> Per-document agent tokens
    </h2>
    <button class="btn btn-primary text-xs" onclick={() => (showCreate = true)} disabled={minting}>
      <Plus class="size-3" /> Mint token
    </button>
  </div>

  <p class="text-sm text-text-secondary mb-4 leading-relaxed">
    Doc-scoped tokens authenticate an agent to this specific document
    only. A token minted here cannot read or mutate any sibling
    document even within the same org.
  </p>

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">{error}</div>
  {/if}

  {#if revealed}
    <div class="card p-4 mb-4 border-l-4 border-warning">
      <h3 class="font-display font-extralight text-base mb-2">Copy this token now</h3>
      <p class="text-xs text-text-secondary mb-3 leading-relaxed">
        Hash stores only a hash. If you lose this string you must
        mint a new token; we cannot reveal it again.
      </p>
      <div class="flex gap-2 items-center">
        <code class="font-mono text-xs bg-bg-elevated border border-border-light rounded px-3 py-2 flex-1 break-all"
          >{revealed.token}</code
        >
        <button
          type="button"
          class="btn btn-secondary text-xs"
          onclick={async () => {
            try {
              await navigator.clipboard.writeText(revealed!.token);
              copied = true;
            } catch {
              copied = false;
            }
          }}
        >
          <Copy class="size-3" /> {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" class="btn btn-secondary text-xs" onclick={() => (revealed = null)}>Dismiss</button>
      </div>
    </div>
  {/if}

  {#if showCreate}
    <div class="card p-4 mb-4">
      <h3 class="font-display font-extralight text-base mb-3">New token</h3>
      <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-2">Scopes</p>
      <div class="flex flex-wrap gap-3 text-sm mb-4">
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={scopes.read} /> read
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={scopes.write} /> write:authoring
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={scopes.sign} /> write:workflow
        </label>
      </div>
      <label class="block text-sm mb-4">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">TTL (days, max 90)</span>
        <input type="number" min="1" max="90" bind:value={ttlDays} class="block px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm w-24" />
      </label>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={mint} disabled={minting}>
          {minting ? 'Minting...' : 'Mint'}
        </button>
        <button class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted text-sm">Loading...</p>
  {:else if tokens.length === 0}
    <p class="text-text-muted text-sm">No tokens minted yet.</p>
  {:else}
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
          <th class="py-2">Prefix</th>
          <th>Scopes</th>
          <th>Uses</th>
          <th>Expires</th>
          <th class="text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-border-light">
        {#each tokens as t (t.id)}
          <tr>
            <td class="py-2 font-mono text-xs">{t.prefix}</td>
            <td class="text-xs">{(t.scopes || []).join(', ')}</td>
            <td class="font-mono text-xs">{t.used_count}</td>
            <td class="text-xs text-text-muted">
              {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'never'}
            </td>
            <td class="text-right">
              <button class="btn btn-secondary text-xs" onclick={() => revoke(t.id)}>
                <Trash2 class="size-3" />
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>
