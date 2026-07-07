<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { createBlocksDocument, listDocuments, type DocumentResponse } from '$lib/api/client';
  import { FileText, Plus } from 'lucide-svelte';

  let docs = $state<DocumentResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let creating = $state(false);
  let newName = $state('');

  async function refresh() {
    loading = true;
    try {
      const res = await listDocuments();
      docs = res.documents;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  async function createBlank(e: Event) {
    e.preventDefault();
    if (!newName) return;
    creating = true;
    try {
      const d = await createBlocksDocument(newName);
      await goto(`/documents/${d.id}`);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      creating = false;
    }
  }
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Library</p>
    <h1 class="page-title">Documents</h1>
  </div>

  <form onsubmit={createBlank} class="card p-6 mb-8 flex gap-3 items-end">
    <div class="flex-1">
      <label class="block text-sm font-medium mb-1" for="doc-name">New document name</label>
      <input
        id="doc-name"
        type="text"
        bind:value={newName}
        required
        placeholder="Q3 NDA, Acme Corp"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
    </div>
    <button type="submit" class="btn btn-primary" disabled={creating}>
      <Plus class="size-4" /> {creating ? 'Creating…' : 'Create blank'}
    </button>
  </form>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if error}
    <div class="card p-6 text-danger">{error}</div>
  {:else if docs.length === 0}
    <div class="card p-12 text-center">
      <FileText class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">No documents yet</p>
    </div>
  {:else}
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Name</th>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="text-left px-4 py-3 font-medium">Source</th>
            <th class="text-left px-4 py-3 font-medium">Updated</th>
          </tr>
        </thead>
        <tbody>
          {#each docs as d (d.id)}
            <tr class="border-b border-border-light last:border-0 hover:bg-bg-hover cursor-pointer" onclick={() => goto(`/documents/${d.id}`)}>
              <td class="px-4 py-3">{d.name}</td>
              <td class="px-4 py-3 capitalize">{d.status}</td>
              <td class="px-4 py-3 capitalize">{d.source_kind}</td>
              <td class="px-4 py-3 text-text-muted">{new Date(d.updated_at).toLocaleString()}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
