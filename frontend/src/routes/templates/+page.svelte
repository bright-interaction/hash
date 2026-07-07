<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    listTemplates,
    uploadPDFTemplate,
    createDocumentFromTemplate,
    createStarterTemplate,
    createBlocksTemplate,
    type TemplateResponse,
  } from '$lib/api/client';
  import { Upload, FileText, FilePlus, Sparkles, FileSignature } from 'lucide-svelte';

  let templates = $state<TemplateResponse[]>([]);
  let loading = $state(true);
  let uploading = $state(false);
  let error = $state<string | null>(null);
  let creatingId = $state<string | null>(null);
  let seeding = $state<string | null>(null);

  async function seedStarter() {
    seeding = 'starter';
    error = null;
    try {
      await createStarterTemplate('services-agreement-sv');
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = null;
    }
  }

  async function newBlankTemplate() {
    seeding = 'blank';
    error = null;
    try {
      await createBlocksTemplate(`Ny mall (${new Date().toLocaleDateString()})`);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = null;
    }
  }

  async function useTemplate(t: TemplateResponse) {
    creatingId = t.id;
    error = null;
    try {
      const doc = await createDocumentFromTemplate(
        `${t.name} (${new Date().toLocaleDateString()})`,
        t.id,
        t.source_kind,
      );
      await goto(`/documents/${doc.id}`);
    } catch (e) {
      error = (e as Error).message;
      creatingId = null;
    }
  }

  let fileInput: HTMLInputElement;
  let nameInput = $state('');

  async function refresh() {
    loading = true;
    try {
      const res = await listTemplates();
      templates = res.templates;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  async function onUpload(e: Event) {
    e.preventDefault();
    const file = fileInput.files?.[0];
    if (!file || !nameInput) return;
    uploading = true;
    error = null;
    try {
      await uploadPDFTemplate(nameInput, file);
      nameInput = '';
      fileInput.value = '';
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      uploading = false;
    }
  }
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Library</p>
    <h1 class="page-title">Templates</h1>
  </div>

  <div class="card p-6 mb-6">
    <h2 class="font-display font-extralight text-lg mb-1">Start from a ready template</h2>
    <p class="text-sm text-text-secondary mb-4 leading-relaxed">
      Seed a complete, reusable agreement (clauses, a services table and a timeline
      table, with {'{{placeholders}}'}). You can then edit it in any document and
      send it for signature.
    </p>
    <div class="flex flex-wrap gap-3">
      <button class="btn btn-primary" disabled={seeding !== null} onclick={seedStarter}>
        <FileSignature class="size-4" />
        {seeding === 'starter' ? 'Creating…' : 'Tjänsteavtal (svenska)'}
      </button>
      <button class="btn btn-secondary" disabled={seeding !== null} onclick={newBlankTemplate}>
        <Sparkles class="size-4" />
        {seeding === 'blank' ? 'Creating…' : 'Blank block template'}
      </button>
    </div>
  </div>

  <form onsubmit={onUpload} class="card p-6 mb-8 space-y-4">
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-name">Template name</label>
      <input
        id="tpl-name"
        type="text"
        bind:value={nameInput}
        required
        placeholder="Consulting Agreement v1"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
    </div>
    <div>
      <label class="block text-sm font-medium mb-1" for="tpl-file">PDF file</label>
      <input
        id="tpl-file"
        type="file"
        accept="application/pdf"
        bind:this={fileInput}
        required
        class="w-full text-sm"
      />
    </div>
    <button type="submit" class="btn btn-primary" disabled={uploading}>
      <Upload class="size-4" />
      {uploading ? 'Uploading…' : 'Upload PDF as template'}
    </button>
    {#if error}
      <p class="text-sm text-danger">{error}</p>
    {/if}
  </form>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if templates.length === 0}
    <div class="card p-12 text-center">
      <FileText class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">No templates yet</p>
      <p class="text-text-secondary text-sm mt-2">Upload your first PDF above.</p>
    </div>
  {:else}
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Name</th>
            <th class="text-left px-4 py-3 font-medium">Type</th>
            <th class="text-left px-4 py-3 font-medium">Version</th>
            <th class="text-left px-4 py-3 font-medium">Updated</th>
            <th class="text-right px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each templates as t (t.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3">{t.name}</td>
              <td class="px-4 py-3 capitalize">{t.source_kind}</td>
              <td class="px-4 py-3 text-text-muted">v{t.version}</td>
              <td class="px-4 py-3 text-text-muted">{new Date(t.updated_at).toLocaleString()}</td>
              <td class="px-4 py-3 text-right">
                <button
                  class="btn btn-secondary text-xs"
                  disabled={creatingId === t.id}
                  onclick={() => useTemplate(t)}
                >
                  <FilePlus class="size-3" />
                  {creatingId === t.id ? 'Creating…' : 'New document'}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
