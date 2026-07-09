<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    createBlocksDocument,
    importProposalPDF,
    importProposalHTML,
    listDocuments,
    type DocumentResponse,
  } from '$lib/api/client';
  import { FileText, Plus, Upload, PenLine } from 'lucide-svelte';

  let docs = $state<DocumentResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let creating = $state(false);
  let newName = $state('');

  // Import a signable proposal (PDF upload or a designed HTML page).
  let importKind = $state<'pdf' | 'html'>('pdf');
  let importName = $state('');
  let pdfFile = $state<File | null>(null);
  let htmlFile = $state<File | null>(null);
  let landscape = $state(false);
  let importing = $state(false);

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

  async function importProposal(e: Event) {
    e.preventDefault();
    if (!importName) return;
    error = null;
    importing = true;
    try {
      let out;
      if (importKind === 'pdf') {
        if (!pdfFile) {
          error = 'Choose a PDF file to upload.';
          return;
        }
        out = await importProposalPDF(importName, pdfFile);
      } else {
        if (!htmlFile) {
          error = 'Choose an HTML file to render.';
          return;
        }
        const html = await htmlFile.text();
        out = await importProposalHTML(importName, html, landscape);
      }
      await goto(`/documents/${out.document.id}`);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      importing = false;
    }
  }
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Library</p>
    <h1 class="page-title">Documents</h1>
  </div>

  <form onsubmit={createBlank} class="card p-6 mb-4 flex gap-3 items-end">
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

  <!-- Import a signable proposal: an existing PDF, or a designed HTML page
       rendered to PDF. Both land in the field designer to place signatures. -->
  <form onsubmit={importProposal} class="card p-6 mb-8 space-y-4">
    <div class="space-y-1">
      <p class="font-medium text-sm">Import a signable proposal</p>
      <p class="text-text-muted text-sm">
        Turn a finished PDF or a designed page into a document you can drop signature fields onto and send.
      </p>
    </div>

    <div class="inline-flex rounded-md border border-border-light overflow-hidden text-sm">
      <button
        type="button"
        class="px-3 py-1.5 flex items-center gap-1.5 {importKind === 'pdf' ? 'bg-bg-hover font-medium' : 'text-text-muted'}"
        onclick={() => (importKind = 'pdf')}
      >
        <Upload class="size-4" /> PDF file
      </button>
      <button
        type="button"
        class="px-3 py-1.5 flex items-center gap-1.5 border-l border-border-light {importKind === 'html' ? 'bg-bg-hover font-medium' : 'text-text-muted'}"
        onclick={() => (importKind = 'html')}
      >
        <PenLine class="size-4" /> Designed page (HTML)
      </button>
    </div>

    <div class="flex flex-col sm:flex-row gap-3 sm:items-end">
      <div class="flex-1">
        <label class="block text-sm font-medium mb-1" for="import-name">Document name</label>
        <input
          id="import-name"
          type="text"
          bind:value={importName}
          placeholder="Proposal, Acme Corp"
          class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </div>

      {#if importKind === 'pdf'}
        <div class="flex-1">
          <label class="block text-sm font-medium mb-1" for="import-pdf">PDF file</label>
          <input
            id="import-pdf"
            type="file"
            accept="application/pdf,.pdf"
            onchange={(e) => (pdfFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
            class="w-full text-sm"
          />
        </div>
      {:else}
        <div class="flex-1">
          <label class="block text-sm font-medium mb-1" for="import-html">HTML file</label>
          <input
            id="import-html"
            type="file"
            accept="text/html,.html,.htm"
            onchange={(e) => (htmlFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
            class="w-full text-sm"
          />
        </div>
        <label class="flex items-center gap-2 text-sm pb-2 whitespace-nowrap">
          <input type="checkbox" bind:checked={landscape} /> Landscape
        </label>
      {/if}

      <button type="submit" class="btn btn-primary whitespace-nowrap" disabled={importing}>
        <FileText class="size-4" /> {importing ? 'Preparing…' : 'Import & place fields'}
      </button>
    </div>
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
