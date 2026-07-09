<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import {
    getDocument,
    getMe,
    updateDocument,
    createBlocksTemplate,
    documentSignatureFields,
    listChangeRequests,
    reviseDocument,
    approveChangeRequest,
    denyChangeRequest,
    setChangeApprovalMode,
    listComments,
    postComment,
    previewURL,
    documentPdfURL,
    type DocumentResponse,
    type ChangeRequest,
    type DocComment,
  } from '$lib/api/client';
  import BlockEditor from '$lib/components/BlockEditor/Editor.svelte';
  import RiskPanel from '$lib/components/RiskPanel.svelte';
  import AgentTokensPanel from '$lib/components/AgentTokensPanel.svelte';
  import EnvelopePanel from '$lib/components/EnvelopePanel.svelte';
  import SenderPanel from '$lib/components/SenderPanel.svelte';
  import TimelinePanel from '$lib/components/TimelinePanel.svelte';
  import PdfFieldDesigner from '$lib/components/PdfFieldDesigner.svelte';
  import { ArrowLeft, Eye, Sparkles, Save } from 'lucide-svelte';

  let doc = $state<DocumentResponse | null>(null);
  let userName = $state('You');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let showPreview = $state(false);
  let savingTemplate = $state(false);
  let savedTemplateFlash = $state(false);
  let changeRequests = $state<ChangeRequest[]>([]);
  let revising = $state(false);
  let approvalMode = $state<'accept' | 'auto_apply'>('accept');
  let resolvingId = $state<string | null>(null);
  let comments = $state<DocComment[]>([]);
  let commentBody = $state('');
  let postingComment = $state(false);
  let savingMode = $state(false);

  async function toggleSignatureMode() {
    if (!doc) return;
    savingMode = true;
    error = null;
    try {
      doc = await updateDocument(doc.id, { requires_signature: !doc.requires_signature });
    } catch (e) {
      error = (e as Error).message;
    } finally {
      savingMode = false;
    }
  }

  async function loadComments(id: string) {
    try {
      const res = await listComments(id);
      comments = res.comments;
    } catch {
      comments = [];
    }
  }

  async function sendComment() {
    if (!doc || !commentBody.trim()) return;
    postingComment = true;
    error = null;
    try {
      await postComment(doc.id, commentBody.trim());
      commentBody = '';
      await loadComments(doc.id);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      postingComment = false;
    }
  }

  async function loadChangeRequests(id: string) {
    try {
      const res = await listChangeRequests(id);
      changeRequests = res.change_requests;
    } catch {
      changeRequests = [];
    }
  }

  async function resolveCr(cr: ChangeRequest, approve: boolean) {
    if (!doc) return;
    resolvingId = cr.id;
    error = null;
    try {
      if (approve) await approveChangeRequest(doc.id, cr.id);
      else await denyChangeRequest(doc.id, cr.id);
      await loadChangeRequests(doc.id);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      resolvingId = null;
    }
  }

  async function changeApprovalMode(mode: 'accept' | 'auto_apply') {
    approvalMode = mode;
    try {
      await setChangeApprovalMode(mode);
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function revise() {
    if (!doc) return;
    revising = true;
    error = null;
    try {
      const updated = await reviseDocument(doc.id);
      doc = updated;
      changeRequests = [];
      showPreview = false; // back to the editor so the sender can make the changes
    } catch (e) {
      error = (e as Error).message;
    } finally {
      revising = false;
    }
  }

  async function saveAsTemplate() {
    if (!doc) return;
    const name = window.prompt('Template name?', `${doc.name} (mall)`);
    if (!name) return;
    savingTemplate = true;
    error = null;
    try {
      await createBlocksTemplate(name, {
        blocks_json: doc.blocks_json,
        variables_json: doc.variables_json,
      });
      savedTemplateFlash = true;
      setTimeout(() => (savedTemplateFlash = false), 3000);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      savingTemplate = false;
    }
  }

  onMount(async () => {
    const id = $page.params.id;
    if (!id) {
      error = 'Missing document id';
      loading = false;
      return;
    }
    try {
      const [d, me] = await Promise.all([getDocument(id), getMe().catch(() => null)]);
      doc = d;
      // A draft opens in the editor; anything already sent opens read-only so
      // the sender reviews the frozen content rather than appearing to edit it.
      showPreview = d.status !== 'draft';
      if (d.status === 'changes_requested') {
        void loadChangeRequests(d.id);
      }
      if (d.status !== 'draft') {
        void loadComments(d.id);
      }
      if (me?.email) {
        userName = me.email.split('@')[0] || me.email;
      }
      if (me?.change_approval_mode === 'auto_apply' || me?.change_approval_mode === 'accept') {
        approvalMode = me.change_approval_mode;
      }
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  });
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <a class="text-sm text-text-secondary hover:underline inline-flex items-center gap-1 mb-4" href="/documents">
    <ArrowLeft class="size-3" /> Back to documents
  </a>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if error}
    <div class="card p-6 text-danger">{error}</div>
  {:else if doc}
    <div class="mb-6 space-y-2">
      <p class="page-eyebrow">Document · {doc.status}</p>
      <div class="flex items-baseline justify-between gap-4">
        <h1 class="page-title">{doc.name}</h1>
        <div class="flex gap-2">
          <button class="btn btn-secondary" onclick={() => (showPreview = !showPreview)}>
            <Eye class="size-4" /> {showPreview ? 'Edit' : 'Preview'}
          </button>
          {#if doc.source_kind === 'blocks'}
            <button class="btn btn-secondary" disabled={savingTemplate} onclick={saveAsTemplate}>
              <Save class="size-4" /> {savedTemplateFlash ? 'Saved!' : savingTemplate ? 'Saving…' : 'Save as template'}
            </button>
          {/if}
          <a class="btn btn-secondary" href="/settings/api-keys">
            <Sparkles class="size-4" /> Attach AI
          </a>
        </div>
      </div>
    </div>

    {#if doc.status === 'draft'}
      <div class="card p-4 mb-6 flex items-center justify-between gap-4">
        <div>
          <p class="text-sm font-medium">Signeringsläge</p>
          <p class="text-xs text-text-muted">
            {doc.requires_signature
              ? 'Kräver signatur: mottagarna signerar dokumentet.'
              : 'Bara läsa och acceptera: mottagarna öppnar och klickar Acceptera. Ingen signatur.'}
          </p>
        </div>
        <button class="btn btn-secondary whitespace-nowrap" disabled={savingMode} onclick={toggleSignatureMode}>
          {savingMode ? 'Sparar…' : doc.requires_signature ? 'Byt till acceptera' : 'Kräv signatur'}
        </button>
      </div>
    {/if}

    {#if doc.status === 'changes_requested'}
      <div class="card p-5 mb-6 border-l-4 border-warning">
        <h2 class="font-display font-extralight text-lg mb-1">Ändringar begärda</h2>
        <p class="text-sm text-text-secondary mb-3 leading-relaxed">
          En part har begärt ändringar. Signering är pausad. Revidera dokumentet,
          gör ändringarna och skicka det för signering igen.
        </p>
        <div class="flex flex-wrap items-center gap-2 mb-4 text-xs">
          <span class="uppercase tracking-widest text-text-muted font-mono">Vid godkännande</span>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'accept' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('accept')}
          >Markera godkänd (ändra vid revidering)</button>
          <button
            class="px-2 py-1 rounded-md border {approvalMode === 'auto_apply' ? 'border-accent text-accent' : 'border-border-light text-text-muted'}"
            onclick={() => changeApprovalMode('auto_apply')}
          >Tillämpa föreslagen text automatiskt</button>
          <span class="text-text-muted">(global inställning)</span>
        </div>

        {#if changeRequests.length}
          <ul class="space-y-3 mb-4">
            {#each changeRequests as cr (cr.id)}
              <li class="rounded-md border border-border-light bg-bg-elevated p-3">
                <p class="text-xs text-text-muted mb-1">
                  {cr.recipient_name || 'Mottagare'}{cr.recipient_email ? ` · ${cr.recipient_email}` : ''}
                  · {new Date(cr.created_at).toLocaleString()}
                  {#if cr.resolution === 'approved'}· <span class="text-success">godkänd</span>{:else if cr.resolution === 'denied'}· <span class="text-danger">nekad</span>{/if}
                </p>
                {#if cr.quote}
                  <p class="text-sm border-l-2 border-accent pl-2 mb-1"><span class="text-text-muted text-xs">Markerat: </span>{cr.quote}</p>
                {/if}
                {#if cr.message}<p class="text-sm whitespace-pre-wrap mb-1">{cr.message}</p>{/if}
                {#if cr.proposed}<p class="text-sm text-success"><span class="text-text-muted text-xs">Föreslår: </span>{cr.proposed}</p>{/if}
                {#if cr.status === 'open'}
                  <div class="flex gap-2 mt-2">
                    <button class="btn btn-primary text-xs" disabled={resolvingId === cr.id} onclick={() => resolveCr(cr, true)}>Godkänn</button>
                    <button class="btn btn-secondary text-xs" disabled={resolvingId === cr.id} onclick={() => resolveCr(cr, false)}>Neka</button>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
        <button class="btn btn-primary" disabled={revising} onclick={revise}>
          {revising ? 'Reviderar…' : 'Revidera och redigera'}
        </button>
      </div>
    {/if}

    {#if showPreview}
      <iframe
        title="preview"
        src={doc.source_kind === 'pdf' ? documentPdfURL(doc.id) : previewURL(doc.id)}
        class="w-full h-[80vh] card"
      ></iframe>
    {:else if doc.source_kind === 'blocks'}
      <BlockEditor document={doc} onChange={(d) => (doc = d)} {userName} />
    {:else}
      <PdfFieldDesigner documentID={doc.id} />
    {/if}

    <div class="mt-8">
      <SenderPanel
        documentID={doc.id}
        status={doc.status}
        defaultLocale={doc.default_locale}
        signatureFields={doc.source_kind === 'blocks' ? documentSignatureFields(doc) : []}
        onStatusChange={(next) => {
          if (doc) doc = { ...doc, status: next };
        }}
        onDefaultLocaleChange={async (locale) => {
          if (!doc) return;
          const updated = await updateDocument(doc.id, { default_locale: locale });
          doc = updated;
        }}
      />
      {#if doc.status !== 'draft'}
        <section class="card p-5 mb-6">
          <h2 class="font-display font-extralight text-lg mb-1">Kommentarer</h2>
          <p class="text-sm text-text-secondary mb-4 leading-relaxed">
            Ställ och besvara frågor med motparten. Varje inlägg mejlas till den andra parten.
          </p>
          {#if comments.length}
            <ul class="space-y-3 mb-4">
              {#each comments as c (c.id)}
                <li class="rounded-md border border-border-light p-3 {c.author_side === 'sender' ? 'bg-bg-elevated' : ''}">
                  <p class="text-xs text-text-muted mb-1">
                    {c.author_name}
                    <span class="uppercase tracking-wide">· {c.author_side === 'sender' ? 'vi' : 'motpart'}</span>
                    · {new Date(c.created_at).toLocaleString()}
                  </p>
                  <p class="text-sm whitespace-pre-wrap">{c.body}</p>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="text-text-muted text-sm mb-4">Inga kommentarer än.</p>
          {/if}
          <textarea
            bind:value={commentBody}
            rows="2"
            placeholder="Skriv en kommentar…"
            class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-2"
          ></textarea>
          <button class="btn btn-primary" disabled={postingComment || !commentBody.trim()} onclick={sendComment}>
            {postingComment ? 'Skickar…' : 'Skicka kommentar'}
          </button>
        </section>
      {/if}
      <RiskPanel documentID={doc.id} />
      <EnvelopePanel documentID={doc.id} isEnvelope={!!doc.is_envelope} />
      <TimelinePanel documentID={doc.id} />
      <AgentTokensPanel documentID={doc.id} />
    </div>
  {/if}
</div>
