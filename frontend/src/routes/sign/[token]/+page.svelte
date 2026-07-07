<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { page } from '$app/stores';
  import { CheckCircle2, FileSignature, ShieldCheck, X } from 'lucide-svelte';
  import { startTelemetry } from '$lib/telemetry';
  import SignerFields from '$lib/components/SignerFields.svelte';
  import PdfSignerView from '$lib/components/PdfSignerView.svelte';
  import A13Notice from '$lib/components/A13Notice.svelte';
  import { t, locale, setLocale, initLocale, preferLocale, LOCALES, type Locale } from '$lib/i18n';

  type Privacy = {
    controller: string;
    processor: string;
    processor_email: string;
    purpose_summary: string;
    legal_basis: string;
    retention_years: number;
    jurisdiction_dp: string;
    policy_url: string;
    dsr_endpoint: string;
  };

  type Ctx = {
    document_id: string;
    document_name: string;
    status: string;
    source_kind: string;
    routing_tier?: string;
    qes_provider?: string;
    recipient: { id: string; email: string; name: string; role: string; status: string; locale: string };
    fonts: string[];
    privacy: Privacy;
  };

  let ctx = $state<Ctx | null>(null);
  let loadError = $state<string | null>(null);
  let documentHTML = $state<string>('');

  let typedName = $state('');
  let chosenFont = $state('Caveat');
  let showAdoptModal = $state(false);
  let signing = $state(false);
  let signError = $state<string | null>(null);
  let completed = $state<{ url: string | null } | null>(null);

  let showDeclineModal = $state(false);
  let declineReason = $state('');
  let declined = $state(false);

  let showChangesModal = $state(false);
  let changesMessage = $state('');
  let changesRequested = $state(false);

  // Inline annotation: the signer marks a span of text and proposes a change.
  let showAnno = $state(false);
  let annoQuote = $state('');
  let annoContext = $state('');
  let annoBlockId = $state('');
  let annoComment = $state('');
  let annoProposed = $state('');
  let annoTop = $state(0);
  let annoLeft = $state(0);
  let annoCount = $state(0);
  let annoError = $state<string | null>(null);

  // Comment thread (Q&A with the sender).
  type DocComment = { id: string; author_name: string; author_side: string; body: string; created_at: string };
  let comments = $state<DocComment[]>([]);
  let commentBody = $state('');
  let postingComment = $state(false);

  async function loadComments() {
    try {
      const res = await fetch(`/sign/${$page.params.token}/comments`);
      if (res.ok) comments = (await res.json()).comments ?? [];
    } catch {
      /* best effort */
    }
  }

  async function sendComment() {
    if (!commentBody.trim()) return;
    postingComment = true;
    try {
      const res = await fetch(`/sign/${$page.params.token}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ body: commentBody.trim() })
      });
      if (res.ok) {
        commentBody = '';
        await loadComments();
      }
    } finally {
      postingComment = false;
    }
  }

  function onDocMouseUp() {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return;
    const text = sel.toString().trim();
    if (!text) return;
    const node = sel.anchorNode;
    const startEl = node && node.nodeType === 3 ? node.parentElement : (node as Element | null);
    const blockEl = startEl?.closest('[data-block-id]') ?? null;
    if (!blockEl) return;
    annoBlockId = blockEl.getAttribute('data-block-id') ?? '';
    annoQuote = text;
    annoContext = (blockEl.textContent ?? '').trim().slice(0, 600);
    annoComment = '';
    annoProposed = '';
    annoError = null;
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    annoTop = Math.min(rect.bottom + 8, window.innerHeight - 280);
    annoLeft = Math.max(12, Math.min(rect.left, window.innerWidth - 360));
    showAnno = true;
  }

  async function submitAnno() {
    if (!annoComment.trim() && !annoProposed.trim()) {
      annoError = $t('changes.placeholder');
      return;
    }
    try {
      const res = await fetch(`/sign/${$page.params.token}/request-changes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: annoComment,
          block_id: annoBlockId,
          quote: annoQuote,
          context: annoContext,
          proposed: annoProposed
        })
      });
      if (!res.ok) {
        annoError = await res.text();
        return;
      }
      annoCount += 1;
      showAnno = false;
      window.getSelection()?.removeAllRanges();
    } catch (e) {
      annoError = (e as Error).message;
    }
  }

  // v1.2: fillable fields gate. Defaults true so docs without fields
  // still let the signer through immediately. SignerFields toggles this
  // to false while a required field is unfilled.
  let fieldsFilled = $state(true);

  $effect(() => {
    if (ctx?.recipient.name) typedName = ctx.recipient.name;
  });

  async function load() {
    const token = $page.params.token;
    try {
      const res = await fetch(`/sign/${token}`);
      if (!res.ok) {
        loadError = 'This link is invalid or has expired.';
        return;
      }
      ctx = await res.json();

      // Single-locale ceremony: render the whole signer experience (chrome,
      // the Article 13 notice, buttons) in the language the sender chose for
      // this recipient, so it can never mix with the browser language. The
      // server already emits the notice + document + emails in this locale;
      // preferLocale aligns the SPA store unless the visitor has manually
      // picked their own language (their toggle still wins on return).
      if (ctx?.recipient?.locale) preferLocale(ctx.recipient.locale, { force: true });

      // Reflect what this recipient has already done so a return visit (after
      // BankID/QES, or just reopening the link) never re-shows the signing
      // form. Download is offered once the whole document is completed; a
      // signer who signed while others are still pending sees the recorded
      // state without a premature download.
      const rs = ctx?.recipient.status;
      const docDone = ctx?.status === 'completed';
      if (rs === 'declined') {
        declined = true;
      } else if (rs === 'signed' || docDone) {
        completed = { url: docDone ? `/sign/${token}/final-pdf` : null };
      } else if (ctx?.status === 'changes_requested') {
        // A change request paused signing; show the pending state on return.
        changesRequested = true;
      }

      // Block-source documents render server-side HTML; pdf-source documents
      // render via pdf.js in PdfSignerView, so skip the HTML endpoint (it
      // refuses pdf-source).
      if (ctx?.source_kind === 'blocks') {
        const docRes = await fetch(`/sign/${token}/document`);
        if (docRes.ok) {
          documentHTML = await docRes.text();
        }
      }
      // Best-effort view ping (idempotent server-side).
      void fetch(`/sign/${token}/view`, { method: 'POST' });
      void loadComments();
    } catch (e) {
      loadError = (e as Error).message;
    }
  }

  let stopTelemetry: (() => void) | null = null;

  onMount(() => {
    initLocale();
    const token = $page.params.token;
    if (!token) {
      loadError = 'Missing sign token';
      return;
    }
    load();
    // Telemetry is gated on Article 13 consent; A13Notice fires
    // onAcknowledged below when the signer picks "continue with
    // analytics", which calls handleConsent(true).
  });

  function handleConsent(telemetry: boolean) {
    const token = $page.params.token;
    if (!telemetry || !token) return;
    try {
      stopTelemetry = startTelemetry(token);
    } catch {
      stopTelemetry = null;
    }
  }

  onDestroy(() => {
    stopTelemetry?.();
  });

  async function adopt() {
    if (!ctx) return;
    if (!typedName.trim()) {
      signError = 'Please type your name first.';
      return;
    }
    showAdoptModal = true;
  }

  async function confirmSign() {
    if (!ctx) return;
    signing = true;
    signError = null;
    try {
      const res = await fetch(`/sign/${$page.params.token}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ typed_name: typedName, font: chosenFont })
      });
      if (!res.ok) {
        signError = await res.text();
        return;
      }
      const body = await res.json();
      if (body.completed) {
        // Prefer the stable signer route over the ephemeral presigned URL so
        // the link keeps working if the signer reloads or returns later.
        completed = { url: `/sign/${$page.params.token}/final-pdf` };
      } else {
        // Other signers still pending.
        completed = { url: null };
      }
      showAdoptModal = false;
    } catch (e) {
      signError = (e as Error).message;
    } finally {
      signing = false;
    }
  }

  async function decline() {
    showDeclineModal = true;
  }

  async function confirmDecline() {
    if (!ctx) return;
    try {
      await fetch(`/sign/${$page.params.token}/decline`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: declineReason })
      });
      declined = true;
      showDeclineModal = false;
    } catch (e) {
      signError = (e as Error).message;
    }
  }

  function requestChanges() {
    showChangesModal = true;
  }

  async function confirmRequestChanges() {
    if (!ctx) return;
    if (!changesMessage.trim()) {
      signError = $t('changes.placeholder');
      return;
    }
    try {
      const res = await fetch(`/sign/${$page.params.token}/request-changes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: changesMessage })
      });
      if (!res.ok) {
        signError = await res.text();
        return;
      }
      changesRequested = true;
      showChangesModal = false;
    } catch (e) {
      signError = (e as Error).message;
    }
  }

  function fontFamilyFor(name: string): string {
    return `'${name}', cursive`;
  }

  let qesStarting = $state(false);
  let qesError = $state<string | null>(null);

  async function startQES() {
    if (!ctx) return;
    qesError = null;
    qesStarting = true;
    try {
      const res = await fetch(`/sign/${$page.params.token}/qes/start`, {
        method: 'POST'
      });
      if (!res.ok) {
        qesError = await res.text();
        return;
      }
      const body = await res.json() as { redirect_url: string; provider: string };
      // Send the signer's browser to the QTSP hosted UI. For the 'mock'
      // provider this redirects right back to /qes/callback/{session_id}?mock=1
      // so the flow completes without a real BankID round trip.
      window.location.href = body.redirect_url;
    } catch (e) {
      qesError = (e as Error).message;
    } finally {
      qesStarting = false;
    }
  }
</script>

<svelte:head>
  <link rel="stylesheet" href="/fonts/fonts.css" />
</svelte:head>

{#if ctx?.privacy}
  <A13Notice
    privacy={ctx.privacy}
    documentName={ctx.document_name}
    storageKey={`hash_signer_a13:${$page.params.token}`}
    onAcknowledged={handleConsent}
  />
{/if}

<div class="signer-page">
  <header class="signer-bar">
    <div class="brand">
      <FileSignature class="size-4" />
      <span>Hash</span>
    </div>
    <div class="bar-right">
      {#if ctx}
        <div class="meta">
          <span>{ctx.document_name}</span>
          <span class="dot">·</span>
          <span>{$t('sign.for', { name: ctx.recipient.name, role: ctx.recipient.role })}</span>
        </div>
      {/if}
      <select
        class="lang-select"
        aria-label="Language"
        value={$locale}
        onchange={(e) => setLocale((e.currentTarget as HTMLSelectElement).value as Locale)}
      >
        {#each LOCALES as l (l.code)}
          <option value={l.code}>{l.name}</option>
        {/each}
      </select>
    </div>
  </header>

  {#if loadError}
    <div class="banner banner-danger">{loadError}</div>
  {:else if !ctx}
    <p class="loading">{$t('common.loading')}</p>
  {:else if declined}
    <div class="state-card">
      <X class="size-10 text-danger mb-3 mx-auto" />
      <h2>{$t('sign.declined.title')}</h2>
      <p>{$t('sign.declined.body')}</p>
    </div>
  {:else if completed}
    <div class="state-card">
      <CheckCircle2 class="size-10 text-success mb-3 mx-auto" />
      <h2>{$t('sign.signed.title')}</h2>
      {#if completed.url}
        <p>{$t('sign.signed.allParties')}</p>
        <a class="btn btn-primary" href={completed.url} download>
          {$t('sign.signed.download')}
        </a>
      {:else}
        <p>{$t('sign.signed.recorded')}</p>
      {/if}
    </div>
  {:else if changesRequested}
    <div class="state-card">
      <CheckCircle2 class="size-10 text-info mb-3 mx-auto" />
      <h2>{$t('changes.requested.title')}</h2>
      <p>{$t('changes.requested.body')}</p>
    </div>
  {:else}
    <main class="signer-main">
      <article class="document-frame">
        {#if ctx.source_kind === 'pdf'}
          <PdfSignerView
            token={$page.params.token ?? ''}
            signed={!!completed}
            onFilledChange={(v) => (fieldsFilled = v)}
            onSignatureClick={adopt}
          />
        {:else}
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div class="doc-page" onmouseup={onDocMouseUp}>
            {@html documentHTML}
          </div>
        {/if}
      </article>

      <aside class="signer-actions">
        {#if ctx.routing_tier === 'QES'}
          <h3 class="section-eyebrow">{$t('sign.qes.title')}</h3>
          <p class="text-xs text-text-muted mb-3">
            {$t('sign.qes.body', { provider: ctx.qes_provider ?? 'Hash QES' })}
          </p>
          <button class="btn btn-primary w-full" disabled={qesStarting} onclick={startQES}>
            <ShieldCheck class="size-4" /> {$t('sign.qes.button')}
          </button>
          {#if qesError}
            <p class="text-danger text-xs mt-2">{qesError}</p>
          {/if}
          <button class="btn btn-secondary w-full" onclick={decline}>{$t('common.decline')}</button>
          <button class="btn btn-secondary w-full" onclick={requestChanges}>{$t('common.requestChanges')}</button>
        {:else}
        {#if ctx.source_kind !== 'pdf'}
          <SignerFields token={$page.params.token ?? ''} onChange={(v) => (fieldsFilled = v)} />
        {:else}
          <p class="text-xs text-text-muted mb-3">{$t('sign.pdf.fillHint')}</p>
        {/if}

        <p class="anno-hint">
          {$t('changes.markHint')}
          {#if annoCount > 0}<span class="anno-count">{annoCount}</span>{/if}
        </p>

        <h3 class="section-eyebrow">{$t('sign.yourName')}</h3>
        <input
          type="text"
          bind:value={typedName}
          placeholder={$t('sign.namePlaceholder')}
          class="name-input"
        />

        <button
          class="btn btn-primary w-full"
          disabled={!typedName.trim() || !fieldsFilled}
          onclick={adopt}
          title={!fieldsFilled ? $t('sign.fillRequiredTitle') : ''}
        >
          <FileSignature class="size-4" /> {$t('sign.adoptAndSign')}
        </button>
        {#if !fieldsFilled}
          <p class="text-xs text-text-muted mt-2">{$t('sign.saveRequired')}</p>
        {/if}

        <button class="btn btn-secondary w-full" onclick={decline}>{$t('common.decline')}</button>
        <button class="btn btn-secondary w-full" onclick={requestChanges}>{$t('common.requestChanges')}</button>
        {/if}

        <p class="legal-note">
          <ShieldCheck class="size-3 inline" />
          {$t('sign.legalNote')}
        </p>
        {#if signError}
          <p class="error">{signError}</p>
        {/if}

        <div class="comments">
          <h3 class="section-eyebrow">{$t('comments.title')}</h3>
          {#if comments.length}
            <ul class="comment-list">
              {#each comments as c (c.id)}
                <li class="comment-item {c.author_side === 'signer' ? 'mine' : ''}">
                  <span class="comment-meta">{c.author_name}</span>
                  <span class="comment-body">{c.body}</span>
                </li>
              {/each}
            </ul>
          {/if}
          <textarea
            bind:value={commentBody}
            rows="2"
            placeholder={$t('comments.placeholder')}
            class="comment-input"
          ></textarea>
          <button class="btn btn-secondary w-full" disabled={postingComment || !commentBody.trim()} onclick={sendComment}>
            {$t('comments.send')}
          </button>
        </div>
      </aside>
    </main>
  {/if}
</div>

{#if showAdoptModal && ctx}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('adopt.title')}</h3>
      <p class="modal-sub">{$t('adopt.sub')}</p>

      <div class="font-grid">
        {#each ctx.fonts as font (font)}
          <button
            class="font-option"
            class:selected={chosenFont === font}
            onclick={() => (chosenFont = font)}
            type="button"
          >
            <span class="font-preview" style="font-family: {fontFamilyFor(font)};">
              {typedName || ctx.recipient.name}
            </span>
            <span class="font-label">{font}</span>
          </button>
        {/each}
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showAdoptModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" disabled={signing} onclick={confirmSign}>
          {signing ? $t('adopt.signing') : $t('adopt.confirm')}
        </button>
      </div>
      {#if signError}
        <p class="error">{signError}</p>
      {/if}
    </div>
  </div>
{/if}

{#if showDeclineModal}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('decline.title')}</h3>
      <p class="modal-sub">{$t('decline.sub')}</p>
      <textarea
        bind:value={declineReason}
        rows="3"
        placeholder={$t('decline.reasonPlaceholder')}
        class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      ></textarea>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showDeclineModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" onclick={confirmDecline}>{$t('decline.confirm')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showChangesModal}
  <div class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal">
      <h3 class="modal-title">{$t('changes.title')}</h3>
      <p class="modal-sub">{$t('changes.sub')}</p>
      <textarea
        bind:value={changesMessage}
        rows="4"
        placeholder={$t('changes.placeholder')}
        class="w-full p-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      ></textarea>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick={() => (showChangesModal = false)}>{$t('common.cancel')}</button>
        <button class="btn btn-primary" onclick={confirmRequestChanges}>{$t('changes.confirm')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showAnno}
  <div class="anno-popup" style="top: {annoTop}px; left: {annoLeft}px;">
    <p class="anno-popup-label">{$t('changes.title')}</p>
    <p class="anno-popup-quote">{annoQuote}</p>
    <textarea
      bind:value={annoComment}
      rows="2"
      placeholder={$t('changes.placeholder')}
      class="anno-input"
    ></textarea>
    <input bind:value={annoProposed} placeholder={$t('changes.proposedPlaceholder')} class="anno-input anno-single" />
    <div class="anno-popup-actions">
      <button class="btn btn-secondary" onclick={() => (showAnno = false)}>{$t('common.cancel')}</button>
      <button class="btn btn-primary" onclick={submitAnno}>{$t('changes.confirm')}</button>
    </div>
    {#if annoError}<p class="error">{annoError}</p>{/if}
  </div>
{/if}

<style>
  .signer-page {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--t-bg);
  }
  .signer-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.25rem;
    background: var(--t-bg-surface);
    border-bottom: 1px solid var(--t-border-light);
    font-size: 13px;
  }
  .brand {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.05rem;
  }
  .meta {
    display: flex;
    gap: 0.5rem;
    color: var(--t-text-muted);
    font-size: 12px;
  }
  .dot { opacity: 0.5; }
  .bar-right { display: flex; align-items: center; gap: 1rem; }
  .lang-select {
    padding: 3px 8px;
    font-size: 12px;
    color: var(--t-text-secondary);
    background: var(--t-bg-elevated);
    border: 1px solid var(--t-border-light);
    border-radius: 6px;
    cursor: pointer;
  }
  .loading { padding: 3rem; text-align: center; color: var(--t-text-muted); }
  .signer-main {
    display: grid;
    grid-template-columns: 1fr 280px;
    gap: 1.25rem;
    padding: 1.5rem;
    flex: 1;
  }
  /* The document column sits on a soft gutter, like a Google-Docs canvas. */
  .document-frame {
    background: var(--t-bg);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 2rem 1.5rem;
    min-height: 70vh;
    overflow: auto;
  }
  /* A4 sheet (794px @ 96dpi) centered on the gutter with on-screen margins
     mirroring the printed 1in page margins. The injected document supplies
     its own typography (scoped under .hash-doc); we only frame the page. */
  .doc-page {
    width: 794px;
    max-width: 100%;
    margin: 0 auto;
    background: #ffffff;
    color: #18181b;
    padding: 72px 76px;
    border-radius: 4px;
    box-shadow:
      0 1px 2px rgba(24, 24, 27, 0.06),
      0 10px 30px rgba(24, 24, 27, 0.08);
  }
  .doc-page :global(.hash-doc) {
    max-width: none;
    margin: 0;
  }
  .signer-actions {
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    height: fit-content;
    position: sticky;
    top: 1rem;
  }
  .section-eyebrow {
    font-family: var(--font-mono);
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.2em;
    color: var(--t-text-muted);
    margin: 0;
  }
  .name-input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.375rem;
    background: var(--t-bg-elevated);
    font-size: 0.9rem;
  }
  .legal-note {
    font-size: 11px;
    color: var(--t-text-muted);
    line-height: 1.4;
    margin-top: 0.5rem;
  }
  .error {
    color: var(--t-danger);
    font-size: 12px;
    margin-top: 0.5rem;
  }
  .anno-hint {
    font-size: 11px;
    color: var(--t-text-muted);
    line-height: 1.4;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .anno-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--t-accent);
    color: var(--t-accent-foreground, #fff);
    font-size: 10px;
    font-weight: 600;
  }
  .anno-popup {
    position: fixed;
    z-index: 200;
    width: 340px;
    max-width: calc(100vw - 24px);
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.6rem;
    box-shadow: 0 16px 48px rgba(10, 10, 10, 0.28);
    padding: 0.85rem;
  }
  .anno-popup-label {
    font-family: var(--font-mono);
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.18em;
    color: var(--t-text-muted);
    margin: 0 0 0.4rem;
  }
  .anno-popup-quote {
    font-size: 12px;
    color: var(--t-text-primary);
    border-left: 3px solid var(--t-accent);
    padding: 0.2rem 0 0.2rem 0.6rem;
    margin: 0 0 0.5rem;
    max-height: 60px;
    overflow: auto;
  }
  .anno-input {
    width: 100%;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    background: var(--t-bg-elevated);
    font-size: 0.85rem;
    margin-bottom: 0.45rem;
    box-sizing: border-box;
  }
  .anno-popup-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }
  .comments {
    margin-top: 1rem;
    padding-top: 0.85rem;
    border-top: 1px solid var(--t-border-light);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .comment-list {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    max-height: 220px;
    overflow-y: auto;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .comment-item {
    background: var(--t-bg-elevated);
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    padding: 0.4rem 0.55rem;
    font-size: 0.8rem;
  }
  .comment-item.mine {
    border-color: var(--t-accent);
  }
  .comment-meta {
    display: block;
    font-size: 0.65rem;
    color: var(--t-text-muted);
    margin-bottom: 0.15rem;
  }
  .comment-body {
    white-space: pre-wrap;
    color: var(--t-text-primary);
  }
  .comment-input {
    width: 100%;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--t-border-light);
    border-radius: 0.4rem;
    background: var(--t-bg-elevated);
    font-size: 0.82rem;
    box-sizing: border-box;
  }
  .state-card {
    margin: 4rem auto;
    max-width: 480px;
    background: var(--t-bg-surface);
    border: 1px solid var(--t-border-light);
    border-radius: 0.75rem;
    padding: 2.5rem;
    text-align: center;
  }
  .state-card h2 {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.5rem;
    margin: 0 0 0.5rem;
  }
  .banner {
    margin: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 0.5rem;
    border: 1px solid var(--t-border-light);
  }
  .banner-danger {
    color: var(--t-danger);
    border-color: var(--t-danger);
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(10, 10, 10, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 1rem;
  }
  .modal {
    background: var(--t-bg-surface);
    border-radius: 1rem;
    padding: 1.5rem;
    max-width: 520px;
    width: 100%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
  }
  .modal-title {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 1.4rem;
    margin: 0 0 0.25rem;
  }
  .modal-sub {
    color: var(--t-text-muted);
    font-size: 13px;
    margin: 0 0 1rem;
  }
  .font-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
    margin: 1rem 0;
  }
  .font-option {
    background: var(--t-bg-elevated);
    border: 2px solid var(--t-border-light);
    border-radius: 0.5rem;
    padding: 1rem 0.75rem;
    cursor: pointer;
    text-align: center;
    transition: border-color 150ms ease, background 150ms ease;
  }
  .font-option:hover {
    background: var(--t-bg-hover);
  }
  .font-option.selected {
    border-color: var(--t-accent);
    background: var(--t-bg-surface);
  }
  .font-preview {
    display: block;
    font-size: 1.6rem;
    line-height: 1;
    margin-bottom: 0.5rem;
    color: var(--t-text-primary);
  }
  .font-label {
    display: block;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--t-text-muted);
  }
  .modal-actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 1rem;
  }
  @media (max-width: 768px) {
    .signer-main {
      grid-template-columns: 1fr;
    }
    .signer-actions {
      position: static;
    }
  }
</style>
