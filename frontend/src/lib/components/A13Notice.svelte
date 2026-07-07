<script lang="ts">
  import { ShieldCheck, Info, ExternalLink } from 'lucide-svelte';
  import { get } from 'svelte/store';
  import { t } from '$lib/i18n';

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

  type Props = {
    privacy: Privacy | null;
    documentName: string;
    /** Stable per-link key so the same signer doesn't see it twice. */
    storageKey: string;
    /** Fires after the user acknowledges; arg=true if they consented to telemetry. */
    onAcknowledged: (telemetry: boolean) => void;
  };

  let { privacy, documentName, storageKey, onAcknowledged }: Props = $props();

  // Default to "not yet acknowledged" so the modal blocks until the
  // user picks one of the two actions. We check localStorage once on
  // mount; storage failures fall back to "show the notice" rather
  // than silently skipping it.
  let acknowledged = $state<boolean>(false);
  let showRequestForm = $state(false);
  let requestKind = $state('access');
  let requestNote = $state('');
  let requestStatus = $state<{ ok: boolean; message: string } | null>(null);

  $effect(() => {
    try {
      if (typeof localStorage !== 'undefined' && localStorage.getItem(storageKey)) {
        acknowledged = true;
      }
    } catch {
      acknowledged = false;
    }
  });

  function accept(telemetry: boolean) {
    try {
      localStorage.setItem(storageKey, telemetry ? 'with-telemetry' : 'without-telemetry');
    } catch {
      // Storage disabled (Safari private mode etc.); proceed anyway,
      // worst case the user sees the banner again next visit.
    }
    acknowledged = true;
    onAcknowledged(telemetry);
  }

  async function submitDSR() {
    if (!privacy) return;
    requestStatus = null;
    try {
      const res = await fetch(privacy.dsr_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ kind: requestKind, note: requestNote }),
      });
      if (!res.ok) {
        const body = await res.text();
        requestStatus = { ok: false, message: body || `request failed (${res.status})` };
        return;
      }
      requestStatus = {
        ok: true,
        message: get(t)('a13.requestReceived'),
      };
      requestNote = '';
    } catch (e) {
      requestStatus = { ok: false, message: (e as Error).message };
    }
  }
</script>

{#if privacy && !acknowledged}
  <div
    class="a13-overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="a13-title"
  >
    <div class="a13-card">
      <header class="a13-header">
        <ShieldCheck class="size-5" />
        <h2 id="a13-title">{$t('a13.title')}</h2>
      </header>

      <p class="a13-intro">{$t('a13.intro', { document: documentName })}</p>

      <dl class="a13-facts">
        <div>
          <dt>{$t('a13.controller')}</dt>
          <dd>{privacy.controller}</dd>
        </div>
        <div>
          <dt>{$t('a13.processor')}</dt>
          <dd>{privacy.processor} ({privacy.processor_email})</dd>
        </div>
        <div>
          <dt>{$t('a13.purpose')}</dt>
          <dd>{privacy.purpose_summary}</dd>
        </div>
        <div>
          <dt>{$t('a13.legalBasis')}</dt>
          <dd>{privacy.legal_basis}</dd>
        </div>
        <div>
          <dt>{$t('a13.retention')}</dt>
          <dd>{$t('a13.retentionValue', { years: privacy.retention_years })}</dd>
        </div>
        <div>
          <dt>{$t('a13.authority')}</dt>
          <dd>{privacy.jurisdiction_dp}</dd>
        </div>
      </dl>

      <details class="a13-rights">
        <summary>
          <Info class="size-4" /> {$t('a13.rightsSummary')}
        </summary>
        <p>{$t('a13.rightsBody')}</p>
        {#if !showRequestForm}
          <button class="a13-link-btn" type="button" onclick={() => (showRequestForm = true)}
            >{$t('a13.submitRequest')}</button
          >
        {/if}
        {#if showRequestForm}
          <div class="a13-dsr-form">
            <label>
              {$t('a13.kindLabel')}
              <select bind:value={requestKind}>
                <option value="access">{$t('a13.dsr.access')} (Art. 15)</option>
                <option value="rectification">{$t('a13.dsr.rectification')} (Art. 16)</option>
                <option value="erasure">{$t('a13.dsr.erasure')} (Art. 17)</option>
                <option value="restriction">{$t('a13.dsr.restriction')} (Art. 18)</option>
                <option value="portability">{$t('a13.dsr.portability')} (Art. 20)</option>
                <option value="objection">{$t('a13.dsr.objection')} (Art. 21)</option>
              </select>
            </label>
            <label>
              {$t('a13.noteLabel')}
              <textarea bind:value={requestNote} rows={2} placeholder={$t('a13.notePlaceholder')}></textarea>
            </label>
            <button type="button" class="a13-primary" onclick={submitDSR}>{$t('a13.sendRequest')}</button>
            {#if requestStatus}
              <p class="a13-status {requestStatus.ok ? 'ok' : 'err'}">{requestStatus.message}</p>
            {/if}
          </div>
        {/if}
      </details>

      <a class="a13-policy" href={privacy.policy_url} target="_blank" rel="noopener">
        {$t('a13.readPolicy')} <ExternalLink class="size-3" />
      </a>

      <footer class="a13-actions">
        <button type="button" class="a13-secondary" onclick={() => accept(false)}>
          {$t('a13.continueWithout')}
        </button>
        <button type="button" class="a13-primary" onclick={() => accept(true)}>
          {$t('a13.continue')}
        </button>
      </footer>
      <p class="a13-fineprint">{$t('a13.fineprint')}</p>
    </div>
  </div>
{/if}

<style>
  .a13-overlay {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.55);
    backdrop-filter: blur(2px);
    z-index: 50;
    display: grid;
    place-items: center;
    padding: 1rem;
  }
  .a13-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 20px 50px rgba(15, 23, 42, 0.2);
    max-width: 540px;
    width: 100%;
    padding: 1.5rem 1.5rem 1.25rem;
    font-family: 'Inter', system-ui, sans-serif;
    color: #0f172a;
    max-height: 90vh;
    overflow-y: auto;
  }
  .a13-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
  }
  .a13-header h2 {
    margin: 0;
    font-size: 1.05rem;
    font-weight: 600;
  }
  .a13-intro {
    font-size: 0.9rem;
    line-height: 1.5;
    margin: 0 0 1rem;
    color: #334155;
  }
  .a13-facts {
    margin: 0 0 0.75rem;
    display: grid;
    gap: 0.5rem 1rem;
    grid-template-columns: 1fr;
    font-size: 0.85rem;
  }
  .a13-facts dt {
    font-weight: 600;
    color: #475569;
  }
  .a13-facts dd {
    margin: 0.15rem 0 0;
    color: #0f172a;
    line-height: 1.4;
  }
  .a13-rights {
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
  }
  .a13-rights summary {
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-weight: 500;
  }
  .a13-rights p {
    margin: 0.5rem 0;
    color: #334155;
  }
  .a13-link-btn {
    background: none;
    border: none;
    color: #2563eb;
    padding: 0;
    font: inherit;
    cursor: pointer;
    text-decoration: underline;
  }
  .a13-dsr-form {
    display: grid;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  .a13-dsr-form label {
    display: grid;
    gap: 0.2rem;
    font-size: 0.8rem;
    color: #475569;
  }
  .a13-dsr-form select,
  .a13-dsr-form textarea {
    font: inherit;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 0.35rem 0.5rem;
    background: white;
  }
  .a13-status.ok {
    color: #16a34a;
  }
  .a13-status.err {
    color: #dc2626;
  }
  .a13-policy {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    color: #2563eb;
    font-size: 0.85rem;
    text-decoration: none;
    margin-bottom: 1rem;
  }
  .a13-policy:hover {
    text-decoration: underline;
  }
  .a13-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 0.5rem;
  }
  .a13-primary,
  .a13-secondary {
    font: inherit;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    cursor: pointer;
    font-weight: 500;
  }
  .a13-primary {
    background: #0f172a;
    color: white;
  }
  .a13-primary:hover {
    background: #111c33;
  }
  .a13-secondary {
    background: white;
    color: #0f172a;
    border-color: #cbd5e1;
  }
  .a13-secondary:hover {
    background: #f8fafc;
  }
  .a13-fineprint {
    margin-top: 0.75rem;
    font-size: 0.7rem;
    color: #64748b;
    line-height: 1.4;
  }
</style>
