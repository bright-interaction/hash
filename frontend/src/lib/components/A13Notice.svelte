<script lang="ts">
  import { ShieldCheck, Info, ExternalLink } from 'lucide-svelte';

  type Privacy = {
    controller: string;
    controller_contact: string;
    processor: string;
    processor_email: string;
    purpose_summary: string;
    legal_basis: string;
    retention_years: number;
    jurisdiction_dp: string;
    policy_url: string;
    dsr_endpoint: string;
	notice_digest: string;
    copy: {
      title: string;
      intro: string;
      controller_label: string;
      controller_contact_label: string;
      processor_label: string;
      purpose_label: string;
      legal_basis_label: string;
      retention_label: string;
      retention_value: string;
      authority_label: string;
      rights_summary: string;
      rights_body: string;
      submit_request_label: string;
      kind_label: string;
      dsr_access_label: string;
      dsr_rectification_label: string;
      dsr_erasure_label: string;
      dsr_restriction_label: string;
      dsr_portability_label: string;
      dsr_objection_label: string;
      note_label: string;
      note_placeholder: string;
      send_request_label: string;
      request_received: string;
      read_policy_label: string;
      acknowledgement_label: string;
      fine_print: string;
    };
  };

  type Props = {
    privacy: Privacy | null;
    /** Stable non-credential document+recipient+notice-version key. */
    storageKey: string;
	/** Fires after the user acknowledges the required disclosure. */
	onAcknowledged: () => void;
  };

  let { privacy, storageKey, onAcknowledged }: Props = $props();

  // Default to "not yet acknowledged" so the modal blocks until the
  // user picks one of the two actions. We check localStorage once on
  // mount; storage failures fall back to "show the notice" rather
  // than silently skipping it.
  let acknowledged = $state<boolean>(false);
  let showRequestForm = $state(false);
  let requestKind = $state('access');
  let requestNote = $state('');
  let requestStatus = $state<{ ok: boolean; message: string } | null>(null);
  let notifiedStorageKey = '';

  $effect(() => {
    try {
      acknowledged = typeof localStorage !== 'undefined' && Boolean(localStorage.getItem(storageKey));
    } catch {
      acknowledged = false;
    }
    // A restored acknowledgement is valid only because storageKey contains the
    // current server notice digest. Tell the parent so it can begin gated
    // response calls (including the evidence-producing view ping).
    if (acknowledged && notifiedStorageKey !== storageKey) {
      notifiedStorageKey = storageKey;
      onAcknowledged();
    }
  });

  function accept() {
    try {
	  localStorage.setItem(storageKey, 'acknowledged');
    } catch {
      // Storage disabled (Safari private mode etc.); proceed anyway,
      // worst case the user sees the banner again next visit.
    }
    acknowledged = true;
    notifiedStorageKey = storageKey;
	onAcknowledged();
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
        message: privacy.copy.request_received,
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
        <h2 id="a13-title">{privacy.copy.title}</h2>
      </header>

      <p class="a13-intro">{privacy.copy.intro}</p>

      <dl class="a13-facts">
        <div>
          <dt>{privacy.copy.controller_label}</dt>
          <dd>{privacy.controller}</dd>
        </div>
		<div>
		  <dt>{privacy.copy.controller_contact_label}</dt>
		  <dd>{privacy.controller_contact}</dd>
		</div>
        <div>
          <dt>{privacy.copy.processor_label}</dt>
          <dd>{privacy.processor} ({privacy.processor_email})</dd>
        </div>
        <div>
          <dt>{privacy.copy.purpose_label}</dt>
          <dd>{privacy.purpose_summary}</dd>
        </div>
        <div>
          <dt>{privacy.copy.legal_basis_label}</dt>
          <dd>{privacy.legal_basis}</dd>
        </div>
        <div>
          <dt>{privacy.copy.retention_label}</dt>
          <dd>{privacy.copy.retention_value}</dd>
        </div>
        <div>
          <dt>{privacy.copy.authority_label}</dt>
          <dd>{privacy.jurisdiction_dp}</dd>
        </div>
      </dl>

      <details class="a13-rights">
        <summary>
          <Info class="size-4" /> {privacy.copy.rights_summary}
        </summary>
        <p>{privacy.copy.rights_body}</p>
        {#if !showRequestForm}
          <button class="a13-link-btn" type="button" onclick={() => (showRequestForm = true)}
            >{privacy.copy.submit_request_label}</button
          >
        {/if}
        {#if showRequestForm}
          <div class="a13-dsr-form">
            <label>
              {privacy.copy.kind_label}
              <select bind:value={requestKind}>
                <option value="access">{privacy.copy.dsr_access_label}</option>
                <option value="rectification">{privacy.copy.dsr_rectification_label}</option>
                <option value="erasure">{privacy.copy.dsr_erasure_label}</option>
                <option value="restriction">{privacy.copy.dsr_restriction_label}</option>
                <option value="portability">{privacy.copy.dsr_portability_label}</option>
                <option value="objection">{privacy.copy.dsr_objection_label}</option>
              </select>
            </label>
            <label>
              {privacy.copy.note_label}
              <textarea bind:value={requestNote} rows={2} placeholder={privacy.copy.note_placeholder}></textarea>
            </label>
            <button type="button" class="a13-primary" onclick={submitDSR}>{privacy.copy.send_request_label}</button>
            {#if requestStatus}
              <p class="a13-status {requestStatus.ok ? 'ok' : 'err'}">{requestStatus.message}</p>
            {/if}
          </div>
        {/if}
      </details>

      <a class="a13-policy" href={privacy.policy_url} target="_blank" rel="noopener">
        {privacy.copy.read_policy_label} <ExternalLink class="size-3" />
      </a>

      <footer class="a13-actions">
		<button type="button" class="a13-primary" onclick={accept}>
          {privacy.copy.acknowledgement_label}
        </button>
      </footer>
      <p class="a13-fineprint">{privacy.copy.fine_print}</p>
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
  .a13-primary {
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
  .a13-fineprint {
    margin-top: 0.75rem;
    font-size: 0.7rem;
    color: #64748b;
    line-height: 1.4;
  }
</style>
