<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getOrgAIProvider,
    setOrgAIProvider,
    deleteOrgAIProvider,
    type OrgAIProvider,
  } from '$lib/api/client';
  import { Bot, ShieldCheck, Trash2, TriangleAlert } from 'lucide-svelte';

  let cfg = $state<OrgAIProvider | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Form fields.
  let fProvider = $state('mistral');
  let fBaseURL = $state('');
  let fModel = $state('');
  let fKey = $state('');
  let fEnabled = $state(true);
  let saving = $state(false);
  let saved = $state(false);

  const PLACEHOLDERS: Record<string, { base: string; model: string }> = {
    mistral: { base: 'https://api.mistral.ai', model: 'mistral-large-latest' },
    anthropic: { base: 'https://api.anthropic.com', model: 'claude-sonnet-4-6' },
  };

  function hydrate(s: OrgAIProvider) {
    cfg = s;
    if (s.configured) {
      fProvider = s.provider || 'mistral';
      fBaseURL = s.base_url || '';
      fModel = s.model || '';
      fEnabled = s.enabled;
      fKey = ''; // never returned; blank means keep existing
    }
  }

  async function refresh() {
    loading = true;
    try {
      hydrate(await getOrgAIProvider());
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function save() {
    error = null;
    saved = false;
    if (!cfg?.configured && !fKey.trim()) {
      error = 'An API key is required to set up your own provider.';
      return;
    }
    saving = true;
    try {
      const res = await setOrgAIProvider({
        provider: fProvider,
        base_url: fBaseURL.trim(),
        model: fModel.trim(),
        api_key: fKey.trim(),
        enabled: fEnabled,
      });
      hydrate(res);
      saved = true;
      setTimeout(() => (saved = false), 3000);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  async function remove() {
    if (!confirm('Remove your AI provider? This org will fall back to the platform default.')) return;
    error = null;
    try {
      await deleteOrgAIProvider();
      fKey = '';
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }
</script>

<div class="px-6 py-10 max-w-3xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · AI</p>
    <h1 class="page-title">AI provider</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 leading-relaxed">
    Bring your own AI: route this org's risk analysis, clarification and
    negotiation calls to your own provider and key instead of the platform
    default. Your key is encrypted at rest and never shown again. Shield
    tokenization still applies, so personal data is masked before any prompt
    leaves the platform.
  </p>

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-4">
      {error}
    </div>
  {/if}

  {#if loading}
    <div class="card p-5">
      <div class="h-4 w-40 bg-bg-elevated rounded mb-3"></div>
      <div class="h-9 w-full bg-bg-elevated rounded mb-3"></div>
      <div class="h-9 w-full bg-bg-elevated rounded"></div>
    </div>
  {:else if cfg && !cfg.byoai_available}
    <div class="card p-5 border-l-4 border-warning">
      <h2 class="font-display font-extralight text-lg mb-1 flex items-center gap-2">
        <TriangleAlert class="size-4" /> Not available on this instance
      </h2>
      <p class="text-sm text-text-secondary leading-relaxed">
        This Hash instance has no AI key-encryption key configured, so a
        bring-your-own key cannot be stored securely. All AI calls use the
        platform default provider. Ask your operator to set
        <code class="font-mono text-xs">HASH_AI_SHIELD_KEY</code> to enable
        this.
      </p>
    </div>
  {:else if cfg}
    <section class="card p-5 mb-6">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display font-extralight text-lg flex items-center gap-2">
          <Bot class="size-4" />
          {cfg.configured ? 'Your provider' : 'Use your own provider'}
        </h2>
        {#if cfg.configured}
          <span
            class="text-xs font-mono px-2 py-0.5 rounded-full border {cfg.enabled
              ? 'text-success border-success'
              : 'text-text-muted border-border-light'}"
          >
            {cfg.enabled ? 'active' : 'disabled'}
          </span>
        {/if}
      </div>

      {#if !cfg.configured}
        <p class="text-sm text-text-muted mb-4">
          Currently using the platform default provider. Configure your own below.
        </p>
      {/if}

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
        <label class="flex flex-col gap-2 text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Provider</span>
          <select
            bind:value={fProvider}
            class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          >
            <option value="mistral">Mistral (EU)</option>
            <option value="anthropic">Anthropic</option>
          </select>
        </label>
        <label class="flex flex-col gap-2 text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Model</span>
          <input
            type="text"
            bind:value={fModel}
            placeholder={PLACEHOLDERS[fProvider]?.model}
            class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="flex flex-col gap-2 text-sm sm:col-span-2">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Base URL</span>
          <input
            type="text"
            bind:value={fBaseURL}
            placeholder={PLACEHOLDERS[fProvider]?.base}
            class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
          <span class="text-xs text-text-muted">
            Point at an EU-hosted endpoint to keep AI processing in-region.
          </span>
        </label>
        <label class="flex flex-col gap-2 text-sm sm:col-span-2">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">API key</span>
          <input
            type="password"
            bind:value={fKey}
            autocomplete="off"
            placeholder={cfg.configured
              ? `Keeping current key ending ...${cfg.key_last4 ?? ''}`
              : 'Paste your provider API key'}
            class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm font-mono"
          />
          <span class="text-xs text-text-muted">
            {cfg.configured
              ? 'Leave blank to keep the stored key. Stored encrypted; never shown again.'
              : 'Stored encrypted at rest; never shown again.'}
          </span>
        </label>
      </div>

      <label class="flex items-center gap-2 text-sm mb-4">
        <input type="checkbox" bind:checked={fEnabled} /> Route this org's AI calls to this provider
      </label>

      <div class="flex items-center gap-3">
        <button
          class="btn btn-primary active:scale-[0.98] transition-transform"
          onclick={save}
          disabled={saving}
        >
          {saving ? 'Saving...' : cfg.configured ? 'Save changes' : 'Save provider'}
        </button>
        {#if cfg.configured}
          <button class="btn btn-secondary" onclick={remove}>
            <Trash2 class="size-4" /> Remove
          </button>
        {/if}
        {#if saved}
          <span class="text-xs text-success flex items-center gap-1">
            <ShieldCheck class="size-3" /> Saved
          </span>
        {/if}
        {#if cfg.configured && cfg.updated_at}
          <span class="text-xs text-text-muted ml-auto">
            Updated {new Date(cfg.updated_at).toLocaleString()}
          </span>
        {/if}
      </div>
    </section>
  {/if}
</div>
