<script lang="ts">
  import { runRiskAnalysis, type RiskAnalyzeResult, type RiskFinding } from '$lib/api/client';
  import { ShieldAlert, Sparkles, Globe, ChevronDown, ChevronUp } from 'lucide-svelte';

  type Props = {
    documentID: string;
  };

  let { documentID }: Props = $props();

  let running = $state(false);
  let error = $state<string | null>(null);
  let result = $state<RiskAnalyzeResult | null>(null);
  let locale = $state('en');
  let senderContext = $state('');
  let expanded = $state<Record<string, boolean>>({});
  let dismissed = $state<Record<string, boolean>>({});

  async function analyze() {
    running = true;
    error = null;
    try {
      result = await runRiskAnalysis(documentID, { locale, sender_context: senderContext });
    } catch (e) {
      error = (e as Error).message;
    } finally {
      running = false;
    }
  }

  function severityClass(severity: string) {
    switch (severity) {
      case 'high':
        return 'text-danger border-danger';
      case 'medium':
        return 'text-warning border-warning';
      case 'low':
        return 'text-text-muted border-border-light';
      default:
        return 'text-text-muted border-border-light';
    }
  }

  const visibleFindings = $derived(
    (result?.findings ?? []).filter((f, idx) => !dismissed[`${f.block_id}:${idx}`])
  );
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <ShieldAlert class="size-4" /> AI risk analysis
    </h2>
    <button class="btn btn-primary text-xs" onclick={analyze} disabled={running}>
      <Sparkles class="size-3" /> {running ? 'Analyzing...' : 'Run analysis'}
    </button>
  </div>

  <p class="text-sm text-text-secondary mb-3 leading-relaxed">
    Surfaces liability, IP, auto-renewal, jurisdiction, payment-terms,
    indemnification and data-protection risks across the block tree.
    Selected document content is transmitted to the configured AI provider. Shield applies
    redaction and an operator-configured endpoint policy, but that hostname policy does not prove
    provider residency. Run analysis only after the provider, location, and transfer terms are in
    the approved sub-processor schedule.
  </p>

  <div class="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-3 items-end mb-4">
    <label class="text-sm">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono flex items-center gap-1">
        <Globe class="size-3" /> Locale
      </span>
      <select bind:value={locale} class="block px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm">
        <option value="en">English</option>
        <option value="sv">Svenska</option>
        <option value="de">Deutsch</option>
        <option value="fr">Français</option>
      </select>
    </label>
    <label class="text-sm">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Sender context (optional)</span>
      <input
        type="text"
        bind:value={senderContext}
        placeholder="e.g. SaaS subscription, 12-month term, EUR billing"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      />
    </label>
  </div>

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">{error}</div>
  {/if}

  {#if result}
    {#if result.findings.length === 0}
      <p class="text-sm text-text-muted">No findings. Document parses clean against the standard risk taxonomy.</p>
    {:else}
      <ul class="divide-y divide-border-light">
        {#each result.findings as f, idx (f.block_id + ':' + idx)}
          {@const key = `${f.block_id}:${idx}`}
          {#if !dismissed[key]}
            <li class="py-3 border-l-2 pl-3 {severityClass(f.severity)}">
              <button
                class="w-full text-left flex justify-between items-start gap-3"
                onclick={() => (expanded[key] = !expanded[key])}
              >
                <div class="flex-1 space-y-1">
                  <div class="flex items-center gap-2 text-xs">
                    <span class="font-mono uppercase tracking-widest">{f.severity}</span>
                    <span class="text-text-muted">{f.category}</span>
                    {#if f.block_id}
                      <span class="text-text-muted font-mono">block #{f.block_id.slice(0, 8)}</span>
                    {/if}
                  </div>
                  <div class="text-sm">{f.summary}</div>
                </div>
                {#if expanded[key]}
                  <ChevronUp class="size-4 text-text-muted shrink-0" />
                {:else}
                  <ChevronDown class="size-4 text-text-muted shrink-0" />
                {/if}
              </button>
              {#if expanded[key]}
                <div class="mt-2 pl-1 space-y-2 text-sm">
                  {#if f.suggestion}
                    <p>
                      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Suggestion</span>
                      <br />{f.suggestion}
                    </p>
                  {/if}
                  <button class="btn btn-secondary text-xs" onclick={(e) => { e.stopPropagation(); dismissed[key] = true; }}>
                    Dismiss
                  </button>
                </div>
              {/if}
            </li>
          {/if}
        {/each}
      </ul>
      <p class="text-xs text-text-muted mt-3">
        Shield active: {result.shield_active ? 'yes' : 'no'} ·
        Provider: {result.provider || 'unknown'} ·
        {visibleFindings.length} active finding{visibleFindings.length === 1 ? '' : 's'}.
      </p>
    {/if}
  {/if}
</section>
