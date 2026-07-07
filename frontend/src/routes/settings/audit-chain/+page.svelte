<script lang="ts">
  import { verifyAuditChain, type AuditChainResult } from '$lib/api/client';
  import { ShieldCheck, AlertTriangle, RefreshCw } from 'lucide-svelte';

  let result = $state<AuditChainResult | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);
  let limit = $state(5000);

  async function run() {
    loading = true;
    error = null;
    try {
      result = await verifyAuditChain(limit);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  const abbrev = (hex: string) =>
    !hex ? '(empty)' : hex.length <= 20 ? hex : `${hex.slice(0, 8)}...${hex.slice(-8)}`;
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Compliance</p>
    <h1 class="page-title">Audit chain verify</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Every audit event commits to its predecessor via a
    <code class="font-mono text-xs">SHA-256(prev_hash || kind || 0x00 || payload)</code>
    chain. This page walks the chain and reports any divergence
    between the recomputed hash and the stored value. Tampering with
    any historical row breaks every chain downstream of it.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  <section class="card p-5 mb-6">
    <div class="flex flex-wrap items-end gap-3">
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Rows to verify</span>
        <input
          type="number"
          bind:value={limit}
          min="100"
          max="50000"
          class="block px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm w-32"
        />
      </label>
      <button class="btn btn-primary" onclick={run} disabled={loading}>
        <RefreshCw class="size-4 {loading ? 'animate-spin' : ''}" />
        {loading ? 'Verifying...' : 'Run verification'}
      </button>
    </div>
  </section>

  {#if result}
    <section
      class="card p-5 mb-4 border-l-4 {result.ok ? 'border-success' : 'border-danger'}"
    >
      <div class="flex items-center gap-2 mb-2">
        {#if result.ok}
          <ShieldCheck class="size-5 text-success" />
          <span class="font-display font-extralight text-lg">Chain verified</span>
        {:else}
          <AlertTriangle class="size-5 text-danger" />
          <span class="font-display font-extralight text-lg">Chain divergence detected</span>
        {/if}
      </div>
      <p class="text-sm text-text-secondary">
        Checked {result.total_checked} row{result.total_checked === 1 ? '' : 's'}.
        {#if !result.ok}
          First divergence at index <span class="font-mono">{result.first_bad_index}</span>.
        {/if}
      </p>
    </section>

    {#if result.failures && result.failures.length > 0}
      <section class="card p-5">
        <h2 class="font-display font-extralight text-lg mb-4">Divergent rows</h2>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
              <th class="py-2">Index</th>
              <th>Kind</th>
              <th>Stored hash</th>
              <th>Recomputed</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border-light">
            {#each result.failures as f (f.event_id)}
              <tr>
                <td class="py-2 font-mono text-xs">{f.index}</td>
                <td class="font-mono text-xs">{f.kind}</td>
                <td class="font-mono text-xs">{abbrev(f.stored_row_hash)}</td>
                <td class="font-mono text-xs">{abbrev(f.recomputed_hash)}</td>
                <td class="text-xs">{f.reason}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="text-xs text-text-muted mt-4">
          Divergence does not by itself prove tampering: pre-fix-#10
          rows have an empty stored hash and will show up here as
          "row_hash missing". A non-empty stored hash that does not
          match the recompute is the real signal.
        </p>
      </section>
    {/if}
  {/if}
</div>
