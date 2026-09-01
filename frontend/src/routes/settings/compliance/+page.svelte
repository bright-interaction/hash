<script lang="ts">
  import { onMount } from 'svelte';
  import {
    seedCompliance,
    listComplianceFlags,
    setComplianceFlagStatus,
    runComplianceFlagSweep,
    type ComplianceFlag,
  } from '$lib/api/client';
  import { ShieldCheck, AlertTriangle, RotateCw } from 'lucide-svelte';

  let businessType = $state('saas');
  let jurisdiction = $state('SE');
  let seeding = $state(false);
  let seedMessage = $state<string | null>(null);

  let flags = $state<ComplianceFlag[]>([]);
  let statusFilter = $state<string>('open');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let sweeping = $state(false);

  async function refresh() {
    loading = true;
    try {
      const res = await listComplianceFlags(statusFilter);
      flags = res.flags ?? [];
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function seed() {
    seeding = true;
    seedMessage = null;
    try {
      await seedCompliance(businessType, jurisdiction);
      seedMessage = `Seeded baseline kit for ${businessType} / ${jurisdiction}. DRAFT KIT v1; have your counsel review before use.`;
    } catch (e) {
      seedMessage = (e as Error).message;
    } finally {
      seeding = false;
    }
  }

  async function sweep() {
    sweeping = true;
    try {
      await runComplianceFlagSweep();
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      sweeping = false;
    }
  }

  async function transition(id: string, status: string) {
    try {
      await setComplianceFlagStatus(id, status);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  const businessTypes = ['saas', 'consulting', 'law_firm', 'healthcare', 'fintech', 'other'];
</script>

<div class="px-6 py-10 max-w-5xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Compliance</p>
    <h1 class="page-title">Compliance kit</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    The built-in DPA, Records of Processing, and Article 13 kit is an unapproved
    development draft and cannot be seeded or sent in production. The EDPB feed
    flagger raises flags here when an advisory touches an existing reviewed baseline.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  <section class="card p-5 mb-6">
    <h2 class="font-display font-extralight text-lg mb-3 flex items-center gap-2">
      <ShieldCheck class="size-4" /> Development-only draft kit
    </h2>
    <div class="flex flex-wrap gap-3 items-end">
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Business type</span>
        <select bind:value={businessType} class="block px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm">
          {#each businessTypes as t (t)}
            <option value={t}>{t}</option>
          {/each}
        </select>
      </label>
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Jurisdiction</span>
        <input
          type="text"
          bind:value={jurisdiction}
          placeholder="SE"
          class="block px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm w-24"
        />
      </label>
      <button class="btn btn-primary" onclick={seed} disabled={seeding}>
        {seeding ? 'Seeding...' : 'Seed kit'}
      </button>
    </div>
    {#if seedMessage}
      <p class="text-xs text-text-secondary mt-3">{seedMessage}</p>
    {/if}
  </section>

  <section class="card p-5">
    <div class="flex items-center justify-between mb-4">
      <h2 class="font-display font-extralight text-lg flex items-center gap-2">
        <AlertTriangle class="size-4" /> Compliance flags
      </h2>
      <div class="flex gap-2 items-center">
        <select bind:value={statusFilter} onchange={refresh} class="text-sm px-3 py-1.5 rounded border border-border-light bg-bg-elevated">
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
          <option value="">All</option>
        </select>
        <button class="btn btn-secondary text-xs" onclick={sweep} disabled={sweeping}>
          <RotateCw class="size-3" /> {sweeping ? 'Running...' : 'Run sweep'}
        </button>
      </div>
    </div>

    {#if loading}
      <p class="text-text-muted text-sm">Loading...</p>
    {:else if flags.length === 0}
      <p class="text-text-muted text-sm">No flags in this state.</p>
    {:else}
      <ul class="divide-y divide-border-light">
        {#each flags as f (f.id)}
          <li class="py-3 flex flex-col sm:flex-row sm:items-center gap-3">
            <div class="flex-1">
              <div class="text-sm font-medium">{f.update_title}</div>
              <div class="text-xs text-text-muted mt-1">
                <span class="font-mono">{f.affected_topic}</span> ·
                severity <span class="font-mono">{f.severity}</span>
              </div>
              <div class="text-xs text-text-secondary mt-1">{f.suggested_action}</div>
            </div>
            <div class="flex gap-2">
              <button class="btn btn-secondary text-xs" onclick={() => transition(f.id, 'acknowledged')}>Ack</button>
              <button class="btn btn-secondary text-xs" onclick={() => transition(f.id, 'resolved')}>Resolve</button>
              <button class="btn btn-secondary text-xs" onclick={() => transition(f.id, 'dismissed')}>Dismiss</button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
