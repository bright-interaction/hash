<script lang="ts">
  import { onMount } from 'svelte';
  import { getDashboard, listDocuments, type DashboardKPIs, type DocumentResponse } from '$lib/api/client';
  import { Activity, Clock, FileText, Inbox, Plus, Sparkles, Timer, Users } from 'lucide-svelte';

  let kpis = $state<DashboardKPIs | null>(null);
  let docs = $state<DocumentResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  function fmtDuration(seconds: number): string {
    if (!seconds) return ', ';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
    return `${(seconds / 86400).toFixed(1)}d`;
  }

  onMount(async () => {
    try {
      const [k, d] = await Promise.all([getDashboard(), listDocuments()]);
      kpis = k;
      docs = d.documents.slice(0, 8);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  });
</script>

<div class="px-6 py-10 max-w-6xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">Hash</p>
      <h1 class="page-title">Dashboard</h1>
    </div>
    <a class="btn btn-primary" href="/documents">
      <Plus class="size-4" /> New document
    </a>
  </div>

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if error}
    <div class="card p-6 text-danger">{error}</div>
  {:else if kpis}
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Inbox class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Awaiting</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{kpis.awaiting_signature}</p>
      </div>

      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Activity class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Sent 24h</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{kpis.sent_24h}</p>
      </div>

      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <FileText class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Done 30d</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{kpis.completed_30d}</p>
      </div>

      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Timer class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Time to sign</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{fmtDuration(kpis.time_to_sign_p50_sec)}</p>
        <p class="text-xs text-text-muted mt-1">p50 over 90d</p>
      </div>

      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Clock class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Expiring 7d</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{kpis.expiring_within_7d}</p>
      </div>

      <div class="card p-5">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Sparkles class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Agent-authored</span>
        </div>
        <p class="text-3xl font-display font-extralight mt-2">{kpis.agent_authored_30d}</p>
        <p class="text-xs text-text-muted mt-1">vs {kpis.human_authored_30d} human (30d)</p>
      </div>

      <div class="card p-5 col-span-2">
        <div class="flex items-center gap-2 text-text-muted text-xs">
          <Users class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">Status mix</span>
        </div>
        <div class="flex flex-wrap gap-3 mt-3 text-sm">
          {#each Object.entries(kpis.by_status) as [k, v] (k)}
            <span class="px-2 py-1 rounded-md bg-bg-elevated capitalize text-xs">
              {k} <strong class="font-mono">{v}</strong>
            </span>
          {/each}
        </div>
      </div>
    </div>

    <h2 class="font-display font-extralight text-xl mb-3">Recent documents</h2>
    {#if docs.length === 0}
      <div class="card p-8 text-center text-text-muted">No documents yet.</div>
    {:else}
      <div class="card overflow-hidden">
        <table class="w-full text-sm">
          <thead class="border-b border-border-light bg-bg-elevated">
            <tr>
              <th class="text-left px-4 py-3 font-medium">Name</th>
              <th class="text-left px-4 py-3 font-medium">Status</th>
              <th class="text-left px-4 py-3 font-medium">Updated</th>
            </tr>
          </thead>
          <tbody>
            {#each docs as d (d.id)}
              <tr class="border-b border-border-light last:border-0">
                <td class="px-4 py-3"><a class="hover:underline" href={`/documents/${d.id}`}>{d.name}</a></td>
                <td class="px-4 py-3 capitalize">{d.status}</td>
                <td class="px-4 py-3 text-text-muted">{new Date(d.updated_at).toLocaleString()}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>
