<script lang="ts">
  import { onMount } from 'svelte';
  import {
    createWebhook, deleteWebhook, listWebhookDeliveries, listWebhooks,
    type WebhookDelivery, type WebhookEndpoint
  } from '$lib/api/client';
  import { Plus, Send, Trash2, Webhook } from 'lucide-svelte';

  let endpoints = $state<WebhookEndpoint[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  let showCreate = $state(false);
  let newURL = $state('');
  let evt = $state({
    sent: true, viewed: false, signed: true, completed: true,
    declined: true, voided: false, expired: false, bounced: false
  });
  let creating = $state(false);

  let activeEndpointID = $state<string | null>(null);
  let deliveries = $state<WebhookDelivery[]>([]);

  // Per-endpoint signing secret returned by the create response exactly
  // once. We hold it in component state and surface it in a reveal
  // banner; the list endpoint deliberately strips it on subsequent
  // reads so this is the only opportunity the tenant has to copy it.
  let lastSecret = $state<{ url: string; secret: string } | null>(null);
  let secretCopied = $state(false);

  async function refresh() {
    loading = true;
    try {
      const res = await listWebhooks();
      endpoints = res.webhooks;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function create() {
    if (!newURL.trim()) return;
    creating = true;
    error = null;
    try {
      const events: string[] = [];
      if (evt.sent) events.push('document.sent');
      if (evt.viewed) events.push('document.viewed');
      if (evt.signed) events.push('document.signed');
      if (evt.completed) events.push('document.completed');
      if (evt.declined) events.push('document.declined');
      if (evt.voided) events.push('document.voided');
      if (evt.expired) events.push('document.expired');
      if (evt.bounced) events.push('recipient.bounced');
      const created = await createWebhook(newURL.trim(), events);
      if (created.secret) {
        lastSecret = { url: created.url, secret: created.secret };
        secretCopied = false;
      }
      newURL = '';
      showCreate = false;
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      creating = false;
    }
  }

  async function remove(id: string) {
    if (!confirm('Delete this endpoint? Pending deliveries will not fire.')) return;
    try {
      await deleteWebhook(id);
      if (activeEndpointID === id) {
        activeEndpointID = null;
        deliveries = [];
      }
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function showDeliveries(id: string) {
    activeEndpointID = id;
    try {
      const res = await listWebhookDeliveries(id);
      deliveries = res.deliveries;
    } catch (e) {
      error = (e as Error).message;
    }
  }
</script>

<div class="px-6 py-10 max-w-5xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">Settings · Developer</p>
      <h1 class="page-title">Webhooks</h1>
    </div>
    <button class="btn btn-primary" onclick={() => (showCreate = true)}>
      <Plus class="size-4" /> Add endpoint
    </button>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Hash posts events to subscribed endpoints. Every payload carries
    <code class="font-mono text-xs">X-Hash-Signature: t=…,v1=…</code> with HMAC-SHA256
    over <code class="font-mono text-xs">${'{ts}'}.${'{rawJSONBody}'}</code>.
    Failed deliveries retry on 1m / 5m / 25m / 2h / 12h / 24h, then mark failed.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  {#if lastSecret}
    <div class="card p-5 mb-6 border-l-4 border-warning">
      <h3 class="font-display font-extralight text-lg mb-2">Copy this signing secret now</h3>
      <p class="text-xs text-text-secondary mb-3 leading-relaxed">
        This is the only time we will show this secret. Hash stores
        only a hash; if you lose it you must rotate by deleting and
        recreating the endpoint. The secret is per-endpoint so
        rotating one does not affect any other webhook.
      </p>
      <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-1">Endpoint</p>
      <p class="font-mono text-xs mb-3 break-all">{lastSecret.url}</p>
      <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-1">Signing secret</p>
      <div class="flex gap-2 items-center">
        <code class="font-mono text-xs bg-bg-elevated border border-border-light rounded px-3 py-2 flex-1 break-all"
          >{lastSecret.secret}</code
        >
        <button
          type="button"
          class="btn btn-secondary text-xs"
          onclick={async () => {
            try {
              await navigator.clipboard.writeText(lastSecret!.secret);
              secretCopied = true;
            } catch {
              secretCopied = false;
            }
          }}
        >
          {secretCopied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" class="btn btn-secondary text-xs" onclick={() => (lastSecret = null)}>
          Dismiss
        </button>
      </div>
      <p class="text-xs text-text-muted mt-3">
        Wire the receiving end to verify:
        <code class="font-mono">HMAC-SHA256(secret, "{`{ts}.{rawJSONBody}`}")</code> against the
        <code class="font-mono">v1=</code> portion of <code class="font-mono">X-Hash-Signature</code>.
      </p>
    </div>
  {/if}

  {#if showCreate}
    <div class="card p-5 mb-6">
      <h3 class="font-display font-extralight text-lg mb-3">New webhook endpoint</h3>
      <input
        type="url"
        bind:value={newURL}
        placeholder="https://yoursaas.com/webhooks/hash"
        class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm mb-4"
      />
      <p class="text-xs text-text-muted font-mono uppercase tracking-widest mb-2">Subscribe to</p>
      <div class="grid grid-cols-2 gap-2 mb-4 text-sm">
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.sent} /> document.sent</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.viewed} /> document.viewed</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.signed} /> document.signed</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.completed} /> document.completed</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.declined} /> document.declined</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.voided} /> document.voided</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.expired} /> document.expired</label>
        <label class="flex items-center gap-2"><input type="checkbox" bind:checked={evt.bounced} /> recipient.bounced</label>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={create} disabled={creating || !newURL.trim()}>
          {creating ? 'Saving…' : 'Save endpoint'}
        </button>
        <button class="btn btn-secondary" onclick={() => (showCreate = false)}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else if endpoints.length === 0}
    <div class="card p-12 text-center">
      <Webhook class="size-8 mx-auto text-text-muted mb-3" />
      <p class="font-display text-xl font-extralight">No webhook endpoints yet</p>
      <p class="text-text-secondary text-sm mt-2">Add one to receive Hash events.</p>
    </div>
  {:else}
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">URL</th>
            <th class="text-left px-4 py-3 font-medium">Events</th>
            <th class="text-left px-4 py-3 font-medium">Active</th>
            <th class="text-right px-4 py-3 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each endpoints as e (e.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3 font-mono text-xs break-all">{e.url}</td>
              <td class="px-4 py-3 text-xs">
                <div class="flex gap-1 flex-wrap">
                  {#each e.events_subscribed as ev (ev)}
                    <span class="px-1.5 py-0.5 rounded bg-bg-elevated text-xs font-mono">{ev}</span>
                  {/each}
                </div>
              </td>
              <td class="px-4 py-3">{e.active ? 'yes' : 'no'}</td>
              <td class="px-4 py-3 text-right space-x-2">
                <button class="text-info hover:underline text-xs inline-flex items-center gap-1" onclick={() => showDeliveries(e.id)}>
                  <Send class="size-3" /> Deliveries
                </button>
                <button class="text-danger hover:underline text-xs inline-flex items-center gap-1" onclick={() => remove(e.id)}>
                  <Trash2 class="size-3" /> Delete
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if activeEndpointID}
    <h2 class="font-display font-extralight text-xl mt-8 mb-3">Recent deliveries</h2>
    <div class="card overflow-hidden">
      <table class="w-full text-sm">
        <thead class="border-b border-border-light bg-bg-elevated">
          <tr>
            <th class="text-left px-4 py-3 font-medium">Status</th>
            <th class="text-left px-4 py-3 font-medium">Code</th>
            <th class="text-left px-4 py-3 font-medium">Attempts</th>
            <th class="text-left px-4 py-3 font-medium">Time</th>
            <th class="text-left px-4 py-3 font-medium">Error</th>
          </tr>
        </thead>
        <tbody>
          {#each deliveries as d (d.id)}
            <tr class="border-b border-border-light last:border-0">
              <td class="px-4 py-3 capitalize">{d.status}</td>
              <td class="px-4 py-3 font-mono text-xs">{d.last_status_code ?? ', '}</td>
              <td class="px-4 py-3">{d.attempts}</td>
              <td class="px-4 py-3 text-xs text-text-muted">{new Date(d.created_at).toLocaleString()}</td>
              <td class="px-4 py-3 text-xs text-text-muted">{d.last_error ?? ''}</td>
            </tr>
          {/each}
          {#if deliveries.length === 0}
            <tr><td colspan="5" class="px-4 py-6 text-center text-text-muted">No deliveries yet.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</div>
