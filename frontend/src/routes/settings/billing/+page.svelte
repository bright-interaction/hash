<script lang="ts">
  import { onMount } from 'svelte';
  import { CheckCircle2, CreditCard, Receipt, Sparkles, XCircle } from 'lucide-svelte';

  type Plan = {
    id: string;
    slug: string;
    name: string;
    monthly_price_cents: number;
    yearly_price_cents: number;
    currency: string;
    document_quota_monthly: number;
    recipient_quota_monthly: number;
    features?: Record<string, boolean>;
  };
  type Subscription = {
    id?: string;
    status?: string;
    provider?: string;
    current_period_end?: string | null;
    cancel_at_period_end?: boolean;
  };
  type Invoice = {
    id: string;
    status: string;
    amount_cents: number;
    currency: string;
    hosted_invoice_url?: string;
    paid_at?: string | null;
    created_at: string;
  };

  let plans = $state<Plan[]>([]);
  let currentPlan = $state<Plan | null>(null);
  let subscription = $state<Subscription | null>(null);
  let invoices = $state<Invoice[]>([]);
  let billingEnabled = $state(true);
  let provider = $state<string>('mock');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let interval = $state<'monthly' | 'yearly'>('monthly');

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    loading = true;
    error = null;
    try {
      const [plansRes, subRes, invRes] = await Promise.all([
        fetch('/api/v1/billing/plans').then(r => r.json()),
        fetch('/api/v1/billing/subscription').then(r => r.json()),
        fetch('/api/v1/billing/invoices').then(r => r.json())
      ]);
      plans = plansRes.plans ?? [];
      billingEnabled = plansRes.billing_enabled ?? false;
      provider = plansRes.provider ?? 'mock';
      currentPlan = subRes.plan ?? null;
      subscription = subRes.subscription && Object.keys(subRes.subscription).length ? subRes.subscription : null;
      invoices = invRes.invoices ?? [];
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function checkout(plan: Plan) {
    error = null;
    try {
      const res = await fetch('/api/v1/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan_slug: plan.slug, interval })
      });
      if (!res.ok) {
        error = await res.text();
        return;
      }
      const body = await res.json() as { checkout_url: string };
      window.location.href = body.checkout_url;
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function cancel() {
    if (!confirm('Cancel subscription at the end of the current period? You will keep access until then.')) return;
    try {
      const res = await fetch('/api/v1/billing/cancel', { method: 'POST' });
      if (!res.ok) {
        error = await res.text();
        return;
      }
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function priceFor(plan: Plan): number {
    return interval === 'yearly' ? plan.yearly_price_cents : plan.monthly_price_cents;
  }

  function formatPrice(cents: number, currency: string): string {
    return new Intl.NumberFormat('en-EU', { style: 'currency', currency }).format(cents / 100);
  }

  function quotaLabel(n: number): string {
    if (n === 0) return 'Unlimited';
    return n.toString();
  }
</script>

<div class="max-w-5xl mx-auto px-6 py-12">
  <header class="mb-8">
    <p class="page-eyebrow mb-2">Settings</p>
    <h1 class="page-title">Billing &amp; plan</h1>
    {#if !billingEnabled}
      <p class="text-text-muted text-sm mt-2">Billing is not enabled on this Hash instance.</p>
    {/if}
  </header>

  {#if error}
    <div class="card p-4 mb-6 border border-danger/30 text-danger text-sm">{error}</div>
  {/if}

  {#if loading}
    <p class="text-text-muted">Loading…</p>
  {:else}
    {#if currentPlan}
      <section class="card p-6 mb-8">
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-xs font-mono uppercase tracking-widest text-text-muted mb-1">Current plan</p>
            <h2 class="text-xl font-medium">{currentPlan.name}</h2>
            {#if subscription}
              <p class="text-text-muted text-sm mt-2">
                Status: <strong>{subscription.status}</strong>
                {#if subscription.current_period_end}
                  · renews {new Date(subscription.current_period_end).toLocaleDateString()}
                {/if}
                {#if subscription.cancel_at_period_end}
                  · <span class="text-warn">cancel scheduled</span>
                {/if}
              </p>
            {:else}
              <p class="text-text-muted text-sm mt-2">No active paid subscription. You are on the free tier.</p>
            {/if}
          </div>
          {#if subscription && !subscription.cancel_at_period_end}
            <button class="btn btn-secondary" onclick={cancel}>Cancel at period end</button>
          {/if}
        </div>
        <dl class="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3 mt-6 text-xs">
          <div><dt class="text-text-muted">Documents / mo</dt><dd>{quotaLabel(currentPlan.document_quota_monthly)}</dd></div>
          <div><dt class="text-text-muted">Recipients / mo</dt><dd>{quotaLabel(currentPlan.recipient_quota_monthly)}</dd></div>
          <div><dt class="text-text-muted">AES</dt><dd>{currentPlan.features?.aes ? 'Yes' : 'No'}</dd></div>
          <div><dt class="text-text-muted">QES (BankID)</dt><dd>{currentPlan.features?.qes ? 'Yes' : 'No'}</dd></div>
        </dl>
      </section>
    {/if}

    <section class="mb-8">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-base font-medium flex items-center gap-2"><Sparkles class="size-4" /> Plans</h3>
        <div class="flex items-center gap-2 text-xs">
          <button class="btn btn-secondary" class:btn-primary={interval === 'monthly'} onclick={() => interval = 'monthly'}>Monthly</button>
          <button class="btn btn-secondary" class:btn-primary={interval === 'yearly'} onclick={() => interval = 'yearly'}>Yearly</button>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        {#each plans as plan (plan.id)}
          <div class="card p-6 flex flex-col">
            <h4 class="text-lg font-medium">{plan.name}</h4>
            <p class="text-3xl font-light my-3">
              {formatPrice(priceFor(plan), plan.currency)}
              <span class="text-xs text-text-muted font-normal">/{interval === 'yearly' ? 'year' : 'month'}</span>
            </p>
            <ul class="text-xs text-text-muted space-y-1 mb-4 flex-1">
              <li>{quotaLabel(plan.document_quota_monthly)} documents / month</li>
              <li>{quotaLabel(plan.recipient_quota_monthly)} recipients / month</li>
              {#if plan.features?.aes}<li>AES (identity-bound)</li>{/if}
              {#if plan.features?.qes}<li>QES (BankID via Idura)</li>{/if}
              {#if plan.features?.branding}<li>Custom branding</li>{/if}
              {#if plan.features?.evidence_bundle}<li>Court-ready evidence bundles</li>{/if}
              {#if plan.features?.mcp}<li>MCP API access</li>{/if}
              {#if plan.features?.white_label}<li>White-label</li>{/if}
            </ul>
            {#if currentPlan?.slug === plan.slug}
              <span class="btn btn-secondary w-full cursor-default" aria-disabled="true">
                <CheckCircle2 class="size-4" /> Current plan
              </span>
            {:else if plan.monthly_price_cents > 0}
              <button class="btn btn-primary w-full" onclick={() => checkout(plan)}>
                <CreditCard class="size-4" /> Upgrade to {plan.name}
              </button>
            {:else}
              <span class="btn btn-secondary w-full cursor-default" aria-disabled="true">Free tier</span>
            {/if}
          </div>
        {/each}
      </div>
    </section>

    {#if invoices.length > 0}
      <section>
        <h3 class="text-base font-medium flex items-center gap-2 mb-4">
          <Receipt class="size-4" /> Invoices
        </h3>
        <div class="card overflow-hidden">
          <table class="w-full text-sm">
            <thead class="bg-bg-elevated text-text-muted text-xs">
              <tr>
                <th class="text-left p-3">Date</th>
                <th class="text-left p-3">Status</th>
                <th class="text-right p-3">Amount</th>
                <th class="text-right p-3"></th>
              </tr>
            </thead>
            <tbody>
              {#each invoices as inv (inv.id)}
                <tr class="border-t border-border-light">
                  <td class="p-3">{new Date(inv.created_at).toLocaleDateString()}</td>
                  <td class="p-3">
                    {#if inv.status === 'paid'}
                      <span class="inline-flex items-center gap-1 text-success"><CheckCircle2 class="size-3.5" /> Paid</span>
                    {:else if inv.status === 'failed'}
                      <span class="inline-flex items-center gap-1 text-danger"><XCircle class="size-3.5" /> Failed</span>
                    {:else}
                      <span class="text-text-muted capitalize">{inv.status}</span>
                    {/if}
                  </td>
                  <td class="p-3 text-right font-mono">{formatPrice(inv.amount_cents, inv.currency)}</td>
                  <td class="p-3 text-right">
                    {#if inv.hosted_invoice_url}
                      <a class="text-accent text-xs" href={inv.hosted_invoice_url} target="_blank" rel="noreferrer">View</a>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}

    {#if provider === 'mock'}
      <p class="text-text-muted text-xs mt-6">
        This Hash instance is running the <code class="font-mono">mock</code> billing provider.
        Switch <code class="font-mono">HASH_BILLING_PROVIDER=mollie</code> + set the Mollie env vars to take real payments.
      </p>
    {/if}
  {/if}
</div>
