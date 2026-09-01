<script lang="ts">
  import { onMount } from 'svelte';
  import {
    cancelBillingSubscription,
    getBillingSubscription,
    listBillingInvoices,
    listBillingPlans,
    startBillingCheckout,
    type BillingInvoice,
    type BillingPlan,
    type BillingSubscription,
  } from '$lib/api/client';
  import { CheckCircle2, CreditCard, Receipt, Sparkles, XCircle } from 'lucide-svelte';

  let plans = $state<BillingPlan[]>([]);
  let currentPlan = $state<BillingPlan | null>(null);
  let subscription = $state<BillingSubscription | null>(null);
  let invoices = $state<BillingInvoice[]>([]);
  let billingEnabled = $state(false);
  let provider = $state<string>('disabled');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let interval = $state<'monthly' | 'yearly'>('monthly');
  let checkoutPlanSlug = $state<string | null>(null);
  let cancelling = $state(false);

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    loading = true;
    error = null;
    try {
      const [plansRes, subRes, invRes] = await Promise.all([
        listBillingPlans(),
        getBillingSubscription(),
        listBillingInvoices(),
      ]);
      if (!Array.isArray(plansRes.plans) || !plansRes.plans.every(isBillingPlan)) {
        throw new Error('The billing service returned invalid plan data.');
      }
      if (!Array.isArray(invRes.invoices) || !invRes.invoices.every(isBillingInvoice)) {
        throw new Error('The billing service returned invalid invoice data.');
      }
      const enabled = plansRes.billing_enabled === true;
      if (subRes.billing_enabled !== enabled) {
        throw new Error('The billing service returned inconsistent availability data.');
      }
      const nextPlan = isBillingPlan(subRes.plan) ? subRes.plan : null;
      if (enabled && nextPlan === null) {
        throw new Error('The billing service returned invalid subscription data.');
      }

      plans = plansRes.plans;
      billingEnabled = enabled;
      provider = typeof plansRes.provider === 'string'
        ? plansRes.provider
        : (enabled ? 'unknown' : 'disabled');
      currentPlan = nextPlan;
      subscription = isBillingSubscription(subRes.subscription) ? subRes.subscription : null;
      invoices = invRes.invoices.map((invoice) => ({
        ...invoice,
        hosted_invoice_url: safeExternalURL(invoice.hosted_invoice_url) ?? undefined,
      }));
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  async function checkout(plan: BillingPlan) {
    if (!billingEnabled || checkoutPlanSlug !== null) return;
    error = null;
    checkoutPlanSlug = plan.slug;
    try {
      const body = await startBillingCheckout(plan.slug, interval);
      const checkoutURL = safeExternalURL(body.checkout_url);
      if (checkoutURL === null) {
        throw new Error('The billing provider returned an invalid checkout link.');
      }
      window.location.assign(checkoutURL);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      checkoutPlanSlug = null;
    }
  }

  async function cancel() {
    if (cancelling || !canCancel(subscription)) return;
    if (!confirm('Cancel subscription at the end of the current period? You will keep access until then.')) return;
    error = null;
    cancelling = true;
    try {
      await cancelBillingSubscription();
      await refresh();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      cancelling = false;
    }
  }

  function priceFor(plan: BillingPlan): number {
    return interval === 'yearly' ? plan.yearly_price_cents : plan.monthly_price_cents;
  }

  function formatPrice(cents: number, currency: string): string {
    return new Intl.NumberFormat('en-EU', { style: 'currency', currency }).format(cents / 100);
  }

  function quotaLabel(n: number): string {
    if (n === 0) return 'Unlimited';
    return n.toString();
  }

  function canCancel(value: BillingSubscription | null): boolean {
    return value !== null && value.cancel_at_period_end !== true &&
      (value.status === 'active' || value.status === 'trialing' || value.status === 'past_due');
  }

  function isBillingPlan(value: unknown): value is BillingPlan {
    if (value === null || typeof value !== 'object') return false;
    const plan = value as Record<string, unknown>;
    return typeof plan.id === 'string' && typeof plan.slug === 'string' &&
      typeof plan.name === 'string' && typeof plan.currency === 'string' &&
      /^[A-Z]{3}$/.test(plan.currency) &&
      isNonNegativeInteger(plan.monthly_price_cents) &&
      isNonNegativeInteger(plan.yearly_price_cents) &&
      isNonNegativeInteger(plan.document_quota_monthly) &&
      isNonNegativeInteger(plan.recipient_quota_monthly) && isFeatureMap(plan.features);
  }

  function isBillingSubscription(value: unknown): value is BillingSubscription {
    if (value === null || typeof value !== 'object' || Object.keys(value).length === 0) return false;
    const sub = value as Record<string, unknown>;
    return (sub.id === undefined || typeof sub.id === 'string') &&
      (sub.status === undefined || typeof sub.status === 'string') &&
      (sub.provider === undefined || typeof sub.provider === 'string') &&
      (sub.current_period_end === undefined || sub.current_period_end === null ||
        (typeof sub.current_period_end === 'string' && Number.isFinite(Date.parse(sub.current_period_end)))) &&
      (sub.cancel_at_period_end === undefined || typeof sub.cancel_at_period_end === 'boolean');
  }

  function isBillingInvoice(value: unknown): value is BillingInvoice {
    if (value === null || typeof value !== 'object') return false;
    const invoice = value as Record<string, unknown>;
    return typeof invoice.id === 'string' && typeof invoice.status === 'string' &&
      isNonNegativeInteger(invoice.amount_cents) && typeof invoice.currency === 'string' &&
      /^[A-Z]{3}$/.test(invoice.currency) && typeof invoice.created_at === 'string' &&
      Number.isFinite(Date.parse(invoice.created_at)) &&
      (invoice.hosted_invoice_url === undefined || typeof invoice.hosted_invoice_url === 'string');
  }

  function isNonNegativeInteger(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  }

  function isFeatureMap(value: unknown): value is Record<string, boolean> | undefined {
    return value === undefined || (value !== null && typeof value === 'object' &&
      !Array.isArray(value) && Object.values(value).every((flag) => typeof flag === 'boolean'));
  }

  function safeExternalURL(raw: unknown): string | null {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
    try {
      const url = new URL(raw);
      if (url.username !== '' || url.password !== '') return null;
      if (url.protocol === 'https:') return url.href;
      const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' ||
        url.hostname === '::1' || url.hostname === '[::1]';
      return url.protocol === 'http:' && loopback ? url.href : null;
    } catch {
      return null;
    }
  }

  function errorMessage(value: unknown): string {
    return value instanceof Error && value.message
      ? value.message
      : 'Billing is temporarily unavailable. Please try again.';
  }
</script>

<div class="max-w-5xl mx-auto px-6 py-12">
  <header class="mb-8">
    <p class="page-eyebrow mb-2">Settings</p>
    <h1 class="page-title">Billing &amp; plan</h1>
    {#if !loading && error === null && !billingEnabled}
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
                  · {subscription.cancel_at_period_end ? 'access until' : 'renews'} {new Date(subscription.current_period_end).toLocaleDateString()}
                {/if}
                {#if subscription.cancel_at_period_end}
                  · <span class="text-warn">cancel scheduled</span>
                {/if}
              </p>
            {:else}
              <p class="text-text-muted text-sm mt-2">No active paid subscription. You are on the free tier.</p>
            {/if}
          </div>
          {#if canCancel(subscription)}
            <button class="btn btn-secondary" onclick={cancel} disabled={cancelling} aria-busy={cancelling}>
              {cancelling ? 'Scheduling cancellation…' : 'Cancel at period end'}
            </button>
          {/if}
        </div>
        <dl class="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3 mt-6 text-xs">
          <div><dt class="text-text-muted">Documents / mo</dt><dd>{quotaLabel(currentPlan.document_quota_monthly)}</dd></div>
          <div><dt class="text-text-muted">Recipients / mo</dt><dd>{quotaLabel(currentPlan.recipient_quota_monthly)}</dd></div>
          <div><dt class="text-text-muted">AES</dt><dd>Unavailable</dd></div>
          <div><dt class="text-text-muted">QES</dt><dd>Unavailable</dd></div>
        </dl>
      </section>
    {/if}

    {#if billingEnabled}
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
              <li>SES signing (AES / QES unavailable)</li>
              {#if plan.features?.branding}<li>Custom branding</li>{/if}
              {#if plan.features?.evidence_bundle}<li>Cryptographically verifiable evidence bundles</li>{/if}
              {#if plan.features?.mcp}<li>MCP API access</li>{/if}
              {#if plan.features?.white_label}<li>White-label</li>{/if}
            </ul>
            {#if currentPlan?.slug === plan.slug}
              <span class="btn btn-secondary w-full cursor-default" aria-disabled="true">
                <CheckCircle2 class="size-4" /> Current plan
              </span>
            {:else if plan.monthly_price_cents > 0}
              <button
                class="btn btn-primary w-full"
                onclick={() => checkout(plan)}
                disabled={checkoutPlanSlug !== null}
                aria-busy={checkoutPlanSlug === plan.slug}
              >
                <CreditCard class="size-4" />
                {checkoutPlanSlug === plan.slug ? 'Opening checkout…' : `Upgrade to ${plan.name}`}
              </button>
            {:else}
              <span class="btn btn-secondary w-full cursor-default" aria-disabled="true">Free tier</span>
            {/if}
          </div>
        {/each}
      </div>
      </section>
    {/if}

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
                      <a class="text-accent text-xs" href={inv.hosted_invoice_url} target="_blank" rel="noopener noreferrer">View</a>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}

    {#if billingEnabled && provider === 'mock'}
      <p class="text-text-muted text-xs mt-6">
        This Hash instance is running the <code class="font-mono">mock</code> billing provider.
        Switch <code class="font-mono">HASH_BILLING_PROVIDER=mollie</code> + set the Mollie env vars to take real payments.
      </p>
    {/if}
  {/if}
</div>
