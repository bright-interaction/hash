<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import {
    listRecipients,
    createRecipient,
    updateRecipient,
    deleteRecipient,
    sendDocument,
    remindDocument,
    voidDocument,
    finalPdfURL,
    auditCertURL,
    SendError,
    type Recipient,
    type SignerLink,
    type LawfulBasis,
  } from '$lib/api/client';
  import { LOCALES } from '$lib/i18n';
  import {
    ceremonyModeCopy,
    hasCeremonyParticipant,
    recipientRoleOptions,
  } from './senderMode';
  import {
    Send,
    Bell,
    Ban,
    Plus,
    Trash2,
    Pencil,
    Download,
    FileCheck,
    Copy,
    Users,
    ShieldAlert,
    CreditCard,
    ArrowUpRight,
  } from 'lucide-svelte';

  type Props = {
    documentID: string;
    status: string;
    requiresSignature?: boolean;
    defaultLocale?: string;
    signatureFields?: { role: string; label: string }[];
    onStatusChange?: (next: string) => void;
    onDefaultLocaleChange?: (locale: string) => Promise<void> | void;
  };

  let {
    documentID,
    status,
    requiresSignature = true,
    defaultLocale = 'en',
    signatureFields = [],
    onStatusChange,
    onDefaultLocaleChange,
  }: Props = $props();

  // Distinct roles that have a signature field; each needs a recipient to sign.
  const signerRoles = $derived([
    ...new Set(signatureFields.map((field) => field.role.trim().toLowerCase()).filter(Boolean)),
  ]);
  const missingRoles = $derived(
    requiresSignature
      ? signerRoles.filter((role) => !recipients.some((r) => r.role === role))
      : [],
  );
  const modeCopy = $derived(ceremonyModeCopy(requiresSignature));
  const roleOptions = $derived(recipientRoleOptions(signatureFields));

  // Document-level default ceremony language. The sender dictates this before
  // sending; every new recipient inherits it (see openAdd) and the whole
  // ceremony (email + signing page + rendered document) opens in it.
  // This is deliberately an initial value, not a live mirror of the prop:
  // subsequent changes come from the select and are persisted explicitly.
  let docLocale = $state(untrack(() => defaultLocale || 'en'));
  let savingLocale = $state(false);

  async function changeDocLocale(e: Event) {
    const next = (e.currentTarget as HTMLSelectElement).value;
    docLocale = next;
    savingLocale = true;
    try {
      await onDefaultLocaleChange?.(next);
    } finally {
      savingLocale = false;
    }
  }

  let recipients = $state<Recipient[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let sendErr = $state<SendError | null>(null);

  // Recipient add/edit form.
  let showForm = $state(false);
  let editingId = $state<string | null>(null);
  let fName = $state('');
  let fEmail = $state('');
  let fRole = $state('signer');
  let fLocale = $state('en');
  let saving = $state(false);

  // Lifecycle action state.
  let busy = $state<'send' | 'remind' | 'void' | null>(null);
  let links = $state<SignerLink[] | null>(null);
	let lawfulBasis = $state<LawfulBasis | ''>('');
  let remindedFlash = $state<number | null>(null);
  let copiedID = $state<string | null>(null);

  const editable = $derived(status === 'draft');
  const isLive = $derived(status === 'sent' || status === 'in_progress');
  const isCompleted = $derived(status === 'completed');
  const isTerminal = $derived(
    status === 'voided' || status === 'declined' || status === 'expired',
  );
  const hasParticipant = $derived(
    hasCeremonyParticipant(
      requiresSignature,
      recipients.map((recipient) => recipient.role),
      signerRoles,
    ),
  );

  async function refresh() {
    loading = true;
    try {
      recipients = await listRecipients(documentID);
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  function openAdd() {
    editingId = null;
    fName = '';
    fEmail = '';
    const firstSupportedRequiredRole = roleOptions.find((option) =>
      signerRoles.includes(option.value),
    );
    fRole = requiresSignature ? (firstSupportedRequiredRole?.value ?? 'signer') : 'approver';
    fLocale = requiresSignature ? (docLocale || 'en') : 'en';
    showForm = true;
  }

  function openEdit(r: Recipient) {
    editingId = r.id;
    fName = r.name;
    fEmail = r.email;
    fRole = r.role;
    fLocale = requiresSignature ? (r.locale || 'en') : 'en';
    showForm = true;
  }

  function closeForm() {
    showForm = false;
    editingId = null;
  }

  async function submitForm() {
    if (!fName.trim() || !fEmail.trim()) {
      error = 'Name and email are required.';
      return;
    }
    saving = true;
    error = null;
    try {
      if (editingId) {
        await updateRecipient(documentID, editingId, {
          name: fName.trim(),
          email: fEmail.trim(),
          role: fRole,
          locale: fLocale,
        });
      } else {
        const nextOrder = recipients.reduce((m, r) => Math.max(m, r.order_index), -1) + 1;
        await createRecipient(documentID, {
          name: fName.trim(),
          email: fEmail.trim(),
          role: fRole,
          order_index: nextOrder,
          locale: fLocale,
        });
      }
      closeForm();
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  async function remove(r: Recipient) {
    if (!confirm(`Remove ${r.name} <${r.email}> from this document?`)) return;
    error = null;
    try {
      await deleteRecipient(documentID, r.id);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function send() {
    busy = 'send';
    error = null;
    sendErr = null;
    try {
		if (!lawfulBasis) {
			error = 'Select and confirm the controller\'s GDPR Article 6 lawful basis before sending.';
			return;
		}
		const res = await sendDocument(documentID, lawfulBasis);
      links = res.links;
      onStatusChange?.(res.status || 'sent');
      await refresh();
    } catch (e) {
      if (e instanceof SendError) {
        sendErr = e;
      } else {
        error = (e as Error).message;
      }
    } finally {
      busy = null;
    }
  }

  async function remind() {
    busy = 'remind';
    error = null;
    try {
      const res = await remindDocument(documentID);
      remindedFlash = res.reminded;
      setTimeout(() => (remindedFlash = null), 4000);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      busy = null;
    }
  }

  async function voidDoc() {
    const reason = prompt('Reason for voiding this document (recorded in the audit trail):');
    if (reason === null) return;
    busy = 'void';
    error = null;
    try {
      await voidDocument(documentID, reason.trim() || undefined);
      links = null;
      onStatusChange?.('voided');
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      busy = null;
    }
  }

  async function copyLink(l: SignerLink) {
    try {
      await navigator.clipboard.writeText(l.url);
      copiedID = l.recipient_id;
      setTimeout(() => (copiedID = null), 2000);
    } catch {
      /* clipboard blocked; the link is still visible to select manually */
    }
  }

  // Per-recipient status pill styling.
  function pill(s: string): string {
    switch (s) {
      case 'signed':
      case 'accepted':
        return 'text-success border-success';
      case 'viewed':
      case 'sent':
        return 'text-info border-info';
      case 'declined':
      case 'bounced':
        return 'text-danger border-danger';
      default:
        return 'text-text-muted border-border-light';
    }
  }

	const lawfulBasisOptions: { value: LawfulBasis; label: string }[] = [
		{ value: 'contract', label: 'Art. 6(1)(b) — contract or requested pre-contractual steps' },
	];

  function ts(value?: string): string {
    return value ? new Date(value).toLocaleString() : '';
  }
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <Users class="size-4" /> {modeCopy.sectionTitle}
    </h2>
    {#if editable}
      <button class="btn btn-secondary text-xs" onclick={openAdd}>
        <Plus class="size-3" /> Add recipient
      </button>
    {/if}
  </div>

  {#if editable}
    <div class="flex flex-wrap items-center gap-2 mb-4 pb-4 border-b border-border-light">
      <span class="text-xs uppercase tracking-widest text-text-muted font-mono">
        {requiresSignature ? 'Default email language' : 'Ceremony language'}
      </span>
      {#if requiresSignature}
        <select
          bind:value={docLocale}
          onchange={changeDocLocale}
          disabled={savingLocale}
          class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm"
        >
          {#each LOCALES as l (l.code)}
            <option value={l.code}>{l.name}</option>
          {/each}
        </select>
      {:else}
        <span class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm">English</span>
      {/if}
      <span class="text-xs text-text-muted">
        {savingLocale ? 'Saving...' : modeCopy.defaultLanguageHelp}
      </span>
    </div>
  {/if}

  <p class="text-sm text-text-secondary mb-4 leading-relaxed">
    {#if editable}
      {modeCopy.editableDescription}
    {:else if isLive}
      {modeCopy.liveDescription}
    {:else if isCompleted}
      {modeCopy.completedDescription}
    {:else}
      This document is {status}. No further sending actions are available.
    {/if}
  </p>

  {#if editable && requiresSignature && signerRoles.length > 0}
    <div class="rounded-md border border-border-light bg-bg-elevated p-3 mb-4 text-sm">
      <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-2">Required signature fields</p>
      <ul class="space-y-1">
        {#each signatureFields as f (f.role + f.label)}
          {@const filled = recipients.some((r) => r.role === f.role.trim().toLowerCase())}
          <li class="flex items-center gap-2">
            <span class="inline-block size-1.5 rounded-full {filled ? 'bg-success' : 'bg-warning'}"></span>
            <span>{f.label}</span>
            <span class="text-text-muted text-xs">· role: {f.role}</span>
            {#if !filled}<span class="text-warning text-xs">missing a recipient with this role</span>{/if}
          </li>
        {/each}
      </ul>
    </div>
  {/if}

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">
      {error}
    </div>
  {/if}

  {#if sendErr}
    {#if sendErr.status === 402}
      <div class="card p-4 mb-4 border-l-4 border-warning">
        <h3 class="font-display font-extralight text-base mb-1 flex items-center gap-2">
          <CreditCard class="size-4" /> Plan limit reached
        </h3>
        <p class="text-sm text-text-secondary mb-3 leading-relaxed">{sendErr.message}</p>
        <a class="btn btn-primary text-xs" href={sendErr.upgradeURL || '/settings/billing'}>
          <ArrowUpRight class="size-3" /> Upgrade plan
        </a>
      </div>
    {:else if sendErr.status === 409 && sendErr.requiredTier}
      <div class="card p-4 mb-4 border-l-4 border-warning">
        <h3 class="font-display font-extralight text-base mb-1 flex items-center gap-2">
          <ShieldAlert class="size-4" /> {requiresSignature ? 'Signature tier unavailable' : 'Ceremony assurance tier unavailable'}
        </h3>
        <p class="text-sm text-text-secondary mb-2 leading-relaxed">
          {#if requiresSignature}
            This document requires <strong>{sendErr.requiredTier}</strong> signing.
            Hash currently supports production signing at SES only, so this send is blocked
            and will not be silently downgraded.
          {:else}
            This document requires <strong>{sendErr.requiredTier}</strong> assurance.
            Hash currently supports production acknowledgement ceremonies at SES only, so this
            send is blocked and will not be silently downgraded.
          {/if}
        </p>
        {#if sendErr.matchedRules && sendErr.matchedRules.length}
          <p class="text-xs uppercase tracking-widest text-text-muted font-mono mb-1">
            Triggered by
          </p>
          <ul class="text-sm text-text-secondary list-disc pl-5 mb-3">
            {#each sendErr.matchedRules as rule}
              <li>{rule}</li>
            {/each}
          </ul>
        {/if}
        <a class="btn btn-secondary text-xs" href="/settings/eidas-rules">Review unavailable-tier rules</a>
      </div>
    {:else}
      <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">
        {sendErr.message}
      </div>
    {/if}
  {/if}

  {#if showForm}
    <div class="card p-4 mb-4">
      <h3 class="font-display font-extralight text-base mb-3">
        {editingId ? 'Edit recipient' : 'New recipient'}
      </h3>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Name</span>
          <input
            type="text"
            bind:value={fName}
            placeholder="Jane Andersson"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Email</span>
          <input
            type="email"
            bind:value={fEmail}
            placeholder="jane@example.com"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Role</span>
          <select
            bind:value={fRole}
            class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          >
            {#each roleOptions as o}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>
        <div class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Language</span>
          {#if requiresSignature}
            <select
              bind:value={fLocale}
              class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
            >
              {#each LOCALES as l (l.code)}
                <option value={l.code}>{l.name}</option>
              {/each}
            </select>
          {:else}
            <div class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm">English</div>
          {/if}
          <span class="text-xs text-text-muted">{modeCopy.recipientLanguageHelp}</span>
        </div>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={submitForm} disabled={saving}>
          {saving ? 'Saving...' : editingId ? 'Save changes' : 'Add recipient'}
        </button>
        <button class="btn btn-secondary" onclick={closeForm}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted text-sm">Loading...</p>
  {:else if recipients.length === 0}
    <p class="text-text-muted text-sm mb-4">
      No recipients yet.{#if editable}{' '}{modeCopy.emptyRecipients}{/if}
    </p>
  {:else}
    <table class="w-full text-sm mb-4">
      <thead>
        <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
          <th class="py-2">Recipient</th>
          <th>Role</th>
          <th>Status</th>
          {#if editable}
            <th class="text-right">Actions</th>
          {/if}
        </tr>
      </thead>
      <tbody class="divide-y divide-border-light">
        {#each recipients as r (r.id)}
          <tr>
            <td class="py-2">
              <div class="font-medium">{r.name}</div>
              <div class="text-xs text-text-muted">{r.email}</div>
            </td>
            <td class="capitalize">{r.role}<span class="text-text-muted normal-case"> · {r.locale}</span></td>
            <td>
              <span
                class="inline-block text-xs px-2 py-0.5 rounded-full border capitalize {pill(r.status)}"
                title={r.status === 'accepted'
                  ? 'Acknowledged'
                  : r.signed_at
                    ? `Signed ${ts(r.signed_at)}`
                  : r.first_viewed_at
                    ? `First viewed ${ts(r.first_viewed_at)}`
                    : r.sent_at
                      ? `Sent ${ts(r.sent_at)}`
                      : ''}
              >
                {r.status}
              </span>
            </td>
            {#if editable}
              <td class="text-right whitespace-nowrap">
                <button class="btn btn-secondary text-xs" onclick={() => openEdit(r)}>
                  <Pencil class="size-3" />
                </button>
                <button class="btn btn-secondary text-xs" onclick={() => remove(r)}>
                  <Trash2 class="size-3" />
                </button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  <!-- Action bar -->
	{#if editable}
		<div class="mb-4 rounded-md border border-border-light bg-bg-elevated p-3 space-y-2">
			<label class="block text-sm" for="lawful-basis">
				<span class="text-xs uppercase tracking-widest text-text-muted font-mono">{modeCopy.lawfulBasisLabel}</span>
				<select
					id="lawful-basis"
					bind:value={lawfulBasis}
					class="mt-1 block w-full px-3 py-2 rounded-md border border-border-light bg-bg text-sm"
					required
				>
					<option value="" disabled>Select the controller-approved basis…</option>
					{#each lawfulBasisOptions as option (option.value)}
						<option value={option.value}>{option.label}</option>
					{/each}
				</select>
			</label>
			<p class="text-xs text-text-muted">
				Your organisation is the controller and must confirm that Art. 6(1)(b) actually applies to this document. Hash currently blocks ceremonies requiring another basis; it does not determine legal effect or choose a basis for you.
			</p>
		</div>
	{/if}
  <div class="flex flex-wrap items-center gap-3 pt-2 border-t border-border-light">
    {#if editable}
      <button class="btn btn-primary" onclick={send} disabled={busy === 'send' || !hasParticipant || missingRoles.length > 0 || !lawfulBasis}>
        <Send class="size-4" /> {busy === 'send' ? modeCopy.sendingAction : modeCopy.sendAction}
      </button>
      {#if !hasParticipant}
        <span class="text-xs text-text-muted">{modeCopy.missingParticipant}</span>
      {:else if missingRoles.length > 0}
        <span class="text-xs text-warning">Add a recipient for: {missingRoles.join(', ')}.</span>
      {/if}
    {:else if isLive}
      <button class="btn btn-secondary" onclick={remind} disabled={busy === 'remind'}>
        <Bell class="size-4" /> {busy === 'remind' ? 'Sending...' : 'Send reminder'}
      </button>
      <button class="btn btn-secondary" onclick={voidDoc} disabled={busy === 'void'}>
        <Ban class="size-4" /> {busy === 'void' ? 'Voiding...' : 'Void document'}
      </button>
      {#if remindedFlash !== null}
        <span class="text-xs text-success">
          Reminder sent to {remindedFlash} pending recipient{remindedFlash === 1 ? '' : 's'}.
        </span>
      {/if}
    {:else if isCompleted}
      <a class="btn btn-primary" href={finalPdfURL(documentID)} download>
        <Download class="size-4" /> {modeCopy.completedPDF}
      </a>
      <a class="btn btn-secondary" href={auditCertURL(documentID)} download>
        <FileCheck class="size-4" /> {modeCopy.auditCertificate}
      </a>
    {:else if isTerminal}
      <span class="text-sm text-text-muted capitalize">Document {status}.</span>
    {/if}
  </div>

  {#if links && links.length}
    <div class="card p-4 mt-4 border-l-4 border-warning">
      <h3 class="font-display font-extralight text-base mb-1">{modeCopy.linksTitle}</h3>
      <p class="text-xs text-text-secondary mb-3 leading-relaxed">
        {modeCopy.linksDescription}
      </p>
      <ul class="divide-y divide-border-light">
        {#each links as l (l.recipient_id)}
          <li class="flex items-center gap-2 py-2">
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium">{l.name}</div>
              <code class="font-mono text-xs text-text-muted break-all">{l.url}</code>
            </div>
            <button class="btn btn-secondary text-xs" onclick={() => copyLink(l)}>
              <Copy class="size-3" /> {copiedID === l.recipient_id ? 'Copied' : 'Copy'}
            </button>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</section>
