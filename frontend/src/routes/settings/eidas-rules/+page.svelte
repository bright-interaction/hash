<script lang="ts">
  import { onMount } from 'svelte';
  import {
    listEIDASRules,
    createEIDASRule,
    updateEIDASRule,
    deleteEIDASRule,
    seedSwedishEIDASDefaults,
    previewEIDASRules,
    type EIDASRule,
    type EIDASPreviewResult,
  } from '$lib/api/client';
  import { Scale, Trash2, Sparkles, Plus, Pencil, FlaskConical } from 'lucide-svelte';

  let rules = $state<EIDASRule[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let seeding = $state(false);

  // --- Rule-builder form state ---
  type Cond = { field: string; varKey: string; op: string; value: string };
  let showForm = $state(false);
  let editingId = $state<string | null>(null);
  let fName = $state('');
  let fTier = $state('SES');
  let fReason = $state('');
  let fPriority = $state(0);
  let fActive = $state(true);
  let combinator = $state<'all' | 'any'>('all');
  let conds = $state<Cond[]>([{ field: 'amount', varKey: '', op: '>=', value: '' }]);
  let advanced = $state(false);
  let rawJSON = $state('');
  let saving = $state(false);
  let formError = $state<string | null>(null);

  // --- Preview tester state ---
  let pvAmount = $state(0);
  let pvCountry = $state('SE');
  let pvDocType = $state('');
  let pvCurrentTier = $state('SES');
  let pvResult = $state<EIDASPreviewResult | null>(null);
  let pvBusy = $state(false);
  let pvError = $state<string | null>(null);

  const tierColor = (t: string) =>
    t === 'QES' ? 'text-warning' : t === 'AES' ? 'text-info' : 'text-text-secondary';

  const FIELDS = [
    { value: 'amount', label: 'Amount' },
    { value: 'country', label: 'Country' },
    { value: 'document_type', label: 'Document type' },
    { value: 'variable', label: 'Variable…' },
  ];
  const OP_LABEL: Record<string, string> = {
    '>=': '≥',
    '>': '>',
    '<=': '≤',
    '<': '<',
    '==': '=',
    '!=': '≠',
    in: 'in list',
  };
  function opsFor(c: Cond): string[] {
    if (c.field === 'amount') return ['>=', '>', '<=', '<', '==', '!='];
    if (c.field === 'country' || c.field === 'document_type') return ['==', '!=', 'in'];
    return ['>=', '>', '<=', '<', '==', '!=', 'in']; // variable
  }

  async function refresh() {
    loading = true;
    try {
      const res = await listEIDASRules();
      rules = res.rules ?? [];
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function seed() {
    seeding = true;
    try {
      await seedSwedishEIDASDefaults();
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      seeding = false;
    }
  }

  // --- predicate <-> builder ---
  function fieldName(c: Cond): string {
    return c.field === 'variable' ? `variables.${c.varKey.trim()}` : c.field;
  }
  function coerceValue(c: Cond): unknown {
    const numericField = c.field === 'amount';
    if (c.op === 'in') {
      return c.value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => (numericField ? Number(s) : s));
    }
    if (['>', '>=', '<', '<='].includes(c.op) || numericField) return Number(c.value);
    if (c.field === 'variable' && c.value.trim() !== '' && !Number.isNaN(Number(c.value)))
      return Number(c.value);
    return c.value;
  }
  function leafFor(c: Cond): Record<string, unknown> {
    return { field: fieldName(c), op: c.op, value: coerceValue(c) };
  }
  function buildPredicate(): unknown {
    if (advanced) return JSON.parse(rawJSON);
    const leaves = conds
      .filter((c) => fieldName(c) && c.op && c.value.trim() !== '')
      .map(leafFor);
    if (leaves.length === 0) throw new Error('Add at least one condition.');
    if (leaves.length === 1) return leaves[0];
    return { [combinator]: leaves };
  }
  function parseLeaf(p: unknown): Cond | null {
    if (!p || typeof p !== 'object') return null;
    const o = p as Record<string, unknown>;
    if (typeof o.field !== 'string' || typeof o.op !== 'string') return null;
    let field = o.field;
    let varKey = '';
    if (field.startsWith('variables.')) {
      varKey = field.slice('variables.'.length);
      field = 'variable';
    } else if (!['amount', 'country', 'document_type'].includes(field)) {
      return null;
    }
    const value = Array.isArray(o.value) ? o.value.join(', ') : String(o.value ?? '');
    return { field, varKey, op: o.op, value };
  }
  function loadPredicate(pred: unknown): boolean {
    const o = pred as Record<string, unknown> | null;
    const arr = o && (Array.isArray(o.all) ? o.all : Array.isArray(o.any) ? o.any : null);
    if (arr) {
      const parsed = arr.map(parseLeaf);
      if (parsed.some((x) => x === null)) return false;
      combinator = Array.isArray(o!.all) ? 'all' : 'any';
      conds = parsed as Cond[];
      return true;
    }
    const leaf = parseLeaf(pred);
    if (leaf) {
      combinator = 'all';
      conds = [leaf];
      return true;
    }
    return false;
  }

  function resetForm() {
    editingId = null;
    fName = '';
    fTier = 'SES';
    fReason = '';
    fPriority = 0;
    fActive = true;
    combinator = 'all';
    conds = [{ field: 'amount', varKey: '', op: '>=', value: '' }];
    advanced = false;
    rawJSON = '';
    formError = null;
  }
  function openNew() {
    resetForm();
    showForm = true;
  }
  function openEdit(r: EIDASRule) {
    if (r.required_tier === 'AES' || r.required_tier === 'QES') {
      error = `${r.required_tier} is unavailable in this production release. Deactivate or delete the rule instead.`;
      return;
    }
    resetForm();
    editingId = r.id;
    fName = r.name;
    fTier = r.required_tier;
    fReason = r.reason;
    fPriority = r.priority;
    fActive = r.active;
    if (!loadPredicate(r.predicate_json)) {
      advanced = true;
      rawJSON = JSON.stringify(r.predicate_json ?? {}, null, 2);
    }
    showForm = true;
  }
  function toggleAdvanced() {
    if (!advanced) {
      // entering advanced: seed the textarea with what the builder has
      try {
        rawJSON = JSON.stringify(buildPredicate(), null, 2);
      } catch {
        rawJSON = rawJSON || '{\n  "field": "amount",\n  "op": ">=",\n  "value": 100000\n}';
      }
      advanced = true;
    } else {
      // leaving advanced: try to map raw JSON back into the builder
      try {
        const parsed = JSON.parse(rawJSON);
        if (loadPredicate(parsed)) advanced = false;
        else formError = 'This predicate is too complex for the visual builder; staying in JSON mode.';
      } catch (e) {
        formError = 'Invalid JSON: ' + (e as Error).message;
      }
    }
  }

  function addCond() {
    conds = [...conds, { field: 'amount', varKey: '', op: '>=', value: '' }];
  }
  function removeCond(i: number) {
    conds = conds.filter((_, idx) => idx !== i);
  }

  // Live JSON preview of the predicate the form would submit.
  const predicatePreview = $derived.by(() => {
    try {
      return JSON.stringify(buildPredicate(), null, 2);
    } catch (e) {
      return '// ' + (e as Error).message;
    }
  });

  async function save() {
    formError = null;
    if (fTier !== 'SES') {
      formError = 'AES and QES are unavailable in this production release.';
      return;
    }
    if (!fName.trim()) {
      formError = 'Name is required.';
      return;
    }
    let predicate: unknown;
    try {
      predicate = buildPredicate();
    } catch (e) {
      formError = (e as Error).message;
      return;
    }
    saving = true;
    try {
      const payload = {
        name: fName.trim(),
        priority: Number(fPriority) || 0,
        predicate_json: predicate,
        required_tier: fTier,
        reason: fReason.trim(),
        active: fActive,
      };
      if (editingId) await updateEIDASRule(editingId, payload);
      else await createEIDASRule(payload);
      showForm = false;
      await refresh();
    } catch (e) {
      formError = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  async function toggleActive(r: EIDASRule) {
    if (!r.active && (r.required_tier === 'AES' || r.required_tier === 'QES')) {
      error = `${r.required_tier} is unavailable and this rule cannot be reactivated.`;
      return;
    }
    try {
      await updateEIDASRule(r.id, { active: !r.active });
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function remove(id: string) {
    if (!confirm('Delete this rule? Sends will no longer escalate based on it.')) return;
    try {
      await deleteEIDASRule(id);
      await refresh();
    } catch (e) {
      error = (e as Error).message;
    }
  }

  async function runPreview() {
    pvBusy = true;
    pvError = null;
    try {
      pvResult = await previewEIDASRules({
        amount: Number(pvAmount) || 0,
        country: pvCountry.trim(),
        document_type: pvDocType.trim(),
        current_tier: pvCurrentTier,
      });
    } catch (e) {
      pvError = (e as Error).message;
      pvResult = null;
    } finally {
      pvBusy = false;
    }
  }
</script>

<div class="px-6 py-10 max-w-5xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">Settings · Compliance</p>
      <h1 class="page-title">eIDAS routing rules</h1>
    </div>
    <div class="flex gap-2">
      <button
        class="btn btn-secondary"
        onclick={seed}
        disabled
        title="Unavailable while AES and QES signing are disabled"
      >
        <Sparkles class="size-4" /> Swedish defaults unavailable
      </button>
      <button class="btn btn-primary" onclick={openNew}>
        <Plus class="size-4" /> New rule
      </button>
    </div>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Production signing currently supports SES only. AES and QES are not
    production-capable and cannot be selected or reactivated. Existing higher-tier
    rules remain visible so you can deactivate or delete them; any document that
    requires one of those tiers is blocked rather than silently downgraded to SES.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  {#if showForm}
    <section class="card p-5 mb-6">
      <h2 class="font-display font-extralight text-lg mb-4">
        {editingId ? 'Edit rule' : 'New rule'}
      </h2>

      {#if formError}
        <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-4">
          {formError}
        </div>
      {/if}

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
        <label class="text-sm sm:col-span-2">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Name</span>
          <input
            type="text"
            bind:value={fName}
            placeholder="SES routing note"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Required tier</span>
          <select
            bind:value={fTier}
            class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          >
            <option value="SES">SES (simple)</option>
            <option value="AES" disabled>AES (unavailable)</option>
            <option value="QES" disabled>QES (unavailable)</option>
          </select>
        </label>
        <label class="text-sm">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Priority</span>
          <input
            type="number"
            bind:value={fPriority}
            class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
        <label class="text-sm sm:col-span-2">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Reason (shown to the sender when this rule blocks a send)</span>
          <input
            type="text"
            bind:value={fReason}
            placeholder="Reason shown when this rule matches."
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
          />
        </label>
      </div>

      <div class="flex items-center justify-between mb-2">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Conditions</span>
        <button class="btn btn-secondary text-xs" onclick={toggleAdvanced}>
          {advanced ? 'Visual builder' : 'Edit as JSON'}
        </button>
      </div>

      {#if advanced}
        <textarea
          bind:value={rawJSON}
          rows="8"
          spellcheck="false"
          class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm font-mono"
        ></textarea>
        <p class="text-xs text-text-muted mt-1">
          Leaf: <code class="font-mono">{'{ "field": "amount", "op": ">=", "value": 100000 }'}</code>.
          Combine with <code class="font-mono">{'{ "all": [...] }'}</code> or
          <code class="font-mono">{'{ "any": [...] }'}</code>.
        </p>
      {:else}
        {#if conds.length > 1}
          <div class="flex items-center gap-2 text-sm mb-2">
            <span class="text-text-muted">Match</span>
            <select
              bind:value={combinator}
              class="px-2 py-1 rounded-md border border-border-light bg-bg-elevated text-sm"
            >
              <option value="all">all</option>
              <option value="any">any</option>
            </select>
            <span class="text-text-muted">of the following</span>
          </div>
        {/if}
        <div class="space-y-2">
          {#each conds as c, i (i)}
            <div class="flex flex-wrap items-center gap-2">
              <select
                bind:value={c.field}
                class="px-2 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
              >
                {#each FIELDS as f}
                  <option value={f.value}>{f.label}</option>
                {/each}
              </select>
              {#if c.field === 'variable'}
                <input
                  type="text"
                  bind:value={c.varKey}
                  placeholder="variable key"
                  class="px-2 py-2 rounded-md border border-border-light bg-bg-elevated text-sm w-36"
                />
              {/if}
              <select
                bind:value={c.op}
                class="px-2 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
              >
                {#each opsFor(c) as op}
                  <option value={op}>{OP_LABEL[op]}</option>
                {/each}
              </select>
              <input
                type="text"
                bind:value={c.value}
                placeholder={c.op === 'in' ? 'SE, NO, DK' : 'value'}
                class="px-2 py-2 rounded-md border border-border-light bg-bg-elevated text-sm flex-1 min-w-[8rem]"
              />
              {#if conds.length > 1}
                <button class="btn btn-secondary text-xs" onclick={() => removeCond(i)}>
                  <Trash2 class="size-3" />
                </button>
              {/if}
            </div>
          {/each}
        </div>
        <button class="btn btn-secondary text-xs mt-2" onclick={addCond}>
          <Plus class="size-3" /> Add condition
        </button>

        <div class="mt-3">
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Predicate</span>
          <pre class="mt-1 p-3 rounded-md border border-border-light bg-bg-elevated text-xs font-mono overflow-x-auto">{predicatePreview}</pre>
        </div>
      {/if}

      <div class="flex items-center gap-4 mt-4">
        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={fActive} /> Active
        </label>
        <div class="flex gap-2 ml-auto">
          <button class="btn btn-primary" onclick={save} disabled={saving}>
            {saving ? 'Saving...' : editingId ? 'Save changes' : 'Create rule'}
          </button>
          <button class="btn btn-secondary" onclick={() => (showForm = false)}>Cancel</button>
        </div>
      </div>
    </section>
  {/if}

  <section class="card p-5 mb-6">
    <h2 class="font-display font-extralight text-lg mb-4 flex items-center gap-2">
      <Scale class="size-4" /> Active rules
    </h2>
    {#if loading}
      <p class="text-text-muted text-sm">Loading...</p>
    {:else if rules.length === 0}
      <p class="text-text-muted text-sm">
        No rules yet. Click <em>New rule</em> to add an SES routing rule.
      </p>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
            <th class="py-2">Name</th>
            <th>Tier</th>
            <th>Priority</th>
            <th>Active</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border-light">
          {#each rules as r (r.id)}
            <tr>
              <td class="py-3">
                <div class="font-medium">{r.name}</div>
                <div class="text-xs text-text-muted">{r.reason}</div>
              </td>
              <td class="font-mono text-xs {tierColor(r.required_tier)}">
                {r.required_tier}{r.required_tier === 'AES' || r.required_tier === 'QES' ? ' · unavailable' : ''}
              </td>
              <td class="font-mono text-xs">{r.priority}</td>
              <td>
                <button
                  class="text-xs font-mono underline decoration-dotted"
                  onclick={() => toggleActive(r)}
                  disabled={!r.active && (r.required_tier === 'AES' || r.required_tier === 'QES')}
                  title="Toggle active"
                >
                  {r.active ? 'yes' : 'no'}
                </button>
              </td>
              <td class="text-right whitespace-nowrap">
                <button
                  class="btn btn-secondary text-xs"
                  onclick={() => openEdit(r)}
                  disabled={r.required_tier === 'AES' || r.required_tier === 'QES'}
                  title={r.required_tier === 'AES' || r.required_tier === 'QES'
                    ? `${r.required_tier} is unavailable; deactivate or delete this rule`
                    : 'Edit rule'}
                >
                  <Pencil class="size-3" />
                </button>
                <button class="btn btn-secondary text-xs" onclick={() => remove(r.id)}>
                  <Trash2 class="size-3" />
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section class="card p-5">
    <h2 class="font-display font-extralight text-lg mb-1 flex items-center gap-2">
      <FlaskConical class="size-4" /> Test your rules
    </h2>
    <p class="text-sm text-text-secondary mb-4 leading-relaxed">
      Run a hypothetical document through the engine to see which tier it would
      require, without sending anything.
    </p>
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Amount</span>
        <input
          type="number"
          bind:value={pvAmount}
          class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </label>
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Country</span>
        <input
          type="text"
          bind:value={pvCountry}
          placeholder="SE"
          class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </label>
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Doc type</span>
        <input
          type="text"
          bind:value={pvDocType}
          placeholder="healthcare"
          class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </label>
      <label class="text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Current tier</span>
        <select
          bind:value={pvCurrentTier}
          class="block w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        >
          <option value="SES">SES</option>
          <option value="AES" disabled>AES (unavailable)</option>
          <option value="QES" disabled>QES (unavailable)</option>
        </select>
      </label>
    </div>
    <button class="btn btn-secondary" onclick={runPreview} disabled={pvBusy}>
      {pvBusy ? 'Evaluating...' : 'Evaluate'}
    </button>

    {#if pvError}
      <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mt-3">
        {pvError}
      </div>
    {/if}

    {#if pvResult}
      <div class="mt-4 p-4 rounded-md border border-border-light bg-bg-elevated">
        <div class="flex items-baseline gap-2 mb-2">
          <span class="text-sm text-text-muted">Required tier:</span>
          <span class="font-mono text-base {tierColor(pvResult.required_tier)}">{pvResult.required_tier}</span>
          {#if pvResult.required_tier === 'AES' || pvResult.required_tier === 'QES'}
            <span class="text-xs text-danger ml-2">unavailable in this release · send blocked</span>
          {:else if pvResult.would_block}
            <span class="text-xs text-danger ml-2">would block this send</span>
          {:else}
            <span class="text-xs text-success ml-2">send allowed at current tier</span>
          {/if}
        </div>
        <p class="text-xs text-text-muted mb-2">{pvResult.evaluated_count} rule(s) evaluated</p>
        {#if pvResult.matched_rules.length}
          <ul class="text-sm list-disc pl-5">
            {#each pvResult.matched_rules as m (m.id)}
              <li>
                <span class="font-medium">{m.name}</span>
                <span class="font-mono text-xs {tierColor(m.required_tier)}">→ {m.required_tier}</span>
                {#if m.reason}<span class="text-text-muted"> · {m.reason}</span>{/if}
              </li>
            {/each}
          </ul>
        {:else}
          <p class="text-sm text-text-muted">No rules matched. The document stays at SES (the floor).</p>
        {/if}
      </div>
    {/if}
  </section>
</div>
