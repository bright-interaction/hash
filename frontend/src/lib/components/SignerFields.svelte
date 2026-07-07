<script lang="ts">
  // SignerFields renders the v1.2 fillable-field panel on the signer
  // page. It fetches /sign/{token}/fields, renders one input per field
  // (text / date / checkbox / dropdown / initial), and submits values
  // back to /sign/{token}/fields when the signer clicks "Save fields".
  //
  // The parent gates the typed-name signature button on `allFilled` so
  // a signer cannot sign before required fields are populated. The
  // backend enforces the same gate (sign.Engine.Sign refuses with "N
  // required field(s) unfilled") so a malicious client can't skip.
  import { onMount } from 'svelte';
  import { CheckCircle2, Loader2 } from 'lucide-svelte';
  import { t } from '$lib/i18n';

  type Field = {
    id: string;
    type: 'text' | 'date' | 'checkbox' | 'dropdown' | 'initial';
    label?: string;
    required: boolean;
    value?: string;
    completed_at?: string;
    options?: { choices?: string[] };
  };

  let { token, onChange }: { token: string; onChange: (filled: boolean) => void } = $props();

  let fields = $state<Field[]>([]);
  let loaded = $state(false);
  let saving = $state(false);
  let saveError = $state<string | null>(null);
  let savedAt = $state<string | null>(null);

  // Local edit buffer keyed by field id so a signer can revise before
  // saving. Initialised from server `value` when fields load.
  const buf = $state<Record<string, string>>({});

  function isFilled(f: Field, v: string): boolean {
    if (f.type === 'checkbox') {
      return v === 'true';
    }
    return v.trim() !== '';
  }

  function recomputeFilled(): boolean {
    if (fields.length === 0) return true;
    for (const f of fields) {
      if (!f.required) continue;
      const v = buf[f.id] ?? '';
      if (!isFilled(f, v)) return false;
    }
    return true;
  }

  $effect(() => {
    onChange(recomputeFilled());
  });

  onMount(async () => {
    try {
      const res = await fetch(`/sign/${token}/fields`);
      if (!res.ok) {
        // Endpoint may 404 on legacy docs without fields wired; treat
        // as zero-fields so the signer flow still works.
        loaded = true;
        return;
      }
      const data = await res.json() as { fields: Field[] };
      // Signature fields are signed via the sign step, not filled here; the
      // list now includes them (for the pdf signer overlay) so drop them.
      fields = (data.fields ?? []).filter((f) => (f.type as string) !== 'signature');
      for (const f of fields) {
        buf[f.id] = f.value ?? (f.type === 'checkbox' ? 'false' : '');
      }
      loaded = true;
    } catch (e) {
      saveError = (e as Error).message;
      loaded = true;
    }
  });

  async function save() {
    saving = true;
    saveError = null;
    try {
      const values = fields.map((f) => ({ field_id: f.id, value: buf[f.id] ?? '' }));
      const res = await fetch(`/sign/${token}/fields`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ values })
      });
      if (!res.ok) {
        saveError = await res.text();
        return;
      }
      // Refresh from server so completed_at timestamps populate.
      const data = await res.json() as { updated: Field[] };
      for (const u of data.updated) {
        const idx = fields.findIndex((x) => x.id === u.id);
        if (idx >= 0) {
          fields[idx] = { ...fields[idx], ...u };
        }
      }
      savedAt = new Date().toISOString();
    } catch (e) {
      saveError = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  function dropdownChoices(f: Field): string[] {
    return f.options?.choices ?? [];
  }
</script>

{#if !loaded}
  <div class="fields-loading">
    <Loader2 class="size-4 animate-spin" />
    <span>{$t('fields.loading')}</span>
  </div>
{:else if fields.length > 0}
  <h3 class="section-eyebrow">{$t('fields.required')}</h3>
  <p class="text-xs text-text-muted mb-3">{$t('fields.intro')}</p>

  <div class="fields-list">
    {#each fields as f (f.id)}
      <label class="field-row">
        <span class="field-label">
          {f.label ?? f.type}{#if f.required}<span class="req"> *</span>{/if}
          {#if f.completed_at}
            <CheckCircle2 class="size-3 inline text-success ml-1" />
          {/if}
        </span>

        {#if f.type === 'text'}
          <input
            type="text"
            class="field-input"
            bind:value={buf[f.id]}
            placeholder={f.label ?? ''}
          />
        {:else if f.type === 'date'}
          <input type="date" class="field-input" bind:value={buf[f.id]} />
        {:else if f.type === 'initial'}
          <input
            type="text"
            class="field-input"
            maxlength="6"
            placeholder={$t('fields.initials')}
            bind:value={buf[f.id]}
          />
        {:else if f.type === 'checkbox'}
          <input
            type="checkbox"
            checked={buf[f.id] === 'true'}
            onchange={(e) => (buf[f.id] = (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false')}
          />
        {:else if f.type === 'dropdown'}
          <select class="field-input" bind:value={buf[f.id]}>
            <option value="">,  select ,</option>
            {#each dropdownChoices(f) as choice (choice)}
              <option value={choice}>{choice}</option>
            {/each}
          </select>
        {/if}
      </label>
    {/each}
  </div>

  <button
    type="button"
    class="btn btn-secondary w-full mt-3"
    disabled={saving}
    onclick={save}
  >
    {saving ? $t('fields.saving') : $t('fields.save')}
  </button>

  {#if saveError}
    <p class="error mt-2">{saveError}</p>
  {/if}
  {#if savedAt && !saveError}
    <p class="text-xs text-text-muted mt-2">
      {$t('fields.savedAt', { time: new Date(savedAt).toLocaleTimeString() })}
    </p>
  {/if}
{/if}

<style>
  .fields-loading {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-size: 0.85rem;
    color: var(--hash-text-muted, #6b7280);
    margin-bottom: 1rem;
  }
  .fields-list {
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
  }
  .field-row {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .field-label {
    font-size: 0.8rem;
    color: var(--hash-text, #111);
    font-weight: 500;
  }
  .field-label .req {
    color: #c0392b;
  }
  .field-input {
    width: 100%;
    padding: 0.5rem 0.65rem;
    border-radius: 0.4rem;
    border: 1px solid var(--hash-border, #d1d5db);
    background: #fff;
    font-size: 0.9rem;
  }
  .field-input:focus {
    outline: 2px solid var(--hash-accent, #2563eb);
    outline-offset: 1px;
  }
  .error {
    color: #c0392b;
    font-size: 0.8rem;
  }
</style>
