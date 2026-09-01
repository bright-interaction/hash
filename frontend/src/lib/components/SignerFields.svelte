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
  import { signerNoticeHeaders } from '$lib/api/signerNotice';
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

  let { token, noticeDigest, onChange }: {
    token: string;
    noticeDigest: string;
    onChange: (filled: boolean) => void;
  } = $props();

  let fields = $state<Field[]>([]);
  let fieldsLoaded = $state(false);
  let saving = $state(false);
  let loadError = $state<string | null>(null);
  let saveError = $state<string | null>(null);
  let savedAt = $state<string | null>(null);

  // Local edit buffer keyed by field id so a signer can revise before
  // saving. Initialised from server `value` when fields load.
  const buf = $state<Record<string, string>>({});
  // The last values explicitly confirmed by the server. The parent signing
  // gate stays closed while any local edit differs from this snapshot, even
  // when the edit is optional, so signing cannot silently discard it.
  const persisted = $state<Record<string, string>>({});

  function emptyValue(f: Field): string {
    return f.type === 'checkbox' ? 'false' : '';
  }

  function isFilled(f: Field, v: string): boolean {
    if (f.type === 'checkbox') {
      return v === 'true';
    }
    return v.trim() !== '';
  }

  function recomputeFilled(): boolean {
    if (!fieldsLoaded) return false;
    if (loadError || saveError || saving) return false;
    for (const f of fields) {
      const draftValue = buf[f.id] ?? emptyValue(f);
      const persistedValue = persisted[f.id] ?? emptyValue(f);
      if (draftValue !== persistedValue) return false;
      if (f.required && !isFilled(f, persistedValue)) return false;
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
        throw new Error(await responseError(res));
      }
      const data = await res.json() as { fields?: unknown };
      if (!Array.isArray(data.fields)) {
        throw new Error('The server did not return a valid field list.');
      }
      // Signature fields are signed via the sign step, not filled here; the
      // list now includes them (for the pdf signer overlay) so drop them.
      fields = (data.fields as Field[]).filter((f) => (f.type as string) !== 'signature');
      for (const f of fields) {
        const value = f.value ?? emptyValue(f);
        buf[f.id] = value;
        persisted[f.id] = value;
      }
    } catch (e) {
      loadError = `Unable to load document fields: ${errorMessage(e)}`;
    } finally {
      fieldsLoaded = true;
    }
  });

  function errorMessage(value: unknown): string {
    return value instanceof Error && value.message ? value.message : 'The request failed.';
  }

  async function responseError(res: Response): Promise<string> {
    const fallback = `The request failed (${res.status}).`;
    const body = (await res.text()).trim();
    if (!body) return fallback;
    try {
      const parsed = JSON.parse(body) as { error?: unknown };
      if (typeof parsed.error === 'string' && parsed.error.trim()) return parsed.error.trim();
    } catch {
      // Plain-text handler errors are already suitable for the visible alert.
    }
    return body;
  }

  async function save() {
    if (!fieldsLoaded || loadError || saving) return;
    saving = true;
    saveError = null;
    savedAt = null;
    try {
      const values = fields.map((f) => ({ field_id: f.id, value: buf[f.id] ?? emptyValue(f) }));
      const res = await fetch(`/sign/${token}/fields`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({ values })
      });
      if (!res.ok) {
        throw new Error(await responseError(res));
      }
      // Refresh from server so completed_at timestamps populate.
      const data = await res.json() as { updated?: unknown };
      if (!Array.isArray(data.updated)) {
        throw new Error('The server did not confirm the saved fields.');
      }
      const confirmed = data.updated as Field[];
      for (const f of fields) {
        const updated = confirmed.find((candidate) => candidate.id === f.id);
        if (!updated) {
          throw new Error(`The server did not confirm field ${f.label || f.type}.`);
        }
        const confirmedValue = updated.value ?? emptyValue(f);
        persisted[f.id] = confirmedValue;
        buf[f.id] = confirmedValue;
        const idx = fields.findIndex((candidate) => candidate.id === f.id);
        fields[idx] = { ...fields[idx], ...updated };
      }
      fields = [...fields];
      savedAt = new Date().toISOString();
    } catch (e) {
      // A failed or malformed response cannot advance the signing gate. Revert
      // every control to the last server-confirmed snapshot so the UI cannot
      // imply that an unconfirmed value belongs to the durable ceremony.
      for (const f of fields) {
        buf[f.id] = persisted[f.id] ?? emptyValue(f);
      }
      saveError = errorMessage(e);
    } finally {
      saving = false;
    }
  }

  function dropdownChoices(f: Field): string[] {
    return f.options?.choices ?? [];
  }
</script>

{#if !fieldsLoaded}
  <div class="fields-loading">
    <Loader2 class="size-4 animate-spin" />
    <span>{$t('fields.loading')}</span>
  </div>
{:else if loadError}
  <p class="error mt-2" role="alert">{loadError}</p>
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
            disabled={saving}
            bind:value={buf[f.id]}
            placeholder={f.label ?? ''}
          />
        {:else if f.type === 'date'}
          <input type="date" class="field-input" disabled={saving} bind:value={buf[f.id]} />
        {:else if f.type === 'initial'}
          <input
            type="text"
            class="field-input"
            disabled={saving}
            maxlength="6"
            placeholder={$t('fields.initials')}
            bind:value={buf[f.id]}
          />
        {:else if f.type === 'checkbox'}
          <input
            type="checkbox"
            checked={buf[f.id] === 'true'}
            disabled={saving}
            onchange={(e) => (buf[f.id] = (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false')}
          />
        {:else if f.type === 'dropdown'}
          <select class="field-input" disabled={saving} bind:value={buf[f.id]}>
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
    <p class="error mt-2" role="alert">{saveError}</p>
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
