<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { signerNoticeHeaders } from '$lib/api/signerNotice';
  import { t } from '$lib/i18n';

  type Field = {
    id: string;
    type: string;
    page: number;
    x_pct: number;
    y_pct: number;
    w_pct: number;
    h_pct: number;
    required: boolean;
    label?: string;
    value?: string;
    options?: { choices?: string[] };
  };

  type Props = {
    token: string;
    noticeDigest: string;
    signed?: boolean;
    onFilledChange?: (filled: boolean) => void;
    onSignatureClick?: () => void;
  };
  let { token, noticeDigest, signed = false, onFilledChange, onSignatureClick }: Props = $props();

  type PageInfo = { num: number; w: number };

  let pages = $state<PageInfo[]>([]);
  let fields = $state<Field[]>([]);
  let fieldsLoaded = $state(false);
  let loading = $state(true);
  let error = $state<string | null>(null);
  const buf = $state<Record<string, string>>({});
  const persisted = $state<Record<string, string>>({});
  const saving = $state<Record<string, boolean>>({});
  const saveErrors = $state<Record<string, string>>({});
  const canvasEls: Record<number, HTMLCanvasElement> = {};
  const MAX_W = 760;

  function emptyValue(f: Field): string {
    return f.type === 'checkbox' ? 'false' : '';
  }

  function isFilled(f: Field, v: string): boolean {
    if (f.type === 'checkbox') return v === 'true';
    return v.trim() !== '';
  }

  function recomputeFilled(): boolean {
    if (!fieldsLoaded) return false;
    if (Object.keys(saveErrors).length > 0) return false;
    for (const f of fields) {
      if (f.type === 'signature') continue;
      const draftValue = buf[f.id] ?? emptyValue(f);
      const persistedValue = persisted[f.id] ?? emptyValue(f);
      // Do not let signing race an autosave or proceed with a value that the
      // server has not confirmed. This also protects optional edits from being
      // silently lost when the recipient signs immediately after changing one.
      if (saving[f.id] || draftValue !== persistedValue) return false;
      if (f.required && !isFilled(f, persistedValue)) return false;
    }
    return true;
  }

  $effect(() => {
    // Referencing each state object keeps the parent gate reactive to field
    // loading, every keystroke, and every autosave transition.
    void fieldsLoaded;
    void JSON.stringify(buf);
    void JSON.stringify(persisted);
    void JSON.stringify(saving);
    void JSON.stringify(saveErrors);
    void fields.length;
    onFilledChange?.(recomputeFilled());
  });

  onMount(async () => {
    try {
      const fres = await fetch(`/sign/${token}/fields`);
      if (!fres.ok) {
        throw new Error(await responseError(fres));
      }
      const data = (await fres.json()) as { fields: Field[] };
      fields = data.fields ?? [];
      for (const f of fields) {
        const value = f.value ?? emptyValue(f);
        buf[f.id] = value;
        persisted[f.id] = value;
      }
      fieldsLoaded = true;
    } catch (e) {
      error = `Unable to load document fields: ${errorMessage(e)}`;
    }

    try {
      const pdf = await import('$lib/pdf');
      const doc = await pdf.loadPdf(`/sign/${token}/pdf`);
      const infos: PageInfo[] = [];
      const scales: number[] = [];
      for (let n = 1; n <= doc.numPages; n++) {
        const natural = await pdf.unscaledWidth(doc, n);
        scales[n] = Math.min(MAX_W / natural, 2);
        infos.push({ num: n, w: 0 });
      }
      pages = infos;
      await tick();
      for (const p of pages) {
        const el = canvasEls[p.num];
        if (!el) continue;
        const dim = await pdf.renderPage(doc, p.num, el, scales[p.num]);
        p.w = dim.width;
      }
      pages = [...pages];
    } catch (e) {
      const message = `Unable to load document: ${errorMessage(e)}`;
      error = error ? `${error} ${message}` : message;
    } finally {
      loading = false;
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
      // A plain-text response is already suitable for the visible error below.
    }
    return body;
  }

  async function saveField(f: Field) {
    const nextValue = buf[f.id] ?? emptyValue(f);
    const previousValue = persisted[f.id] ?? emptyValue(f);
    if (saving[f.id] || nextValue === previousValue) return;

    saving[f.id] = true;
    delete saveErrors[f.id];
    try {
      const res = await fetch(`/sign/${token}/fields`, {
        method: 'POST',
        headers: signerNoticeHeaders(noticeDigest, true),
        body: JSON.stringify({ values: [{ field_id: f.id, value: nextValue }] }),
      });
      if (!res.ok) {
        throw new Error(await responseError(res));
      }

      const data = (await res.json()) as { updated?: Field[] };
      const updated = data.updated?.find((candidate) => candidate.id === f.id);
      if (!updated) {
        throw new Error('The server did not confirm the saved field.');
      }

      const confirmedValue = updated.value ?? emptyValue(f);
      persisted[f.id] = confirmedValue;
      buf[f.id] = confirmedValue;
      const index = fields.findIndex((candidate) => candidate.id === f.id);
      if (index >= 0) {
        fields[index] = { ...fields[index], ...updated };
        fields = [...fields];
      }
    } catch (e) {
      // A failed request may not have reached the server. Revert the visible
      // control to the last confirmed value so the UI and signing gate agree
      // with the durable ceremony state.
      buf[f.id] = previousValue;
      saveErrors[f.id] = errorMessage(e);
    } finally {
      saving[f.id] = false;
    }
  }

  function fieldsOnPage(page: number): Field[] {
    return fields.filter((f) => f.page === page);
  }

  function fieldName(fieldID: string): string {
    const field = fields.find((candidate) => candidate.id === fieldID);
    return field?.label || field?.type || 'field';
  }
</script>

<div class="pdf-signer">
  {#if error}
    <div class="err" role="alert">{error}</div>
  {/if}
  {#each Object.entries(saveErrors) as [fieldID, message] (fieldID)}
    <div class="err" role="alert">Could not save {fieldName(fieldID)}: {message}</div>
  {/each}
  {#if loading}
    <p class="muted">{$t('pdf.loading')}</p>
  {:else}
    {#each pages as p (p.num)}
      <div class="page" style="width:{p.w}px">
        <canvas bind:this={canvasEls[p.num]}></canvas>
        <div class="overlay">
          {#each fieldsOnPage(p.num) as f (f.id)}
            {#if f.type === 'signature'}
              <button
                type="button"
                class="fld sig"
                class:done={signed}
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                onclick={() => {
                  if (recomputeFilled()) onSignatureClick?.();
                }}
                disabled={signed || !recomputeFilled()}
                title={!recomputeFilled() ? $t('sign.fillRequiredTitle') : ''}
              >
                {signed ? $t('pdf.signed') : $t('pdf.signHere')}
              </button>
            {:else if f.type === 'checkbox'}
              <label
                class="fld chk"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
              >
                <input
                  type="checkbox"
                  checked={buf[f.id] === 'true'}
                  class:save-failed={Boolean(saveErrors[f.id])}
                  aria-invalid={Boolean(saveErrors[f.id])}
                  aria-busy={Boolean(saving[f.id])}
                  disabled={Boolean(saving[f.id])}
                  onchange={(e) => {
                    buf[f.id] = (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false';
                    void saveField(f);
                  }}
                />
              </label>
            {:else if f.type === 'dropdown'}
              <select
                class="fld inp"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                bind:value={buf[f.id]}
                class:save-failed={Boolean(saveErrors[f.id])}
                aria-invalid={Boolean(saveErrors[f.id])}
                aria-busy={Boolean(saving[f.id])}
                disabled={Boolean(saving[f.id])}
                onchange={() => void saveField(f)}
              >
                <option value="">{f.label || 'Select…'}</option>
                {#each f.options?.choices ?? [] as c}
                  <option value={c}>{c}</option>
                {/each}
              </select>
            {:else}
              <input
                class="fld inp"
                type={f.type === 'date' ? 'date' : 'text'}
                placeholder={f.label || f.type}
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                bind:value={buf[f.id]}
                class:save-failed={Boolean(saveErrors[f.id])}
                aria-invalid={Boolean(saveErrors[f.id])}
                aria-busy={Boolean(saving[f.id])}
                disabled={Boolean(saving[f.id])}
                onchange={() => void saveField(f)}
              />
            {/if}
          {/each}
        </div>
      </div>
    {/each}
  {/if}
</div>

<style>
  .pdf-signer {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    align-items: center;
  }
  .page {
    position: relative;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.12);
    border: 1px solid var(--color-border-light, #e5e5e5);
  }
  .page canvas {
    display: block;
  }
  .overlay {
    position: absolute;
    inset: 0;
  }
  .fld {
    position: absolute;
    box-sizing: border-box;
    font-size: 12px;
  }
  .inp {
    border: 1px solid var(--color-accent, #4f46e5);
    background: rgba(79, 70, 229, 0.06);
    border-radius: 3px;
    padding: 0 4px;
  }
  .save-failed {
    border-color: var(--color-danger, #dc2626);
    outline: 2px solid rgba(220, 38, 38, 0.18);
  }
  .chk {
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .sig {
    border: 2px dashed var(--color-accent, #171717);
    background: rgba(23, 23, 23, 0.06);
    color: var(--color-accent, #171717);
    border-radius: 4px;
    font-weight: 600;
    cursor: pointer;
  }
  .sig.done {
    border-style: solid;
    color: var(--color-success, #15803d);
    border-color: var(--color-success, #15803d);
    background: rgba(21, 128, 61, 0.08);
  }
  .err {
    color: var(--color-danger, #dc2626);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }
  .muted {
    color: var(--color-text-muted, #777);
    font-size: 0.875rem;
  }
</style>
