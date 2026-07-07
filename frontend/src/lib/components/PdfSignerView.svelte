<script lang="ts">
  import { onMount, tick } from 'svelte';
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
    signed?: boolean;
    onFilledChange?: (filled: boolean) => void;
    onSignatureClick?: () => void;
  };
  let { token, signed = false, onFilledChange, onSignatureClick }: Props = $props();

  type PageInfo = { num: number; w: number };

  let pages = $state<PageInfo[]>([]);
  let fields = $state<Field[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  const buf = $state<Record<string, string>>({});
  const canvasEls: Record<number, HTMLCanvasElement> = {};
  const MAX_W = 760;

  function isFilled(f: Field): boolean {
    const v = buf[f.id] ?? '';
    if (f.type === 'checkbox') return v === 'true';
    return v.trim() !== '';
  }
  function recomputeFilled(): boolean {
    for (const f of fields) {
      if (f.type === 'signature' || !f.required) continue;
      if (!isFilled(f)) return false;
    }
    return true;
  }
  $effect(() => {
    // referencing buf + fields keeps this reactive to every keystroke.
    void JSON.stringify(buf);
    void fields.length;
    onFilledChange?.(recomputeFilled());
  });

  onMount(async () => {
    try {
      const pdf = await import('$lib/pdf');
      const fres = await fetch(`/sign/${token}/fields`);
      if (fres.ok) {
        const data = (await fres.json()) as { fields: Field[] };
        fields = data.fields ?? [];
        for (const f of fields) {
          buf[f.id] = f.value ?? (f.type === 'checkbox' ? 'false' : '');
        }
      }
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
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  });

  async function saveField(f: Field) {
    try {
      await fetch(`/sign/${token}/fields`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ values: [{ field_id: f.id, value: buf[f.id] ?? '' }] }),
      });
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function fieldsOnPage(page: number): Field[] {
    return fields.filter((f) => f.page === page);
  }
</script>

<div class="pdf-signer">
  {#if error}
    <div class="err">{error}</div>
  {/if}
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
                onclick={() => onSignatureClick?.()}
                disabled={signed}
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
                  onchange={(e) => {
                    buf[f.id] = (e.currentTarget as HTMLInputElement).checked ? 'true' : 'false';
                    saveField(f);
                  }}
                />
              </label>
            {:else if f.type === 'dropdown'}
              <select
                class="fld inp"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
                bind:value={buf[f.id]}
                onchange={() => saveField(f)}
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
                onchange={() => saveField(f)}
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
