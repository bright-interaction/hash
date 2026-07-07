<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    listFields,
    addField,
    deleteField,
    listRecipients,
    documentPdfURL,
    type DocumentField,
    type Recipient,
  } from '$lib/api/client';
  import { PenLine, Type, Calendar, CheckSquare, Trash2, Signature } from 'lucide-svelte';

  type Props = { documentID: string };
  let { documentID }: Props = $props();

  type PageInfo = { num: number; w: number; h: number; scale: number };

  let pages = $state<PageInfo[]>([]);
  let fields = $state<DocumentField[]>([]);
  let recipients = $state<Recipient[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);

  // Tool palette.
  const TOOLS = [
    { type: 'signature', label: 'Signature', icon: Signature },
    { type: 'text', label: 'Text', icon: Type },
    { type: 'date', label: 'Date', icon: Calendar },
    { type: 'checkbox', label: 'Checkbox', icon: CheckSquare },
    { type: 'initial', label: 'Initial', icon: PenLine },
  ];
  let tool = $state('signature');
  let recipientID = $state('');
  let required = $state(true);

  // Drag-to-place state, in page-percentage coordinates.
  let draft = $state<{ page: number; x: number; y: number; w: number; h: number } | null>(null);
  let dragStart: { page: number; x: number; y: number } | null = null;

  const canvasEls: Record<number, HTMLCanvasElement> = {};
  const MAX_W = 760;

  onMount(async () => {
    try {
      const pdf = await import('$lib/pdf');
      const [recs, fs, doc] = await Promise.all([
        listRecipients(documentID),
        listFields(documentID),
        pdf.loadPdf(documentPdfURL(documentID)),
      ]);
      recipients = recs;
      fields = fs;
      if (recs.length) recipientID = recs[0].id;

      const infos: PageInfo[] = [];
      for (let n = 1; n <= doc.numPages; n++) {
        const natural = await pdf.unscaledWidth(doc, n);
        const scale = Math.min(MAX_W / natural, 2);
        infos.push({ num: n, w: 0, h: 0, scale });
      }
      pages = infos;
      await tick();
      // Render each page into its bound canvas, recording the rendered size.
      for (const p of pages) {
        const el = canvasEls[p.num];
        if (!el) continue;
        const dim = await pdf.renderPage(doc, p.num, el, p.scale);
        p.w = dim.width;
        p.h = dim.height;
      }
      pages = [...pages];
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  });

  function recipientName(id?: string): string {
    if (!id) return 'Any recipient';
    const r = recipients.find((x) => x.id === id);
    return r ? r.name : 'recipient';
  }

  function pctFromEvent(e: PointerEvent, layer: HTMLElement) {
    const rect = layer.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * 100,
      y: ((e.clientY - rect.top) / rect.height) * 100,
    };
  }

  function onPointerDown(e: PointerEvent, page: number, layer: HTMLElement) {
    if (e.button !== 0) return;
    if (tool === 'signature' && !recipientID) {
      error = 'Pick a recipient before placing a signature field.';
      return;
    }
    error = null;
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
    const p = pctFromEvent(e, layer);
    dragStart = { page, x: p.x, y: p.y };
    draft = { page, x: p.x, y: p.y, w: 0, h: 0 };
  }

  function onPointerMove(e: PointerEvent, layer: HTMLElement) {
    if (!dragStart) return;
    const p = pctFromEvent(e, layer);
    draft = {
      page: dragStart.page,
      x: Math.min(dragStart.x, p.x),
      y: Math.min(dragStart.y, p.y),
      w: Math.abs(p.x - dragStart.x),
      h: Math.abs(p.y - dragStart.y),
    };
  }

  async function onPointerUp() {
    const d = draft;
    dragStart = null;
    draft = null;
    if (!d) return;
    // A click (no real drag) drops a sensibly sized default box.
    if (d.w < 1.5 || d.h < 1) {
      d.w = tool === 'signature' ? 26 : 18;
      d.h = tool === 'signature' ? 7 : 4;
    }
    try {
      const created = await addField(documentID, {
        type: tool,
        page: d.page,
        x_pct: round(d.x),
        y_pct: round(d.y),
        w_pct: round(d.w),
        h_pct: round(d.h),
        required,
        recipient_id: recipientID || undefined,
        label: TOOLS.find((t) => t.type === tool)?.label,
      });
      fields = [...fields, created];
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function round(n: number): number {
    return Math.round(n * 1000) / 1000;
  }

  async function remove(f: DocumentField) {
    try {
      await deleteField(f.id);
      fields = fields.filter((x) => x.id !== f.id);
    } catch (e) {
      error = (e as Error).message;
    }
  }

  function fieldsOnPage(page: number): DocumentField[] {
    return fields.filter((f) => f.page === page);
  }

  function boxClass(type: string): string {
    return type === 'signature'
      ? 'border-accent bg-accent/10 text-accent'
      : 'border-info bg-info/10 text-info';
  }
</script>

<section class="card p-5 mb-6">
  <div class="flex items-center justify-between mb-3">
    <h2 class="font-display font-extralight text-lg flex items-center gap-2">
      <Signature class="size-4" /> Field designer
    </h2>
  </div>
  <p class="text-sm text-text-secondary mb-4 leading-relaxed">
    Pick a field type, then click (or drag a box) on the page to place it. Each
    signer fills their fields and signs where you drop a signature field; the
    values stamp onto the final PDF at exactly these positions.
  </p>

  <!-- Toolbar -->
  <div class="flex flex-wrap items-end gap-3 mb-4 pb-4 border-b border-border-light">
    <div class="flex flex-wrap gap-1">
      {#each TOOLS as t}
        <button
          class="btn text-xs {tool === t.type ? 'btn-primary' : 'btn-secondary'}"
          onclick={() => (tool = t.type)}
        >
          <t.icon class="size-3" /> {t.label}
        </button>
      {/each}
    </div>
    <label class="text-sm">
      <span class="block text-xs uppercase tracking-widest text-text-muted font-mono mb-1">Recipient</span>
      <select
        bind:value={recipientID}
        class="px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
      >
        {#if tool !== 'signature'}
          <option value="">Any recipient</option>
        {/if}
        {#each recipients as r (r.id)}
          <option value={r.id}>{r.name}</option>
        {/each}
      </select>
    </label>
    <label class="flex items-center gap-2 text-sm pb-2">
      <input type="checkbox" bind:checked={required} /> Required
    </label>
  </div>

  {#if error}
    <div class="p-3 rounded-md border border-danger bg-bg-elevated text-danger text-sm mb-3">{error}</div>
  {/if}

  {#if recipients.length === 0 && !loading}
    <div class="p-3 rounded-md border border-warning bg-bg-elevated text-sm mb-3">
      Add recipients first so signature fields can be assigned to a signer.
    </div>
  {/if}

  {#if loading}
    <p class="text-text-muted text-sm">Loading PDF...</p>
  {:else}
    <div class="space-y-6">
      {#each pages as p (p.num)}
        <div class="relative mx-auto shadow-sm border border-border-light" style="width:{p.w}px">
          <canvas bind:this={canvasEls[p.num]} class="block"></canvas>
          <!-- Field overlay layer (same pixel box as the canvas) -->
          <div
            class="absolute inset-0 cursor-crosshair"
            role="application"
            tabindex="-1"
            aria-label="Field placement layer for page {p.num}"
            onpointerdown={(e) => onPointerDown(e, p.num, e.currentTarget as HTMLElement)}
            onpointermove={(e) => onPointerMove(e, e.currentTarget as HTMLElement)}
            onpointerup={onPointerUp}
            onpointerleave={onPointerUp}
          >
            {#each fieldsOnPage(p.num) as f (f.id)}
              <div
                class="absolute border-2 rounded flex items-center justify-between gap-1 px-1 text-[10px] font-mono {boxClass(f.type)}"
                style="left:{f.x_pct}%;top:{f.y_pct}%;width:{f.w_pct}%;height:{f.h_pct}%"
              >
                <span class="truncate">{f.type === 'signature' ? recipientName(f.recipient_id) : f.label || f.type}</span>
                <button
                  type="button"
                  class="shrink-0 hover:text-danger"
                  aria-label="Remove field"
                  onpointerdown={(e) => e.stopPropagation()}
                  onclick={() => remove(f)}
                >
                  <Trash2 class="size-3" />
                </button>
              </div>
            {/each}
            {#if draft && draft.page === p.num}
              <div
                class="absolute border-2 border-dashed border-accent bg-accent/10 pointer-events-none rounded"
                style="left:{draft.x}%;top:{draft.y}%;width:{draft.w}%;height:{draft.h}%"
              ></div>
            {/if}
          </div>
          <span class="absolute -top-3 left-2 text-[10px] font-mono text-text-muted bg-bg-surface px-1">
            Page {p.num}
          </span>
        </div>
      {/each}
    </div>
  {/if}
</section>
