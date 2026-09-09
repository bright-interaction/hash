<script lang="ts">
  import { onMount } from 'svelte';
  import { getBranding, saveBranding, type OrgBranding } from '$lib/api/client';
  import { Palette, Save } from 'lucide-svelte';

  let branding = $state<Partial<OrgBranding>>({});
  let loading = $state(true);
  let saving = $state(false);
  let error = $state<string | null>(null);
  let saved = $state(false);

  async function load() {
    loading = true;
    try {
      branding = await getBranding();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  onMount(load);

  async function save() {
    saving = true;
    saved = false;
    error = null;
    try {
      branding = await saveBranding(branding);
      saved = true;
      setTimeout(() => (saved = false), 2200);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  function colorField(key: keyof OrgBranding, label: string) {
    return { key, label };
  }

  const colorFields = [
    colorField('primary_hex', 'Primary'),
    colorField('accent_hex', 'Accent'),
    colorField('surface_hex', 'Surface'),
    colorField('text_hex', 'Body text'),
    colorField('muted_hex', 'Muted'),
    colorField('signature_color', 'Signature ink'),
  ];
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 flex items-baseline justify-between">
    <div class="space-y-2">
      <p class="page-eyebrow">Settings · Branding</p>
      <h1 class="page-title">Brand theme</h1>
    </div>
    <button class="btn btn-primary" onclick={save} disabled={saving || loading}>
      <Save class="size-4" /> {saving ? 'Saving...' : 'Save changes'}
    </button>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Colors below feed every rendered document, signer page, and audit
    certificate via CSS custom properties. Body-text contrast is
    enforced server-side to meet WCAG AA against your surface color.
    Self-hosted fonts only (no third-party CDN).
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}
  {#if saved}
    <div class="card p-3 mb-4 text-success text-sm">Branding saved.</div>
  {/if}

  {#if loading}
    <p class="text-text-muted">Loading...</p>
  {:else}
    <section class="card p-5 mb-6">
      <h2 class="font-display font-extralight text-lg mb-4 flex items-center gap-2">
        <Palette class="size-4" /> Palette
      </h2>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {#each colorFields as f (f.key)}
          <label class="flex items-center gap-3 text-sm">
            <input
              type="color"
              value={branding[f.key] || '#000000'}
              oninput={(e) => {
                branding = { ...branding, [f.key]: (e.target as HTMLInputElement).value };
              }}
              class="h-10 w-12 cursor-pointer border border-border-light rounded"
            />
            <div class="flex-1">
              <div class="text-xs uppercase tracking-widest text-text-muted font-mono">{f.label}</div>
              <input
                type="text"
                value={branding[f.key] || ''}
                oninput={(e) => {
                  branding = { ...branding, [f.key]: (e.target as HTMLInputElement).value };
                }}
                placeholder="#000000"
                class="font-mono text-xs w-full bg-bg-elevated border border-border-light rounded px-2 py-1"
              />
            </div>
          </label>
        {/each}
      </div>
    </section>

    <section class="card p-5 mb-6">
      <h2 class="font-display font-extralight text-lg mb-4">Logo</h2>
      <label class="block text-sm mb-3">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Logo URL</span>
        <input
          type="url"
          bind:value={branding.logo_url}
          placeholder="https://your.cdn/logo.png"
          class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </label>
      <label class="block text-sm">
        <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Logo alt text</span>
        <input
          type="text"
          bind:value={branding.logo_alt}
          placeholder="Acme Inc."
          class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated text-sm"
        />
      </label>
      <p class="text-xs text-text-muted mt-3">
        Logo URLs and Hash-hosted logo uploads are disabled in production until
        each asset is pinned to an exact retained storage version. Palette and
        font settings remain available and are frozen when a document is sent.
      </p>
    </section>

    <section class="card p-5">
      <h2 class="font-display font-extralight text-lg mb-4">Type</h2>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
        <label>
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Heading family</span>
          <input
            type="text"
            bind:value={branding.font_heading}
            placeholder="Geist, Inter, sans-serif"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated"
          />
        </label>
        <label>
          <span class="text-xs uppercase tracking-widest text-text-muted font-mono">Body family</span>
          <input
            type="text"
            bind:value={branding.font_body}
            placeholder="Inter, system-ui, sans-serif"
            class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated"
          />
        </label>
      </div>
      <p class="text-xs text-text-muted mt-3">
        Only families embedded in Hash's PDF renderer (Inter, Geist,
        plus the calligraphy set) resolve consistently; unknown
        families fall back to <code class="font-mono">system-ui</code>.
      </p>
    </section>
  {/if}
</div>
