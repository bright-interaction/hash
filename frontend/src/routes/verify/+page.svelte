<script lang="ts">
  import { onMount } from 'svelte';
  import { ShieldCheck, ShieldAlert, Key, Upload, FileCheck2, CheckCircle2, XCircle } from 'lucide-svelte';

  type VerifyBundleCheck = {
    name: string;
    ok: boolean;
    expected: string;
    actual: string;
    detail?: string;
  };
  type VerifyBundleReport = {
    ok: boolean;
    document_id: string;
    document_name: string;
    issuer: string;
    generated_at: string;
    signature_valid: boolean;
    signature_note?: string;
    public_key_b64?: string;
    checks: VerifyBundleCheck[];
    errors?: string[];
  };

  let serverPubKey = $state<string>('');
  let pubKey = $state('');
  let payload = $state('');
  let sig = $state('');
  let result = $state<'idle' | 'valid' | 'invalid' | 'error'>('idle');
  let errorMsg = $state<string | null>(null);

  let dragging = $state(false);
  let bundleReport = $state<VerifyBundleReport | null>(null);
  let bundleError = $state<string | null>(null);
  let bundleLoading = $state(false);

  onMount(async () => {
    try {
      const res = await fetch('/.well-known/hash-public-key');
      if (res.ok) {
        const body = await res.json();
        serverPubKey = body.public_key_b64 ?? '';
        if (!pubKey && serverPubKey) pubKey = serverPubKey;
      }
    } catch (_) {
      // best-effort; user can still paste a key manually
    }
  });

  async function check(e: Event) {
    e.preventDefault();
    result = 'idle';
    errorMsg = null;
    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          public_key_b64: pubKey.trim(),
          payload,
          signature_b64: sig.trim()
        })
      });
      if (!res.ok) {
        result = 'error';
        errorMsg = await res.text();
        return;
      }
      const body = await res.json();
      result = body.valid ? 'valid' : 'invalid';
    } catch (e) {
      result = 'error';
      errorMsg = (e as Error).message;
    }
  }

  async function verifyBundle(file: File) {
    bundleError = null;
    bundleReport = null;
    bundleLoading = true;
    try {
      const form = new FormData();
      form.append('bundle', file);
      const res = await fetch('/api/verify-bundle', {
        method: 'POST',
        body: form
      });
      if (!res.ok) {
        bundleError = await res.text();
        return;
      }
      bundleReport = (await res.json()) as VerifyBundleReport;
    } catch (e) {
      bundleError = (e as Error).message;
    } finally {
      bundleLoading = false;
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.pdf')) {
      bundleError = 'expected a Hash evidence bundle PDF';
      return;
    }
    verifyBundle(file);
  }

  function onPick(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) verifyBundle(file);
  }

  function abbrev(hex: string): string {
    if (!hex) return '';
    if (hex.length <= 16) return hex;
    return hex.slice(0, 8) + '…' + hex.slice(-8);
  }
</script>

<div class="min-h-screen bg-bg">
  <header class="border-b border-border-light px-6 py-4">
    <a href="/" class="font-display font-extralight text-lg">Hash</a>
  </header>

  <main class="max-w-3xl mx-auto px-6 py-12">
    <p class="page-eyebrow mb-3">Audit certificate verification</p>
    <h1 class="page-title mb-3">Verify a Hash-issued signature</h1>
    <p class="text-text-secondary text-sm mb-8 leading-relaxed max-w-2xl">
      Every Hash audit certificate carries an ed25519 signature over its body.
      Paste the public key, the certificate body bytes, and the signature; the server
      computes <code class="font-mono text-xs">ed25519.verify(pub, sha256("hash:audit-cert:v1:" || body), sig)</code>
      and tells you whether they match.
    </p>

    {#if serverPubKey}
      <div class="card p-4 mb-6">
        <div class="flex items-center gap-2 text-text-muted text-xs mb-2">
          <Key class="size-3.5" />
          <span class="font-mono uppercase tracking-widest">This server's public key</span>
        </div>
        <code class="block break-all text-xs font-mono">{serverPubKey}</code>
      </div>
    {/if}

    <section class="mb-8">
      <h2 class="text-base font-medium mb-2">Drop a Hash evidence bundle PDF</h2>
      <p class="text-text-muted text-xs mb-3 max-w-2xl">
        The bundle is the file you download from <code class="font-mono text-[11px]">Export evidence package</code>
        on any completed document. Every hash inside is checked against the manifest and the ed25519
        signature is verified offline against the embedded public key.
      </p>
      <label
        class="block cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-colors"
        class:border-border-light={!dragging}
        class:border-accent={dragging}
        class:bg-bg-elevated={dragging}
        ondragover={(e) => { e.preventDefault(); dragging = true; }}
        ondragleave={() => { dragging = false; }}
        ondrop={onDrop}
      >
        <input type="file" accept="application/pdf,.pdf" class="hidden" onchange={onPick} />
        <Upload class="size-6 mx-auto mb-2 text-text-muted" />
        <p class="text-sm font-medium">Drop your evidence bundle PDF here</p>
        <p class="text-text-muted text-xs mt-1">or click to choose a file</p>
      </label>

      {#if bundleLoading}
        <p class="text-text-muted text-xs mt-3">Verifying…</p>
      {/if}
      {#if bundleError}
        <div class="card p-4 mt-4 border border-danger/30">
          <p class="text-danger text-sm">{bundleError}</p>
        </div>
      {/if}
      {#if bundleReport}
        <div class="card p-6 mt-4 space-y-4">
          <div class="flex items-start gap-3">
            {#if bundleReport.ok}
              <ShieldCheck class="size-7 text-success shrink-0" />
              <div>
                <h3 class="text-lg font-medium text-success">Bundle verified</h3>
                <p class="text-text-muted text-xs">Every artifact hash matches the manifest and the ed25519 signature is valid.</p>
              </div>
            {:else}
              <ShieldAlert class="size-7 text-danger shrink-0" />
              <div>
                <h3 class="text-lg font-medium text-danger">Verification failed</h3>
                <p class="text-text-muted text-xs">At least one artifact diverged from the manifest or the signature is invalid. See details below.</p>
              </div>
            {/if}
          </div>

          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
            {#if bundleReport.document_name}
              <div><dt class="text-text-muted">Document</dt><dd>{bundleReport.document_name}</dd></div>
            {/if}
            {#if bundleReport.document_id}
              <div><dt class="text-text-muted">Document ID</dt><dd class="font-mono break-all">{bundleReport.document_id}</dd></div>
            {/if}
            {#if bundleReport.issuer}
              <div><dt class="text-text-muted">Issuer</dt><dd>{bundleReport.issuer}</dd></div>
            {/if}
            {#if bundleReport.generated_at}
              <div><dt class="text-text-muted">Generated</dt><dd>{bundleReport.generated_at}</dd></div>
            {/if}
          </dl>

          <div>
            <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">Cryptographic signature</h4>
            <div class="flex items-center gap-2 text-sm">
              {#if bundleReport.signature_valid}
                <CheckCircle2 class="size-4 text-success" />
                <span><strong>Valid ed25519 signature</strong> over <code class="font-mono text-[10px]">hash:audit-cert:v1</code> domain</span>
              {:else}
                <XCircle class="size-4 text-danger" />
                <span>{bundleReport.signature_note ?? 'signature could not be verified'}</span>
              {/if}
            </div>
            {#if bundleReport.public_key_b64}
              <p class="text-text-muted text-xs mt-2 break-all font-mono">{bundleReport.public_key_b64}</p>
            {/if}
          </div>

          <div>
            <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">Artifact hashes</h4>
            <ul class="space-y-1 text-xs">
              {#each bundleReport.checks as c (c.name)}
                <li class="flex items-center gap-2">
                  {#if c.ok}
                    <CheckCircle2 class="size-3.5 text-success shrink-0" />
                  {:else}
                    <XCircle class="size-3.5 text-danger shrink-0" />
                  {/if}
                  <code class="font-mono">{c.name}</code>
                  <span class="text-text-muted">·</span>
                  <span class="text-text-muted">expected</span>
                  <code class="font-mono text-[10px]">{abbrev(c.expected)}</code>
                  {#if c.detail}
                    <span class="text-danger">({c.detail})</span>
                  {:else if !c.ok}
                    <span class="text-text-muted">·</span>
                    <span class="text-text-muted">actual</span>
                    <code class="font-mono text-[10px] text-danger">{abbrev(c.actual)}</code>
                  {/if}
                </li>
              {/each}
            </ul>
          </div>

          {#if bundleReport.errors && bundleReport.errors.length}
            <div>
              <h4 class="text-xs font-mono uppercase tracking-widest text-text-muted mb-2">Errors</h4>
              <ul class="text-xs text-danger space-y-1">
                {#each bundleReport.errors as e}<li>{e}</li>{/each}
              </ul>
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <h2 class="text-base font-medium mb-2 flex items-center gap-2">
      <FileCheck2 class="size-4 text-text-muted" />
      Or verify a single (payload, signature) pair
    </h2>
    <p class="text-text-muted text-xs mb-3 max-w-2xl">
      Use this if you've extracted the signed cert payload + signature manually (for example from a bundle you opened in your PDF reader).
    </p>

    <form onsubmit={check} class="card p-6 space-y-4">
      <div>
        <label class="block text-sm font-medium mb-1" for="pub">Public key (base64)</label>
        <input id="pub" bind:value={pubKey} required class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs" />
      </div>
      <div>
        <label class="block text-sm font-medium mb-1" for="payload">Certificate body (the bytes that were signed)</label>
        <textarea id="payload" bind:value={payload} rows="6" required class="w-full p-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs"></textarea>
      </div>
      <div>
        <label class="block text-sm font-medium mb-1" for="sig">Signature (base64)</label>
        <input id="sig" bind:value={sig} required class="w-full px-3 py-2 rounded-md border border-border-light bg-bg-elevated font-mono text-xs" />
      </div>
      <button type="submit" class="btn btn-primary">Verify</button>

      {#if result === 'valid'}
        <div class="flex items-center gap-2 text-success p-3 rounded-md bg-bg-elevated">
          <ShieldCheck class="size-5" />
          <span><strong>Valid.</strong> This signature was produced by the holder of the matching private key.</span>
        </div>
      {:else if result === 'invalid'}
        <div class="flex items-center gap-2 text-danger p-3 rounded-md bg-bg-elevated">
          <ShieldAlert class="size-5" />
          <span><strong>Invalid.</strong> The signature does not match the body bytes for this public key.</span>
        </div>
      {:else if result === 'error'}
        <div class="text-danger text-sm">Error: {errorMsg}</div>
      {/if}
    </form>

    <p class="text-text-muted text-xs mt-6">
      Verifying offline? The same logic runs in any ed25519 library.
      Algorithm: ed25519. Pre-hash domain separator: <code class="font-mono">hash:audit-cert:v1:</code>
    </p>
  </main>
</div>
