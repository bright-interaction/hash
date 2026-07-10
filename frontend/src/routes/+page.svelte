<script lang="ts">
  import { onMount } from 'svelte';
  import { FileSignature, Sparkles, ShieldCheck } from 'lucide-svelte';

  let user = $state<{ email: string; org_id: string } | null>(null);
  let loading = $state(true);

  onMount(async () => {
    try {
      const res = await fetch('/api/v1/me', { credentials: 'include' });
      if (res.ok) {
        user = await res.json();
      }
    } catch {
      // not signed in is fine on the marketing route
    } finally {
      loading = false;
    }
  });
</script>

<div class="min-h-screen flex flex-col">
  <header class="border-b border-border-light px-6 py-4 flex items-center justify-between">
    <div class="flex items-center gap-2">
      <FileSignature class="size-5 text-accent" />
      <span class="font-display text-xl font-extralight tracking-tight">Hash</span>
    </div>
    <nav class="flex items-center gap-3">
      {#if loading}
        <span class="text-sm text-text-muted">…</span>
      {:else if user}
        <a class="btn btn-secondary" href="/dashboard">Dashboard</a>
        <form method="POST" action="/auth/logout" class="inline">
          <button class="btn btn-secondary" type="submit">Sign out</button>
        </form>
      {:else}
        <a class="btn btn-primary" href="/auth/login">Sign in</a>
      {/if}
    </nav>
  </header>

  <main class="flex-1 flex flex-col items-center justify-center px-6 text-center max-w-3xl mx-auto py-20">
    <p class="page-eyebrow mb-4">Hash · Every signature, hash-chained</p>
    <h1 class="page-title mb-6">Agent-native e-signing.<br />Self-hosted. EU-sovereign.</h1>
    <p class="text-text-secondary text-lg max-w-xl mb-10 leading-relaxed">
      Document creation + e-signing with PandaDoc-style typed signatures, an open MCP for
      BYOAI authoring, and zero per-user fees.
    </p>
    <div class="flex gap-3">
      {#if user}
        <a class="btn btn-primary" href="/dashboard">Go to dashboard</a>
      {:else}
        <a class="btn btn-primary" href="/auth/login">Sign in</a>
      {/if}
      <a class="btn btn-secondary" href="https://github.com/brightinteraction/hash" rel="noreferrer" target="_blank">
        Source
      </a>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-16 text-left w-full">
      <div class="card p-6">
        <Sparkles class="size-5 text-accent mb-3" />
        <h3 class="font-display font-extralight text-lg mb-2">BYOAI authoring</h3>
        <p class="text-text-secondary text-sm leading-relaxed">
          Plug your own LLM via MCP and let it draft, edit, and place signature fields.
        </p>
      </div>
      <div class="card p-6">
        <FileSignature class="size-5 text-accent mb-3" />
        <h3 class="font-display font-extralight text-lg mb-2">Adopt-style signatures</h3>
        <p class="text-text-secondary text-sm leading-relaxed">
          Five curated calligraphy fonts. One tap to adopt. No drawing required.
        </p>
      </div>
      <div class="card p-6">
        <ShieldCheck class="size-5 text-accent mb-3" />
        <h3 class="font-display font-extralight text-lg mb-2">Audit-grade evidence</h3>
        <p class="text-text-secondary text-sm leading-relaxed">
          Every signing event hashed, timestamped, and bound into a server-signed certificate.
        </p>
      </div>
    </div>
  </main>

  <footer class="border-t border-border-light px-6 py-4 text-xs text-text-muted text-center">
    Built by Bright Interaction. eIDAS SES + AES compliant. QES via QTSP-of-choice.
  </footer>
</div>
