<script lang="ts">
  let { children } = $props();
</script>

<div class="min-h-screen bg-bg">
  <header class="border-b border-border-light px-6 py-4 flex items-center justify-between">
    <a href="/" class="font-display font-extralight text-lg">Hash</a>
    <nav class="text-sm flex gap-4 text-text-secondary">
      <a href="/legal/terms" class="hover:text-text-primary">Terms</a>
      <a href="/legal/privacy" class="hover:text-text-primary">Privacy</a>
      <a href="/legal/dpa" class="hover:text-text-primary">DPA</a>
      <a href="/legal/eidas" class="hover:text-text-primary">eIDAS</a>
      <a href="/verify" class="hover:text-text-primary">Verify</a>
    </nav>
  </header>
  <main class="max-w-3xl mx-auto px-6 py-12 prose-legal">
    {@render children()}
  </main>
</div>

<style>
  :global(.prose-legal) {
    line-height: 1.65;
  }
  :global(.prose-legal h1) {
    font-family: var(--font-display);
    font-weight: 200;
    font-size: 2.25rem;
    margin: 0 0 0.5rem;
  }
  :global(.prose-legal h2) {
    font-family: var(--font-display);
    font-weight: 300;
    font-size: 1.4rem;
    margin: 2rem 0 0.75rem;
  }
  :global(.prose-legal h3) {
    font-weight: 600;
    font-size: 1.05rem;
    margin: 1.5rem 0 0.5rem;
  }
  :global(.prose-legal p) {
    margin: 0.75rem 0;
    color: var(--t-text-primary);
  }
  :global(.prose-legal ul) {
    list-style: disc;
    padding-left: 1.5rem;
    margin: 0.75rem 0;
  }
  :global(.prose-legal ol) {
    list-style: decimal;
    padding-left: 1.5rem;
    margin: 0.75rem 0;
  }
  :global(.prose-legal li) {
    margin: 0.3rem 0;
  }
  :global(.prose-legal code) {
    font-family: var(--font-mono);
    font-size: 0.85em;
    background: var(--t-bg-elevated);
    padding: 0.1rem 0.3rem;
    border-radius: 0.25rem;
  }
  :global(.prose-legal .draft-banner) {
    border-left: 3px solid var(--t-warning);
    background: var(--t-bg-elevated);
    padding: 0.75rem 1rem;
    margin: 1rem 0 2rem;
    font-size: 0.85rem;
    color: var(--t-text-secondary);
  }
</style>
