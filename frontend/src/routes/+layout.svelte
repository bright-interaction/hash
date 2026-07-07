<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { FileSignature, LayoutDashboard, FileText, LayoutTemplate, Settings, ShieldCheck } from 'lucide-svelte';

  let { children } = $props();

  let me = $state<{ email: string; role: string } | null>(null);

  // App chrome (the global nav) renders on the authenticated app surfaces only.
  // The public signer ceremony (/sign), legal pages, the auth screens, and the
  // marketing/login root render standalone with no nav.
  const path = $derived($page.url.pathname);
  const showChrome = $derived(
    !(path === '/' || path.startsWith('/sign') || path.startsWith('/legal') || path.startsWith('/auth'))
  );

  const navItems = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/documents', label: 'Documents', icon: FileText },
    { href: '/templates', label: 'Templates', icon: LayoutTemplate },
    { href: '/verify', label: 'Verify', icon: ShieldCheck },
    { href: '/settings', label: 'Settings', icon: Settings }
  ];

  function isActive(href: string): boolean {
    return path === href || path.startsWith(href + '/');
  }

  onMount(async () => {
    // Only the app surfaces need the identity; skip the probe on public pages.
    if (!showChrome) return;
    try {
      const res = await fetch('/api/v1/me', { credentials: 'include' });
      if (res.ok) me = await res.json();
    } catch {
      // not signed in -> nav still renders; the pages themselves gate.
    }
  });
</script>

{#if showChrome}
  <div class="min-h-screen flex flex-col">
    <header class="border-b border-border-light bg-surface">
      <div class="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between gap-6">
        <a href="/dashboard" class="flex items-center gap-2 shrink-0">
          <FileSignature class="size-5 text-accent" />
          <span class="font-display text-lg font-extralight tracking-tight">Hash</span>
        </a>
        <nav class="flex items-center gap-1 flex-1">
          {#each navItems as item}
            <a
              href={item.href}
              class="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors {isActive(item.href)
                ? 'bg-accent/10 text-accent font-medium'
                : 'text-text-muted hover:text-text hover:bg-border-light/40'}"
            >
              <item.icon class="size-4" />
              <span class="hidden sm:inline">{item.label}</span>
            </a>
          {/each}
        </nav>
        <div class="flex items-center gap-3 shrink-0">
          {#if me}
            <div class="text-right hidden md:block leading-tight">
              <p class="text-xs text-text">{me.email}</p>
              <p class="text-[10px] font-mono uppercase tracking-widest text-text-muted">{me.role}</p>
            </div>
          {/if}
          <form method="POST" action="/auth/logout" class="inline">
            <button class="btn btn-secondary btn-sm" type="submit">Sign out</button>
          </form>
        </div>
      </div>
    </header>
    <main class="flex-1">
      {@render children()}
    </main>
  </div>
{:else}
  {@render children()}
{/if}
