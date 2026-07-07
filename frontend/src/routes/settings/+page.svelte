<script lang="ts">
  import {
    KeyRound,
    Webhook,
    Receipt,
    Palette,
    ShieldCheck,
    Scale,
    UserSearch,
    Bot,
    Users,
  } from 'lucide-svelte';

  const groups = [
    {
      title: 'Developer',
      items: [
        { href: '/settings/api-keys', label: 'API keys', desc: 'Mint MCP + REST agent keys.', icon: KeyRound },
        { href: '/settings/webhooks', label: 'Webhooks', desc: 'Outbound HMAC-signed delivery.', icon: Webhook },
      ],
    },
    {
      title: 'Team',
      items: [
        { href: '/settings/members', label: 'Members & roles', desc: 'Owner / sender / viewer access.', icon: Users },
      ],
    },
    {
      title: 'AI',
      items: [
        { href: '/settings/ai', label: 'AI provider', desc: 'Bring your own model + key.', icon: Bot },
      ],
    },
    {
      title: 'Brand',
      items: [{ href: '/settings/branding', label: 'Branding', desc: 'Colors, logo, fonts.', icon: Palette }],
    },
    {
      title: 'Compliance',
      items: [
        { href: '/settings/compliance', label: 'Compliance kit', desc: 'DPA, RoPA, EDPB flags.', icon: ShieldCheck },
        { href: '/settings/eidas-rules', label: 'eIDAS routing', desc: 'SES / AES / QES tier rules.', icon: Scale },
        { href: '/settings/dsr', label: 'Data subject rights', desc: 'Articles 15 - 22 inbox.', icon: UserSearch },
        { href: '/settings/audit-chain', label: 'Audit chain verify', desc: 'Walk the hash chain end-to-end.', icon: ShieldCheck },
      ],
    },
    {
      title: 'Billing',
      items: [{ href: '/settings/billing', label: 'Plans + invoices', desc: 'Subscriptions and quotas.', icon: Receipt }],
    },
  ];
</script>

<div class="px-6 py-10 max-w-5xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings</p>
    <h1 class="page-title">Workspace</h1>
  </div>

  <div class="space-y-8">
    {#each groups as g (g.title)}
      <section>
        <h2 class="text-xs uppercase tracking-widest text-text-muted font-mono mb-3">{g.title}</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {#each g.items as item (item.href)}
            <a class="card p-4 hover:border-border-strong transition-colors" href={item.href}>
              <div class="flex items-center gap-2 mb-1">
                <item.icon class="size-4" />
                <span class="font-medium">{item.label}</span>
              </div>
              <p class="text-sm text-text-secondary">{item.desc}</p>
            </a>
          {/each}
        </div>
      </section>
    {/each}
  </div>
</div>
