<script lang="ts">
  import { onMount } from 'svelte';
  import { listMembers, updateMemberRole, getMe, type Member } from '$lib/api/client';
  import { Users, ShieldCheck } from 'lucide-svelte';

  let members = $state<Member[]>([]);
  let myRole = $state('');
  let loading = $state(true);
  let error = $state<string | null>(null);
  let savingId = $state<string | null>(null);

  const ROLES = [
    { value: 'owner', label: 'Owner', desc: 'Full access incl. org settings + members' },
    { value: 'sender', label: 'Sender', desc: 'Create, edit, and send documents' },
    { value: 'viewer', label: 'Viewer', desc: 'Read-only access' },
  ];
  const isOwner = $derived(myRole === 'owner');

  async function refresh() {
    loading = true;
    try {
      const [ms, me] = await Promise.all([listMembers(), getMe().catch(() => null)]);
      members = ms;
      if (me?.role) myRole = me.role;
      error = null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(refresh);

  async function changeRole(m: Member, role: string) {
    if (role === m.role) return;
    savingId = m.id;
    error = null;
    try {
      const updated = await updateMemberRole(m.id, role);
      members = members.map((x) => (x.id === m.id ? updated : x));
    } catch (e) {
      error = (e as Error).message;
      await refresh(); // re-sync the select back to the server's value
    } finally {
      savingId = null;
    }
  }

  function roleLabel(role: string): string {
    return ROLES.find((r) => r.value === role)?.label ?? role;
  }
</script>

<div class="px-6 py-10 max-w-4xl mx-auto">
  <div class="mb-8 space-y-2">
    <p class="page-eyebrow">Settings · Team</p>
    <h1 class="page-title">Members &amp; roles</h1>
  </div>

  <p class="text-sm text-text-secondary mb-6 max-w-2xl leading-relaxed">
    Roles control what each person can do. <strong>Owners</strong> manage org
    settings, billing, integrations, and members. <strong>Senders</strong> create
    and send documents. <strong>Viewers</strong> have read-only access. Only an
    owner can change roles.
  </p>

  {#if error}
    <div class="card p-4 mb-4 text-danger text-sm">{error}</div>
  {/if}

  <section class="card p-5">
    <h2 class="font-display font-extralight text-lg mb-4 flex items-center gap-2">
      <Users class="size-4" /> Org members
    </h2>
    {#if loading}
      <p class="text-text-muted text-sm">Loading...</p>
    {:else if members.length === 0}
      <p class="text-text-muted text-sm">No members yet.</p>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs uppercase tracking-widest text-text-muted">
            <th class="py-2">Member</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border-light">
          {#each members as m (m.id)}
            <tr>
              <td class="py-3">
                <div class="font-medium">
                  {m.name || m.email}
                  {#if m.is_self}<span class="text-xs text-text-muted">(you)</span>{/if}
                </div>
                <div class="text-xs text-text-muted">{m.email}</div>
              </td>
              <td>
                {#if isOwner}
                  <select
                    class="px-3 py-1.5 rounded-md border border-border-light bg-bg-elevated text-sm"
                    value={m.role}
                    disabled={savingId === m.id}
                    onchange={(e) => changeRole(m, (e.currentTarget as HTMLSelectElement).value)}
                  >
                    {#each ROLES as r}
                      <option value={r.value}>{r.label}</option>
                    {/each}
                  </select>
                {:else}
                  <span class="inline-flex items-center gap-1 text-sm capitalize">
                    {#if m.role === 'owner'}<ShieldCheck class="size-3 text-accent" />{/if}
                    {roleLabel(m.role)}
                  </span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if !isOwner}
        <p class="text-xs text-text-muted mt-4">Only owners can change roles.</p>
      {/if}
    {/if}
  </section>
</div>
