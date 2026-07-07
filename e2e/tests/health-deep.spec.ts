import { test, expect } from '@playwright/test';

// Regression guard for audit fix #9 (deep /health). The probe used
// to ping Postgres only; now it MUST return a checks[] array with
// every wired dependency reported individually. A missing dep would
// regress the on-call contract that Compose health-checks rely on.

test('/health returns per-dep checks array', async ({ request }) => {
  const res = await request.get('/health');
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.ok).toBe(true);
  expect(Array.isArray(body.checks), '/health must surface per-dep checks').toBe(true);
  const names = (body.checks as Array<{ name: string; ok: boolean }>).map((c) => c.name);
  expect(names).toContain('postgres');
  for (const c of body.checks) {
    expect(c.ok, `${c.name} reported failure on a healthy probe`).toBe(true);
  }
});
