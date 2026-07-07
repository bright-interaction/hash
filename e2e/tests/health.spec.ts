import { test, expect } from '@playwright/test';

test('health endpoint reports ok', async ({ request }) => {
  const res = await request.get('/health');
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.ok).toBe(true);
});

test('security headers present on every response', async ({ request }) => {
  const res = await request.get('/health');
  expect(res.headers()['x-content-type-options']).toBe('nosniff');
  expect(res.headers()['x-frame-options']).toBe('DENY');
  expect(res.headers()['referrer-policy']).toBe('strict-origin-when-cross-origin');
  expect(res.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
});

test('unauthenticated /api/v1/me returns 401', async ({ request }) => {
  const res = await request.get('/api/v1/me');
  expect(res.status()).toBe(401);
});

test('unauthenticated /api/v1/templates returns 401', async ({ request }) => {
  const res = await request.get('/api/v1/templates');
  expect(res.status()).toBe(401);
});

test('unauthenticated POST /api/v1/templates returns 401', async ({ request }) => {
  const res = await request.post('/api/v1/templates', {
    data: { name: 'Test', source_kind: 'blocks', blocks_json: { version: 1, blocks: [] } }
  });
  expect(res.status()).toBe(401);
});
