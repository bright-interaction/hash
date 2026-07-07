import { test, expect } from '@playwright/test';

// Regression guard for audit fix #6 (DSR endpoints) + fix #7 (signer
// page Article 13 surface). Session-required routes return 401; the
// signer-token endpoint exists + rejects malformed input cleanly.

test('sender DSR list requires session', async ({ request }) => {
  const res = await request.get('/api/v1/dsr');
  expect(res.status()).toBe(401);
});

test('sender DSR create requires session', async ({ request }) => {
  const res = await request.post('/api/v1/dsr', {
    data: { kind: 'access', subject_email: 'subject@example.com' },
  });
  expect(res.status()).toBe(401);
});

test('sender DSR transition requires session', async ({ request }) => {
  const res = await request.patch('/api/v1/dsr/00000000-0000-0000-0000-000000000000', {
    data: { status: 'fulfilled' },
  });
  expect(res.status()).toBe(401);
});

test('Article 15 export requires session', async ({ request }) => {
  const res = await request.get('/api/v1/data-subject/export?email=subject@example.com');
  expect(res.status()).toBe(401);
});

test('signer DSR rejects unknown token with 404', async ({ request }) => {
  const res = await request.post('/sign/totally-bogus-token-xyz/dsr', {
    data: { kind: 'access' },
  });
  // 404 (invalid token) or 400 (malformed) - both prove the route is
  // mounted; 401 here would indicate session-auth bleed which would
  // be a serious bug since the signer page must work without one.
  expect([400, 404]).toContain(res.status());
});
