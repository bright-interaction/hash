import { test, expect } from '@playwright/test';

// Regression guard for the audit fix #1: every Hash response must
// stay fully first-party. No googleapis.com / gstatic.com / unsafe
// font sources allowed in the CSP, and /fonts/ must serve real
// woff2 binaries from the embedded SvelteKit static tree.

test('CSP is fully first-party (no third-party font CDN)', async ({ request }) => {
  const res = await request.get('/');
  const csp = res.headers()['content-security-policy'] || '';
  expect(csp).toContain("font-src 'self'");
  expect(csp).toContain("style-src 'self'");
  expect(csp).not.toContain('googleapis');
  expect(csp).not.toContain('gstatic');
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("base-uri 'self'");
  expect(csp).toContain("form-action 'self'");
});

test('fonts.css is served first-party', async ({ request }) => {
  const res = await request.get('/fonts/fonts.css');
  expect(res.status()).toBe(200);
  const body = await res.text();
  expect(body).toContain('@font-face');
  // Negative assertion: a self-hosted fonts.css must NEVER reference
  // a third-party CDN.
  expect(body).not.toContain('gstatic.com');
  expect(body).not.toContain('googleapis.com');
});

test('woff2 binaries are cacheable + CORS-friendly', async ({ request }) => {
  // Pick a face that ships in the embed regardless of subset choice.
  const probe = await request.get('/fonts/fonts.css');
  const m = (await probe.text()).match(/url\((\/fonts\/[^)]+\.woff2)\)/);
  expect(m, 'fonts.css must reference at least one woff2').not.toBeNull();
  const fontURL = m![1];
  const res = await request.get(fontURL);
  expect(res.status()).toBe(200);
  expect(res.headers()['cache-control']).toContain('immutable');
  expect(res.headers()['access-control-allow-origin']).toBe('*');
});

test('Permissions-Policy is locked down', async ({ request }) => {
  const res = await request.get('/');
  const pp = res.headers()['permissions-policy'] || '';
  for (const feature of ['geolocation=()', 'microphone=()', 'camera=()', 'payment=()']) {
    expect(pp).toContain(feature);
  }
});
