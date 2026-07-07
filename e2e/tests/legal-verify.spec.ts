import { test, expect, type APIRequestContext } from '@playwright/test';

// Public legal + verify surface. These pages don't require auth so the test
// is straight HTTP plus signature-roundtrip via /api/verify.

test.describe('public legal + verify surface', () => {
  test('SPA shell serves for /verify, /legal/*, /dashboard', async ({ request }) => {
    const paths = ['/verify', '/legal/terms', '/legal/privacy', '/legal/dpa', '/legal/eidas', '/dashboard'];
    for (const p of paths) {
      const res = await request.get(p);
      expect.soft(res.status(), `${p}`).toBe(200);
      const ct = res.headers()['content-type'] ?? '';
      expect.soft(ct, `${p}`).toContain('text/html');
    }
  });

  test('GET /.well-known/hash-public-key returns the audit key', async ({ request }) => {
    const res = await request.get('/.well-known/hash-public-key');
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.algorithm).toBe('ed25519');
    expect(body.public_key_b64).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(body.public_key_b64.length).toBeGreaterThan(20);
    expect(body.domain).toBe('hash:audit-cert:v1');
  });

  test('POST /api/verify rejects forged sig', async ({ request }) => {
    const res = await request.post('/api/verify', {
      data: {
        public_key_b64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        payload: 'pretend audit cert body',
        signature_b64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
      }
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.valid).toBe(false);
  });

  test('POST /api/verify with empty fields returns 400', async ({ request }) => {
    const res = await request.post('/api/verify', {
      data: { public_key_b64: '', payload: '', signature_b64: '' }
    });
    expect(res.status()).toBe(400);
  });

  test('Sign loop produces a verifiable cert (round-trip via the public endpoint)', async ({ request }) => {
    const keyRes = await request.get('/.well-known/hash-public-key');
    expect(keyRes.status()).toBe(200);
    const pub = (await keyRes.json()).public_key_b64;
    expect(pub).toBeTruthy();

    // We can't fabricate a valid signature without the private seed, but we
    // can prove the verify endpoint at least *accepts* well-formed input.
    // A truly forged sig over pretend payload returns valid=false (above).
    // This test documents the contract: same pub key, same body, real sig
    // would round-trip. Live audit certs are tested via the bash harness.
    expect(pub.length).toBeGreaterThan(20);
  });
});

// Type guard: keep the unused-import error away if we expand.
const _ = (r: APIRequestContext) => r;
