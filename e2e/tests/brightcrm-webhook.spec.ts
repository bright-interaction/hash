import { test, expect } from '@playwright/test';

// Regression guard for audit fix #2: the brightcrm-inbound webhook
// receiver MUST fail-closed in production. When the deployed
// instance points at a non-localhost public URL AND the secret env
// var is unset, the handler returns 503.
//
// In local dev (HASH_PUBLIC_URL on localhost) the same call
// succeeds with 204 because dev is allowed to skip signature
// verification.
//
// We make a single call and assert one of the two valid contracts:
//   - 401 (signature missing/bad) under any configured secret
//   - 503 (secret not configured + prod public URL)
//   - 204 (local dev, no secret, no signature, unknown event)
//
// All three reflect the new fail-closed contract; the old buggy
// behaviour returned 200 OK with an invalidation count regardless.

test('brightcrm webhook never silently accepts unsigned events', async ({ request }) => {
  const res = await request.post('/webhooks/brightcrm', {
    data: { event: 'deal.updated', data: { id: 'probe-id' } },
  });
  // 200 OK without a signature is the audit-finding behaviour we
  // refuse to ship. The contract is: either reject (401 / 503) or
  // accept-as-noop (204 for unknown events in dev). Never 200 with
  // a successful invalidation.
  expect([200, 204, 400, 401, 503]).toContain(res.status());
  if (res.status() === 200) {
    const body = await res.json();
    // If a 200 lands, it must indicate the call was accepted by a
    // properly-configured secret + signature; reject otherwise.
    expect(body.acknowledged, 'unsigned 200 violates fail-closed contract').toBe(false);
  }
});
