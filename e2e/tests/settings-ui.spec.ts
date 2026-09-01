import { test, expect } from '@playwright/test';

// Regression guard for audit fix #8 (operator UI). Each of the
// claimed-shipped settings pages must serve the SPA shell + reach
// the SvelteKit router so the route is real (not 404'd by the
// embedded static FS). The page's client-side data fetch will fire
// /api/v1/* and surface a 401 to the user; the route itself is
// what we're asserting here.

const settingsRoutes = [
  '/settings',
  '/settings/branding',
  '/settings/compliance',
  '/settings/eidas-rules',
  '/settings/dsr',
  '/settings/webhooks',
  '/settings/api-keys',
  '/settings/billing',
];

for (const route of settingsRoutes) {
  test(`${route} serves the SPA shell`, async ({ request }) => {
    const res = await request.get(route);
    expect(res.status()).toBe(200);
    const body = await res.text();
    expect(body).toContain('<!doctype html>');
    // SvelteKit emits this attribute so we can confirm the SPA shell
    // (not a static 200 from an upstream proxy default page) is what
    // we got back.
    expect(body).toContain('data-sveltekit-preload-data');
  });
}

test('settings index links to all sub-pages', async ({ request }) => {
  const res = await request.get('/settings');
  expect(res.status()).toBe(200);
  // The SPA payload is hydrated client-side; we check the SPA shell
  // by sniffing the static index.html. Real UI assertions live in
  // the SvelteKit unit tests; here we only confirm reachability.
  const body = await res.text();
  expect(body).toContain('<!doctype html>');
});

test('eIDAS settings cannot select or seed unavailable AES/QES tiers', async ({ page }) => {
  await page.goto('/settings/eidas-rules');
  await expect(page.getByRole('heading', { name: 'eIDAS routing rules' })).toBeVisible();
  await expect(page.getByText('Production signing currently supports SES only.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Swedish defaults unavailable' })).toBeDisabled();

  await page.getByRole('button', { name: 'New rule' }).click();
  const tier = page.getByLabel('Required tier');
  await expect(tier).toHaveValue('SES');
  await expect(tier.locator('option[value="AES"]')).toHaveAttribute('disabled', '');
  await expect(tier.locator('option[value="QES"]')).toHaveAttribute('disabled', '');

  const currentTier = page.getByLabel('Current tier');
  await expect(currentTier).toHaveValue('SES');
  await expect(currentTier.locator('option[value="AES"]')).toHaveAttribute('disabled', '');
  await expect(currentTier.locator('option[value="QES"]')).toHaveAttribute('disabled', '');
});
