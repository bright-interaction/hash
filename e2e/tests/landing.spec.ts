import { test, expect } from '@playwright/test';

// Landing-page smoke tests. The frontend is served by the dev server in
// local development; in CI we point baseURL at the built static site.

test.describe('marketing landing page', () => {
  test.skip(({ baseURL }) => !baseURL?.includes('5173') && !process.env.HASH_LANDING, 'landing tests need the SvelteKit dev server (or HASH_LANDING=1)');

  test('renders hero copy', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', {
      level: 1,
      name: 'Agent-native e-signing. Self-hosted. Deployment-controlled.',
    })).toBeVisible();
    await expect(page.getByText('Hash · Every signature, hash-chained')).toBeVisible();
  });

  test('shows Sign in CTA when unauthenticated', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('main').getByRole('link', { name: 'Sign in', exact: true })).toBeVisible();
  });
});
