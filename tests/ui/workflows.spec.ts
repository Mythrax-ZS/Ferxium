import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
const release = JSON.parse(readFileSync('apps/website/src/data/releases.json', 'utf8')) as {
  assets: Array<{ platform: string; url: string; sha256: string }>;
};

test('desktop demo scan pauses, resumes and cancels without host file access', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('http://127.0.0.1:1420');
  await expect(page.getByText('INTERACTIVE DEMO')).toBeVisible();
  await page.screenshot({ path: 'artifacts/desktop.png', fullPage: true });
  await page.getByRole('button', { name: 'Run quick scan' }).click();
  await expect(
    page.getByText('Browser preview does not access or protect files.', { exact: false }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Pause', exact: true }).click();
  await expect(page.getByText('paused', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Resume', exact: true }).click();
  await expect(page.getByText('running', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel scan' }).click();
  await page.getByRole('button', { name: 'Scans', exact: true }).click();
  await expect(page.getByText('cancelled', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('switch', { name: 'File monitoring', exact: true }).click();
  await page.getByRole('button', { name: 'Save preferences' }).click();
  await page.getByRole('button', { name: 'Dashboard', exact: true }).click();
  await expect(page.getByText('FILE MONITORING INACTIVE')).toBeVisible();
  expect(errors).toEqual([]);
});

test('website exposes honest downloads and working FAQ/navigation on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('http://127.0.0.1:4321');
  await page.getByRole('button', { name: 'Toggle navigation' }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
  await page
    .getByRole('navigation', { name: 'Main navigation' })
    .getByRole('link', { name: 'Download', exact: true })
    .click();
  const pending = ['windows', 'macos', 'linux'].filter(
    (platform) => !release.assets.some((asset) => asset.platform === platform),
  );
  await expect(page.getByText('Native build not published yet')).toHaveCount(pending.length);
  for (const asset of release.assets) {
    await expect(page.locator(`.download-card a[href="${asset.url}"]`)).toHaveCount(1);
    await expect(page.getByText(asset.sha256, { exact: true })).toBeVisible();
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  const windows = release.assets.find((asset) => asset.platform === 'windows');
  if (windows) {
    await expect(page.getByRole('link', { name: 'Download Windows (x64)' })).toHaveAttribute(
      'href',
      windows.url,
    );
    await expect(page.getByText(windows.sha256, { exact: true })).toBeVisible();
  } else {
    await expect(page.getByRole('link', { name: 'Build for Windows' })).toBeVisible();
    await page.getByRole('link', { name: 'Build for Windows' }).click();
    await expect(page.getByRole('heading', { name: 'Windows', exact: true })).toBeVisible();
  }
  await page.goto('http://127.0.0.1:4321');
  await page.getByText('Is FerXium really free forever?').click();
  await expect(
    page.getByText('Yes. The source code is MIT licensed.', { exact: false }),
  ).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
});

test('every static page loads with a unique title and no browser exceptions', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const titles = new Set<string>();
  for (const route of ['/', '/features/', '/download/', '/docs/', '/about/', '/blog/']) {
    const response = await page.goto(`http://127.0.0.1:4321${route}`);
    expect(response?.status()).toBe(200);
    titles.add(await page.title());
    await expect(page.locator('#main h1')).toBeVisible();
    if (route === '/') await page.screenshot({ path: 'artifacts/website.png', fullPage: true });
  }
  expect(titles.size).toBe(6);
  expect(errors).toEqual([]);
});
