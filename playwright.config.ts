import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/ui',
  timeout: 30_000,
  use: { headless: true, trace: 'retain-on-failure' },
  webServer: [
    {
      command: 'npm run dev:desktop',
      url: 'http://127.0.0.1:1420',
      reuseExistingServer: !process.env.CI,
    },
    {
      command: 'npm run dev:website',
      url: 'http://127.0.0.1:4321',
      reuseExistingServer: !process.env.CI,
    },
  ],
});
