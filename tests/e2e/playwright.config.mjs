import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  // CI tests the actual Compose Nginx service; local source runs retain the proxy.
  webServer: process.env.VAPTX_E2E_EXTERNAL_SERVER === '1' ? undefined : {
    command: 'node server.mjs',
    url: 'http://localhost:3000',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
