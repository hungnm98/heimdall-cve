import { defineConfig, devices } from "@playwright/test";

const PORT = 5173;

/** E2E against the dev server with the MSW mock API (VITE_MOCK=1, see .env.development). */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}/`,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, grepInvert: /@mobile/ },
    { name: "mobile", use: { ...devices["Desktop Chrome"], viewport: { width: 375, height: 812 } }, grep: /@mobile/ },
  ],
  webServer: {
    command: "npm run dev",
    url: `http://127.0.0.1:${PORT}/`,
    env: { VITE_MOCK: "1" },
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
