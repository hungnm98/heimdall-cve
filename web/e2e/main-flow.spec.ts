import { expect, test } from "@playwright/test";

test("add target → preview → save → scan now → live job log → findings → suppress", async ({ page }) => {
  await page.goto("./#/targets");
  await page.getByRole("link", { name: "Add target" }).first().click();
  await expect(page.getByRole("heading", { name: "Add target" })).toBeVisible();

  // Step 1: configure
  await page.getByLabel("Kind").selectOption("org");
  await page.getByLabel("Organization").fill("initech");
  await expect(page.getByLabel("Auth profile")).toHaveValue("github-token");
  await page.getByLabel("Run").selectOption({ label: "Every 3 days" });
  await page.getByRole("button", { name: "Preview repositories" }).click();

  // Step 2: preview lists repos (archived and forks are skipped by default)
  await expect(page.getByText(/repositories would be scanned/)).toBeVisible();
  const preview = page.getByRole("table", { name: "Repositories this target would scan" });
  await expect(preview.getByRole("cell", { name: "initech/api-gateway" })).toBeVisible();
  await expect(preview.getByRole("cell", { name: /initech\/docs/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Save target" }).click();

  // Back on the list, with the new target
  await expect(page.getByRole("heading", { name: "Targets" })).toBeVisible();
  const row = page.getByRole("row", { name: /org:initech/ });
  await expect(row).toContainText("Every 3 days");
  await row.getByRole("button", { name: "Scan org:initech now" }).click();

  // Toast → job log
  const toast = page.getByText(/Scan of org:initech queued as job #\d+/);
  await expect(toast).toBeVisible();
  await page.getByRole("button", { name: "View log" }).click();
  await expect(page.getByRole("heading", { name: /Job #\d+/ })).toBeVisible();
  const log = page.getByRole("log");
  await expect(log).toContainText("Scanning org:initech");
  await expect(log).toContainText("initech/api-gateway");
  await expect(log).toContainText(/Run #\d+ finished/, { timeout: 15_000 });
  await expect(page.getByText("succeeded").first()).toBeVisible();

  // Findings → finding → suppress
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Findings" }).click();
  await expect(page).toHaveURL(/#\/findings\?status=open/);
  await page.getByLabel("Search package or advisory id").fill("lodash");
  await page.getByLabel("Search package or advisory id").press("Enter");
  await expect(page).toHaveURL(/q=lodash/);
  await page.getByRole("link", { name: /^lodash/ }).first().click();
  await expect(page.getByRole("heading", { name: /lodash@4\.17\.15/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^GHSA-p6mc-m468-83gw/ })).toHaveAttribute(
    "href",
    "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw",
  );

  await page.getByRole("button", { name: "Suppress" }).click();
  const dialog = page.getByRole("dialog", { name: "Suppress finding" });
  await dialog.getByRole("button", { name: "Suppress" }).click();
  await expect(dialog.getByText(/at least 3 characters/)).toBeVisible();
  await dialog.getByLabel("Reason").fill("Transitive dev dependency only; tracked in SEC-101");
  await dialog.getByRole("button", { name: "Suppress" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText(/Finding suppressed until/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Unsuppress" })).toBeVisible();
  await expect(page.getByText("Transitive dev dependency only; tracked in SEC-101")).toBeVisible();
});

test("dialogs trap focus and close with Escape", async ({ page }) => {
  await page.goto("./#/auth-profiles");
  const add = page.getByRole("button", { name: "Add profile" });
  await add.click();
  const dialog = page.getByRole("dialog", { name: "Add auth profile" });
  await expect(dialog).toBeVisible();
  for (let i = 0; i < 12; i++) await page.keyboard.press("Tab");
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(add).toBeFocused();
});

test("config targets are read-only", async ({ page }) => {
  await page.goto("./#/targets/1");
  await expect(page.getByText(/defined in the Heimdall config file and is read-only/)).toBeVisible();
  await expect(page.getByLabel("Organization")).toBeDisabled();
});

test("mobile navigation and no horizontal scroll @mobile", async ({ page }) => {
  await page.goto("./#/findings?status=open");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  const width = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(width).toBeLessThanOrEqual(375);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("dialog").getByRole("link", { name: "Scans & Jobs" }).click();
  await expect(page.getByRole("heading", { name: "Scans & jobs" })).toBeVisible();
});
