import { expect, test } from "@playwright/test";

test("dashboard demo visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Demo" }).click();
  await expect(page.getByRole("heading", { name: "SignalPrism NDR" })).toBeVisible();
  await expect(page.getByText("NDR risk")).toBeVisible();
  await expect(page).toHaveScreenshot("dashboard-demo.png", { fullPage: true });
});

test("topology replay visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Sample" }).click();
  await page.getByRole("tab", { name: "Topology" }).click();
  await page.locator("#replayRangeInput").evaluate((input) => {
    input.value = "55";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await expect(page.getByText("Entity-to-entity paths")).toBeVisible();
  await expect(page).toHaveScreenshot("topology-replay.png", { fullPage: true });
});

test("admin tenant management visual state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Demo" }).click();
  await page.getByRole("tab", { name: "Admin" }).click();
  await page.locator("#adminUserNameInput").fill("Avery SOC");
  await page.locator("#adminUserEmailInput").fill("avery@example.com");
  await page.locator("#adminUserRoleInput").selectOption("analyst");
  await expect(page.getByText("Users and roles")).toBeVisible();
  await expect(page).toHaveScreenshot("admin-tenant.png", { fullPage: true });
});
