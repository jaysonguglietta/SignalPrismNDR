export default {
  testDir: "./tests/visual",
  globalSetup: "./tests/visual/global-setup.mjs",
  snapshotPathTemplate: "{testDir}/{testFilePath}-snapshots/{arg}-{projectName}{ext}",
  timeout: 30_000,
  expect: {
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.03
    }
  },
  use: {
    baseURL: "http://127.0.0.1:4174",
    viewport: { width: 1440, height: 1000 },
    colorScheme: "light"
  },
  webServer: {
    command: "npm start",
    url: "http://127.0.0.1:4174/api/health",
    reuseExistingServer: false,
    timeout: 10_000,
    env: {
      PORT: "4174",
      HOST: "127.0.0.1",
      NDR_DATA_DIR: ".ndr-playwright-data",
      NDR_RATE_LIMIT_MAX: "10000"
    }
  },
  projects: [
    {
      name: "chromium-desktop",
      use: { browserName: "chromium" }
    },
    {
      name: "webkit-mobile",
      use: { browserName: "webkit", viewport: { width: 390, height: 844 }, isMobile: true }
    }
  ]
};
