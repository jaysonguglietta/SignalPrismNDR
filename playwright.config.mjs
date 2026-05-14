export default {
  testDir: "./tests/visual",
  timeout: 30_000,
  expect: {
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.03
    }
  },
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1440, height: 1000 },
    colorScheme: "light"
  },
  webServer: {
    command: "npm start",
    url: "http://127.0.0.1:4173/api/health",
    reuseExistingServer: true,
    timeout: 10_000
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
