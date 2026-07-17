import { rm } from "node:fs/promises";
import { resolve } from "node:path";

export default async function globalSetup() {
  await rm(resolve(".ndr-playwright-data"), { recursive: true, force: true });
}
