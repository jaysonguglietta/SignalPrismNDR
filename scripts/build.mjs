import { mkdir, copyFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";

const dist = "dist";
await mkdir(dist, { recursive: true });
await mkdir(join(dist, "public", "src"), { recursive: true });
for (const file of ["server.mjs", "package.json"]) {
  await copyFile(file, join(dist, file));
}
for (const file of ["index.html", "styles.css", "app.js", "favicon.svg"]) {
  await copyFile(file, join(dist, "public", file));
}
await copyDir("src", join(dist, "src"));
for (const file of ["idb-store.js", "backend-client.js", "topology.js", "event-stitching.mjs", "network-heatmap.mjs", "executive-reporting.mjs", "platform-ui.mjs", "operations-ui.mjs"]) {
  await copyFile(join("src", file), join(dist, "public", "src", file));
}
console.log("Build complete: dist/");

async function copyDir(from, to) {
  await mkdir(to, { recursive: true });
  for (const entry of await readdir(from)) {
    const source = join(from, entry);
    const target = join(to, entry);
    const info = await stat(source);
    if (info.isDirectory()) {
      await copyDir(source, target);
    } else {
      await copyFile(source, target);
    }
  }
}
