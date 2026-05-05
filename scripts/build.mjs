import { mkdir, copyFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";

const dist = "dist";
await mkdir(dist, { recursive: true });
for (const file of ["index.html", "styles.css", "app.js", "server.mjs", "package.json"]) {
  await copyFile(file, join(dist, file));
}
await copyDir("src", join(dist, "src"));
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
