#!/usr/bin/env node

import { createWriteStream } from "node:fs";
import { access, mkdir, rename, rm, stat } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import { basename, dirname, extname, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

const MAX_REDIRECTS = 10;
const DEFAULT_DIR = "downloads";
const VIDEO_EXTENSIONS = new Set([
  ".3gp",
  ".avi",
  ".flv",
  ".m4v",
  ".mkv",
  ".mov",
  ".mp4",
  ".mpeg",
  ".mpg",
  ".ogg",
  ".ogv",
  ".ts",
  ".webm",
  ".wmv",
]);

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help || !options.url) {
    printUsage();
    process.exit(options.help ? 0 : 1);
  }

  const url = parseHttpUrl(options.url);
  const response = await openUrl(url, 0);
  const contentLength = Number(response.headers["content-length"] || 0);
  const contentType = String(response.headers["content-type"] || "");
  const outputPath = await getOutputPath(response.url, response.headers, options.output);

  if (!options.force) {
    await assertFileDoesNotExist(outputPath);
  }

  await mkdir(dirname(outputPath), { recursive: true });
  const tempPath = `${outputPath}.part`;

  try {
    console.log(`Downloading ${response.url.href}`);
    if (contentType && !contentType.toLowerCase().startsWith("video/")) {
      console.warn(`Warning: server reported content type "${contentType}". Saving it anyway.`);
    }
    console.log(`Saving to ${outputPath}`);

    response.stream.on("data", createProgressReporter(contentLength));
    await pipeline(response.stream, createWriteStream(tempPath));
    await rename(tempPath, outputPath);

    console.log(`Done: ${outputPath}`);
  } catch (error) {
    await rm(tempPath, { force: true });
    throw error;
  }
}

function parseArgs(args) {
  const options = { force: false, help: false, output: null, url: null };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "-h" || arg === "--help") {
      options.help = true;
    } else if (arg === "-f" || arg === "--force") {
      options.force = true;
    } else if (arg === "-o" || arg === "--output") {
      const value = args[index + 1];
      if (!value) {
        throw new Error(`Missing value for ${arg}`);
      }
      options.output = value;
      index += 1;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!options.url) {
      options.url = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  return options;
}

function parseHttpUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid URL: ${value}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http:// and https:// URLs are supported.");
  }

  return url;
}

function openUrl(url, redirects) {
  if (redirects > MAX_REDIRECTS) {
    throw new Error(`Too many redirects while downloading ${url.href}`);
  }

  const client = url.protocol === "https:" ? https : http;

  return new Promise((resolveResponse, rejectResponse) => {
    const request = client.get(
      url,
      {
        headers: {
          "User-Agent": "SignalPrism-video-downloader/1.0",
        },
      },
      (response) => {
        const statusCode = response.statusCode || 0;

        if (statusCode >= 300 && statusCode < 400 && response.headers.location) {
          response.resume();
          const nextUrl = new URL(response.headers.location, url);
          openUrl(nextUrl, redirects + 1).then(resolveResponse, rejectResponse);
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          response.resume();
          rejectResponse(new Error(`Download failed with HTTP ${statusCode} for ${url.href}`));
          return;
        }

        resolveResponse({ headers: response.headers, stream: response, url });
      },
    );

    request.on("error", rejectResponse);
    request.setTimeout(30_000, () => {
      request.destroy(new Error(`Timed out connecting to ${url.href}`));
    });
  });
}

async function getOutputPath(url, headers, output) {
  if (output) {
    const resolvedOutput = resolve(output);
    if (await pathIsDirectory(resolvedOutput)) {
      return join(resolvedOutput, inferFileName(url, headers));
    }
    return resolvedOutput;
  }

  return resolve(DEFAULT_DIR, inferFileName(url, headers));
}

function inferFileName(url, headers) {
  const dispositionName = parseContentDispositionFilename(headers["content-disposition"]);
  const urlName = sanitizeFileName(decodeURIComponent(basename(url.pathname))) || null;
  const fallbackName = "downloaded-video.mp4";
  const fileName = dispositionName || urlName || fallbackName;

  if (VIDEO_EXTENSIONS.has(extname(fileName).toLowerCase())) {
    return fileName;
  }

  const contentType = String(headers["content-type"] || "").toLowerCase();
  const extension = extensionFromContentType(contentType);
  return `${fileName}${extension}`;
}

function parseContentDispositionFilename(value) {
  if (!value) {
    return null;
  }

  const header = Array.isArray(value) ? value[0] : value;
  const encodedMatch = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (encodedMatch) {
    return sanitizeFileName(decodeURIComponent(encodedMatch[1]));
  }

  const quotedMatch = /filename="([^"]+)"/i.exec(header);
  if (quotedMatch) {
    return sanitizeFileName(quotedMatch[1]);
  }

  const plainMatch = /filename=([^;]+)/i.exec(header);
  if (plainMatch) {
    return sanitizeFileName(plainMatch[1]);
  }

  return null;
}

function sanitizeFileName(value) {
  return value.replaceAll(/[<>:"/\\|?*\u0000-\u001f]/g, "_").trim();
}

function extensionFromContentType(contentType) {
  if (contentType.includes("video/mp4")) return ".mp4";
  if (contentType.includes("video/quicktime")) return ".mov";
  if (contentType.includes("video/webm")) return ".webm";
  if (contentType.includes("video/x-matroska")) return ".mkv";
  if (contentType.includes("video/x-msvideo")) return ".avi";
  if (contentType.includes("video/x-ms-wmv")) return ".wmv";
  if (contentType.includes("application/vnd.apple.mpegurl")) return ".m3u8";
  if (contentType.includes("application/x-mpegurl")) return ".m3u8";
  return ".mp4";
}

async function pathIsDirectory(path) {
  try {
    return (await stat(path)).isDirectory();
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function assertFileDoesNotExist(path) {
  try {
    await access(path);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }

  throw new Error(`File already exists: ${path}. Use --force to overwrite it.`);
}

function createProgressReporter(totalBytes) {
  let downloadedBytes = 0;
  let lastUpdate = 0;

  return (chunk) => {
    downloadedBytes += chunk.length;
    const now = Date.now();
    if (now - lastUpdate < 250) {
      return;
    }
    lastUpdate = now;

    if (totalBytes > 0) {
      const percent = ((downloadedBytes / totalBytes) * 100).toFixed(1).padStart(5);
      process.stdout.write(`\r${formatBytes(downloadedBytes)} / ${formatBytes(totalBytes)} (${percent}%)`);
    } else {
      process.stdout.write(`\r${formatBytes(downloadedBytes)} downloaded`);
    }
  };
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function printUsage() {
  console.log(`Usage:
  node scripts/download-video.mjs <video-url> [--output <path>] [--force]

Examples:
  node scripts/download-video.mjs "https://example.com/video.mp4"
  node scripts/download-video.mjs "https://example.com/video.mp4" --output ./videos/demo.mp4
  node scripts/download-video.mjs "https://example.com/video.mp4" --output ./videos --force

Notes:
  - Works with direct http(s) video file URLs.
  - For sites that stream through players or playlists, use an authorized downloader for that service.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  });
}
