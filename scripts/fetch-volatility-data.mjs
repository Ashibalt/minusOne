#!/usr/bin/env node
/**
 * Fetch the Volatility Foundation's public test corpus into .minusone/datasets/.
 * These are the fixtures for the memory.volatility provider: the same images
 * volatility3's own CI analyzes, published under the VSL license specifically
 * for testing. Nothing here is executed — memory images are read-only input.
 *
 * Usage:
 *   node scripts/fetch-volatility-data.mjs            # XP laptop image (~172 MB gz, ~1 GB raw)
 *   node scripts/fetch-volatility-data.mjs symbols    # full Windows symbol pack (~801 MB zip,
 *                                                     # offline fallback when online symbol
 *                                                     # generation is not possible)
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, stat } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import zlib from "node:zlib";

const RELEASE = "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1";

const ARTIFACTS = {
  image: {
    url: `${RELEASE}/win-xp-laptop-2005-06-25.img.gz`,
    file: "win-xp-laptop-2005-06-25.img.gz",
    sha256: "4cbdd5725adbb9505c8b3f4a51f0f042bac8dd53bf1dcc4b3bb7c71a6c8a74cd",
  },
  symbols: {
    url: `${RELEASE}/symbols/windows.zip`,
    file: "volatility-symbols-windows.zip",
    sha256: "231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e",
  },
};

const datasetsDir = path.resolve(".minusone", "datasets");

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.once("error", reject);
    child.once("close", (exitCode) => resolve(exitCode ?? -1));
  });
}

async function sha256File(filePath) {
  const hash = createHash("sha256");
  await pipeline(createReadStream(filePath), hash);
  return hash.digest("hex");
}

async function download(artifact) {
  const destination = path.join(datasetsDir, artifact.file);
  try {
    const stats = await stat(destination);
    if (stats.size > 0 && (await sha256File(destination)) === artifact.sha256) {
      console.log(`[fetch] ${artifact.file}: already present and verified (${stats.size} bytes)`);
      return destination;
    }
    console.log(`[fetch] ${artifact.file}: present but digest mismatch — resuming download`);
  } catch {
    console.log(`[fetch] ${artifact.file}: downloading ${artifact.url}`);
  }
  const exitCode = await run("curl", ["-fL", "--retry", "3", "-C", "-", "-o", destination, artifact.url]);
  if (exitCode !== 0) throw new Error(`curl exited with code ${exitCode} for ${artifact.url}`);
  const digest = await sha256File(destination);
  if (digest !== artifact.sha256) {
    throw new Error(`sha256 mismatch for ${artifact.file}: expected ${artifact.sha256}, got ${digest}`);
  }
  console.log(`[fetch] ${artifact.file}: sha256 verified`);
  return destination;
}

async function gunzip(gzPath, rawPath) {
  const stats = await stat(rawPath).catch(() => null);
  if (stats && stats.size > 0) {
    console.log(`[fetch] ${path.basename(rawPath)}: already extracted (${stats.size} bytes)`);
    return;
  }
  console.log(`[fetch] extracting ${path.basename(gzPath)} -> ${path.basename(rawPath)}`);
  const temporary = `${rawPath}.part`;
  await pipeline(
    createReadStream(gzPath),
    zlib.createGunzip(),
    createWriteStream(temporary),
  );
  await rename(temporary, rawPath);
  const rawStats = await stat(rawPath);
  console.log(`[fetch] ${path.basename(rawPath)}: ${rawStats.size} bytes`);
}

async function extractSymbols(zipPath) {
  const target = path.join(datasetsDir, "volatility-symbols");
  const marker = path.join(target, "windows");
  const existing = await stat(marker).catch(() => null);
  if (existing) {
    console.log(`[fetch] volatility-symbols/windows: already extracted`);
    return;
  }
  await mkdir(target, { recursive: true });
  console.log(`[fetch] extracting ${path.basename(zipPath)} -> ${path.relative(process.cwd(), target)}`);
  // Windows 10 ships bsdtar, which handles zip archives; Git Bash adds unzip.
  const exitCode = await run("tar", ["-xf", zipPath, "-C", target]);
  if (exitCode !== 0) {
    const fallback = await run("unzip", ["-q", zipPath, "-d", target]);
    if (fallback !== 0) throw new Error("could not extract the symbol pack (need tar or unzip)");
  }
  if (!(await stat(marker).catch(() => null))) {
    throw new Error("symbol pack extracted but the windows/ directory is missing");
  }
}

const mode = process.argv[2] ?? "image";
await mkdir(datasetsDir, { recursive: true });

if (mode === "image") {
  const gzPath = await download(ARTIFACTS.image);
  await gunzip(gzPath, path.join(datasetsDir, "win-xp-laptop-2005-06-25.img"));
  // The verified gz stays on disk: re-extraction after a workspace wipe is cheap.
  console.log("[fetch] memory image ready: .minusone/datasets/win-xp-laptop-2005-06-25.img");
} else if (mode === "symbols") {
  const zipPath = await download(ARTIFACTS.symbols);
  await extractSymbols(zipPath);
  console.log("[fetch] offline symbol pack ready: .minusone/datasets/volatility-symbols/windows");
} else {
  console.error(`unknown mode ${JSON.stringify(mode)} — expected "image" or "symbols"`);
  process.exit(2);
}
