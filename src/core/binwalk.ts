import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * Binwalk signature scanning and carve-only extraction. Scan lists embedded
 * signatures; extract carves them out with --dd='.*' (no external extractor
 * is ever executed) and count/size/depth rails. Nothing carved is run.
 */
export const BINWALK_MAX_SIGNATURES = 200;

export interface BinwalkScanOptions {
  signal?: AbortSignal;
}

export interface BinwalkSignature {
  offset: string;
  decimalOffset: number;
  description: string;
}

export interface BinwalkScanResult {
  backend: "local" | "docker";
  command: CommandResult;
  signatures: BinwalkSignature[];
  truncated: boolean;
  /** Noise signatures suppressed by the impossible-metadata filter. */
  suppressedCount: number;
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalBinwalk(): Promise<string | null> {
  const explicit = process.env.MINUSONE_BINWALK_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("binwalk", ["--help"]);
  return probe ? "binwalk" : null;
}

/** Parse the stable DECIMAL/HEXADECIMAL/DESCRIPTION table binwalk prints. */
export function parseBinwalkSignatures(stdout: string, maxSignatures = BINWALK_MAX_SIGNATURES): { signatures: BinwalkSignature[]; truncated: boolean; suppressedCount: number } {
  const signatures: BinwalkSignature[] = [];
  let suppressed = 0;
  for (const line of stdout.split(/\r?\n/)) {
    const match = /^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$/.exec(line.trim());
    if (match === null) continue;
    const description = (match[3] ?? "").trim();
    if (isNoiseSignature(description)) {
      suppressed += 1;
      continue;
    }
    signatures.push({
      offset: match[2] ?? "0x0",
      decimalOffset: Number(match[1]),
      description,
    });
  }
  return { signatures: signatures.slice(0, maxSignatures), truncated: signatures.length > maxSignatures, suppressedCount: suppressed };
}

/**
 * Noise filter — the Unity.dll lesson: x86 code inside .text matches random
 * firmware headers ("bix header", dates 1970/2098, gigabyte sizes). A real
 * embedded image cannot carry impossible metadata, so those matches are
 * dropped instead of being served as findings the analyst must debunk.
 */
export function isNoiseSignature(description: string): boolean {
  // Impossible timestamps (epoch 1970, or beyond a sane future horizon).
  const dateMatch = description.match(/\b(19\d{2}|20\d{2})\b/g);
  if (dateMatch !== null) {
    for (const yearText of dateMatch) {
      const year = Number(yearText);
      if (year < 1985 || year > 2040) return true;
    }
  }
  // Impossible sizes: an embedded image larger than 4GB or sized in
  // "GB" cannot live inside any real file.
  const sizeMatch = description.match(/\b(\d+(?:\.\d+)?)\s*(GB|TB)\b/i);
  if (sizeMatch !== null) return true;
  const bigBytes = description.match(/\b(\d{10,})\s*(?:bytes|B)\b/i);
  if (bigBytes !== null) return true;
  // Known pattern-false-positive families on compiled x86: none of these
  // firmware headers coexist with a PE/ELF in the wild.
  if (/\b(bix|uimage|u-boot|squashfs.*\(.*unknown)|\bLZMA.*compressor.*\bdict\b/i.test(description)) {
    // Keep legitimate LZMA findings; only the dict-size-flavored noise trips.
    if (/\b(bix|uimage|u-boot)\b/i.test(description)) return true;
  }
  return false;
}

export async function runBinwalkScan(
  workspace: Workspace,
  userPath: string,
  options: BinwalkScanOptions = {},
): Promise<BinwalkScanResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  await inspectBinary(workspace, userPath);

  const localBinwalk = await resolveLocalBinwalk();
  const image = resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk);
  if (localBinwalk === null && image === null) {
    throw new Error("binwalk is disabled: MINUSONE_BINWALK_IMAGE is explicitly empty and no local binwalk was found. Unset the variable to restore the pinned default image.");
  }

  const create = (backend: "local" | "docker", command: CommandResult): BinwalkScanResult => ({
    backend,
    command,
    ...(command.exitCode === 0 && !command.timedOut
      ? parseBinwalkSignatures(command.stdout)
      : { signatures: [], truncated: false, suppressedCount: 0 }),
  });

  if (localBinwalk !== null) {
    const command = await runBoundedCommand(localBinwalk, [absolutePath], {
      cwd: workspace.root,
      timeoutMs: 120_000,
      maxOutputBytes: 4 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return create("local", command);
  }
  const command = await runBoundedCommand("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "1",
    "--memory",
    "1g",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    image as string,
    dockerPath(workspace.relative(absolutePath)),
  ], {
    cwd: workspace.root,
    timeoutMs: 180_000,
    maxOutputBytes: 4 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return create("docker", command);
}

export const BINWALK_EXTRACT_DEFAULT_MAX_FILES = 64;
export const BINWALK_EXTRACT_MAX_FILES_CAP = 512;
export const BINWALK_EXTRACT_DEFAULT_MAX_BYTES_PER_FILE = 16 * 1024 * 1024;
export const BINWALK_EXTRACT_MAX_BYTES_PER_FILE_CAP = 64 * 1024 * 1024;
export const BINWALK_EXTRACT_DEFAULT_DEPTH = 1;
export const BINWALK_EXTRACT_MAX_DEPTH = 3;
export const BINWALK_EXTRACT_DEFAULT_TIMEOUT_SECONDS = 300;
export const BINWALK_EXTRACT_MAX_TIMEOUT_SECONDS = 900;
const BINWALK_EXTRACT_WALK_MAX = 2048;

export interface BinwalkExtractOptions {
  maxFiles?: number;
  maxBytesPerFile?: number;
  depth?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface BinwalkCarvedFile {
  path: string;
  name: string;
  bytes: number;
  sha256: string;
}

export interface BinwalkExtractResult {
  backend: "local" | "docker";
  outDirectory: string;
  command: CommandResult;
  carved: BinwalkCarvedFile[];
  signatures: BinwalkSignature[];
  truncated: boolean;
}

async function sha256File(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

/** Bounded recursive walk of the carve output directory. */
async function listCarvedFiles(
  root: string,
  maxEntries: number,
): Promise<{ files: Array<{ absolute: string; bytes: number }>; truncated: boolean }> {
  const out: Array<{ absolute: string; bytes: number }> = [];
  let scanned = 0;
  let truncated = false;

  async function walk(dir: string): Promise<void> {
    if (truncated) return;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      scanned++;
      if (scanned > BINWALK_EXTRACT_WALK_MAX) {
        truncated = true;
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        if (truncated) return;
      } else if (entry.isFile()) {
        const fileStat = await stat(full).catch(() => null);
        if (fileStat !== null) out.push({ absolute: full, bytes: fileStat.size });
        if (out.length >= maxEntries) {
          truncated = true;
          return;
        }
      }
    }
  }

  await walk(root);
  return { files: out, truncated };
}

/**
 * Carve-only extraction. --dd='.*' matches every signature and, with no
 * :cmd suffix, runs no external extractor; -n/-j cap file count and per-file
 * bytes; -d caps matryoshka recursion. The sample is read from the read-only
 * /workspace mount; carved blobs land in the writable /out mount.
 */
export async function runBinwalkExtract(
  workspace: Workspace,
  userPath: string,
  options: BinwalkExtractOptions = {},
): Promise<BinwalkExtractResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const sample = await inspectBinary(workspace, userPath);

  const maxFiles = Math.min(
    BINWALK_EXTRACT_MAX_FILES_CAP,
    Math.max(1, options.maxFiles ?? BINWALK_EXTRACT_DEFAULT_MAX_FILES),
  );
  const maxBytesPerFile = Math.min(
    BINWALK_EXTRACT_MAX_BYTES_PER_FILE_CAP,
    Math.max(1024, options.maxBytesPerFile ?? BINWALK_EXTRACT_DEFAULT_MAX_BYTES_PER_FILE),
  );
  const depth = Math.min(
    BINWALK_EXTRACT_MAX_DEPTH,
    Math.max(1, options.depth ?? BINWALK_EXTRACT_DEFAULT_DEPTH),
  );
  const timeoutSeconds = Math.min(
    BINWALK_EXTRACT_MAX_TIMEOUT_SECONDS,
    Math.max(30, options.timeoutSeconds ?? BINWALK_EXTRACT_DEFAULT_TIMEOUT_SECONDS),
  );

  const outDirectory = path.join(workspace.root, ".minusone", "binwalk", "out");
  // Start from a clean carve directory so re-runs never mix stale blobs.
  await rm(outDirectory, { recursive: true, force: true });
  await mkdir(outDirectory, { recursive: true });

  const recurse = depth > 1;
  const binwalkArgs = [
    "--dd=.*",
    `--directory=${outDirectory}`,
    `--size=${maxBytesPerFile}`,
    `--count=${maxFiles}`,
    ...(recurse ? ["--matryoshka", `--depth=${depth}`] : []),
    absolutePath,
  ];

  const localBinwalk = await resolveLocalBinwalk();
  const image = resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk);
  if (localBinwalk === null && image === null) {
    throw new Error("binwalk is disabled: MINUSONE_BINWALK_IMAGE is explicitly empty and no local binwalk was found. Unset the variable to restore the pinned default image.");
  }

  const build = async (backend: "local" | "docker", command: CommandResult): Promise<BinwalkExtractResult> => {
    const { files, truncated: walkTruncated } = await listCarvedFiles(outDirectory, maxFiles);
    const carved: BinwalkCarvedFile[] = [];
    for (const file of files) {
      carved.push({
        path: workspace.relative(file.absolute),
        name: path.basename(file.absolute),
        bytes: file.bytes,
        sha256: await sha256File(file.absolute),
      });
    }
    const parsed =
      command.exitCode === 0 && !command.timedOut
        ? parseBinwalkSignatures(command.stdout)
        : { signatures: [], truncated: false };
    return {
      backend,
      outDirectory: workspace.relative(outDirectory),
      command,
      carved,
      signatures: parsed.signatures,
      truncated: walkTruncated || parsed.truncated,
    };
  };

  if (localBinwalk !== null) {
    const command = await runBoundedCommand(localBinwalk, binwalkArgs, {
      cwd: workspace.root,
      timeoutMs: (timeoutSeconds + 60) * 1000,
      maxOutputBytes: 8 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return await build("local", command);
  }

  // Carve into the writable /out mount; the sample is read read-only.
  const relativePath = workspace.relative(absolutePath);
  const command = await runBoundedCommand("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "2",
    "--memory",
    "1g",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    "--volume",
    dockerVolume(outDirectory, "/out"),
    "--workdir",
    "/out",
    image as string,
    "--dd=.*",
    "--directory=/out",
    `--size=${maxBytesPerFile}`,
    `--count=${maxFiles}`,
    "--run-as=root",
    ...(recurse ? ["--matryoshka", `--depth=${depth}`] : []),
    dockerPath(relativePath),
  ], {
    cwd: workspace.root,
    timeoutMs: (timeoutSeconds + 120) * 1000,
    maxOutputBytes: 8 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return await build("docker", command);
}
