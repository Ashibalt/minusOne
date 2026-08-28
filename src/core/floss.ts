import { createHash } from "node:crypto";
import { mkdir, open, readFile, readdir, realpath, rm, stat } from "node:fs/promises";
import path from "node:path";
import { cacheKeyDigest, findArtifactByCacheKey, readArtifactFull, storeArtifact } from "./artifacts.js";
import { inspectBinary } from "./binary.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * FLOSS deep string extraction: emulates decoding routines statically — the
 * sample is never executed. Complements the native strings provider, which
 * only sees plaintext already present in the file.
 */
export const FLOSS_DEFAULT_TIMEOUT_SECONDS = 900;
export const FLOSS_MAX_TIMEOUT_SECONDS = 1800;
export const FLOSS_CLASSES = ["static", "stack", "tight", "decoded"] as const;
export type FlossClass = (typeof FLOSS_CLASSES)[number];

export interface FlossExtractOptions {
  minLength?: number;
  includeStatic?: boolean;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface FlossExtractResult {
  backend: "local" | "docker";
  resultPath: string;
  command: CommandResult;
  report?: unknown;
}

interface FlossString {
  string?: unknown;
  encoding?: unknown;
  offset?: unknown;
  address?: unknown;
  address_type?: unknown;
  decoded_at?: unknown;
  decoding_routine?: unknown;
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalFloss(): Promise<string | null> {
  const explicit = process.env.MINUSONE_FLOSS_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("floss", ["--version"]);
  return probe ? "floss" : null;
}

function hex(value: unknown): string | null {
  return typeof value === "number" && Number.isFinite(value) ? `0x${value.toString(16)}` : null;
}

function boundedString(value: unknown, maxChars: number): string {
  if (typeof value !== "string") return "";
  return value.length <= maxChars ? value : `${value.slice(0, maxChars)}…`;
}

/**
 * Compact model-facing summary of a FLOSS JSON report. Offsets and routine
 * addresses become hex so the agent can cross-reference disassembly and
 * decompilation directly.
 */
export function summarizeFlossReport(
  report: unknown,
  maxPerClass = 200,
  maxStringChars = 200,
): {
  version: string | null;
  minLength: number | null;
  runtimeSeconds: number | null;
  counts: Record<string, number>;
  truncated: boolean;
  decoded: unknown[];
  stack: unknown[];
  tight: unknown[];
  static: unknown[];
} {
  const empty = {
    version: null,
    minLength: null,
    runtimeSeconds: null,
    counts: {} as Record<string, number>,
    truncated: false,
    decoded: [],
    stack: [],
    tight: [],
    static: [],
  };
  if (report === null || typeof report !== "object") return empty;
  const parsed = report as {
    metadata?: { min_length?: unknown; version?: unknown; runtime?: { total?: unknown } };
    strings?: Record<string, unknown>;
  };
  const strings = parsed.strings ?? {};
  const pick = (key: string): FlossString[] =>
    Array.isArray(strings[key]) ? (strings[key] as FlossString[]) : [];

  const decodedAll = pick("decoded_strings");
  const stackAll = pick("stack_strings");
  const tightAll = pick("tight_strings");
  const staticAll = pick("static_strings");
  const truncated =
    decodedAll.length > maxPerClass ||
    stackAll.length > maxPerClass ||
    tightAll.length > maxPerClass ||
    staticAll.length > maxPerClass;

  const clip = (entries: FlossString[]) => entries.slice(0, maxPerClass);
  const runtime = parsed.metadata?.runtime?.total;

  return {
    version: typeof parsed.metadata?.version === "string" ? parsed.metadata.version : null,
    minLength: typeof parsed.metadata?.min_length === "number" ? parsed.metadata.min_length : null,
    runtimeSeconds: typeof runtime === "number" ? runtime : null,
    counts: {
      decoded: decodedAll.length,
      stack: stackAll.length,
      tight: tightAll.length,
      static: staticAll.length,
      language: Array.isArray(strings.language_strings) ? strings.language_strings.length : 0,
    },
    truncated,
    decoded: clip(decodedAll).map((entry) => ({
      string: boundedString(entry.string, maxStringChars),
      encoding: typeof entry.encoding === "string" ? entry.encoding : null,
      addressType: typeof entry.address_type === "string" ? entry.address_type : null,
      decodedAt: hex(entry.decoded_at),
      decodingRoutine: hex(entry.decoding_routine),
    })),
    stack: clip(stackAll).map((entry) => ({
      string: boundedString(entry.string, maxStringChars),
      encoding: typeof entry.encoding === "string" ? entry.encoding : null,
      address: hex(entry.address),
    })),
    tight: clip(tightAll).map((entry) => ({
      string: boundedString(entry.string, maxStringChars),
      encoding: typeof entry.encoding === "string" ? entry.encoding : null,
      address: hex(entry.address),
    })),
    static: clip(staticAll).map((entry) => ({
      string: boundedString(entry.string, maxStringChars),
      encoding: typeof entry.encoding === "string" ? entry.encoding : null,
      offset: hex(entry.offset),
    })),
  };
}

export async function runFlossExtraction(
  workspace: Workspace,
  userPath: string,
  options: FlossExtractOptions = {},
): Promise<FlossExtractResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const binary = await inspectBinary(workspace, userPath);
  const outDirectory = path.join(workspace.root, ".minusone", "floss", "out");
  const resultPath = path.join(outDirectory, `floss-${binary.sampleId}.json`);
  await mkdir(outDirectory, { recursive: true });
  await rm(resultPath, { force: true });

  const timeoutSeconds = Math.min(
    FLOSS_MAX_TIMEOUT_SECONDS,
    options.timeoutSeconds ?? FLOSS_DEFAULT_TIMEOUT_SECONDS,
  );
  const minLength = options.minLength ?? 4;
  const args = ["-q", "-j", "-n", String(minLength)];
  if (options.includeStatic !== true) args.push("--only", "stack", "tight", "decoded");
  args.push("--");

  const createResult = async (
    backend: "local" | "docker",
    command: CommandResult,
    stdoutJson?: string,
  ): Promise<FlossExtractResult> => {
    const base: FlossExtractResult = {
      backend,
      resultPath: workspace.relative(resultPath),
      command,
    };
    if (command.exitCode !== 0 || command.timedOut) return base;
    try {
      const raw =
        stdoutJson !== undefined && stdoutJson.trimStart().startsWith("{")
          ? stdoutJson
          : await readFile(resultPath, "utf8");
      return { ...base, report: JSON.parse(raw) as unknown };
    } catch {
      return base;
    }
  };

  const localFloss = await resolveLocalFloss();
  const image = resolveDockerImage(process.env.MINUSONE_FLOSS_IMAGE, DEFAULT_IMAGES.floss);
  if (localFloss === null && image === null) {
    throw new Error("floss is disabled: MINUSONE_FLOSS_IMAGE is explicitly empty and no local floss was found. Unset the variable to restore the pinned default image.");
  }

  if (localFloss !== null) {
    const command = await runBoundedCommand(localFloss, [...args, absolutePath], {
      cwd: workspace.root,
      timeoutMs: (timeoutSeconds + 60) * 1000,
      maxOutputBytes: 32 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return await createResult("local", command, command.stdout);
  }

  // JSON lands in the writable /out mount while the workspace stays read-only.
  const command = await runBoundedCommand("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "2",
    "--memory",
    "2g",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    "--volume",
    dockerVolume(outDirectory, "/out"),
    "--entrypoint",
    "sh",
    image as string,
    "-c",
    `floss ${args.join(" ")} '${dockerPath(relativePath)}' > '/out/${path.basename(resultPath)}'`,
  ], {
    cwd: workspace.root,
    timeoutMs: (timeoutSeconds + 120) * 1000,
    maxOutputBytes: 512 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return await createResult("docker", command);
}

/**
 * Auto-FLOSS over a pe-sieve dump directory: walk the dumpDir produced by
 * dynamic.unpack and run FLOSS deep extraction on every dumped PE module.
 * Dumps are inert files — nothing is executed. Results are cached by the
 * manifest of dumped files (path + size + digest) so a retried investigation
 * replays instead of re-running minutes of emulation.
 */
export const FLOSS_DUMPS_MAX_FILES = 8;
export const FLOSS_DUMPS_DEFAULT_TIMEOUT_SECONDS = 300;
export const FLOSS_DUMPS_MAX_TIMEOUT_SECONDS = 900;
const FLOSS_DUMPS_MAX_FILE_BYTES = 128 * 1024 * 1024;
const FLOSS_DUMPS_MAX_SCANNED = 512;
const FLOSS_DUMPS_MAX_HIGHLIGHTS = 40;

export interface FlossDumpsOptions {
  maxFiles?: number;
  minLength?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface FlossDumpFileResult {
  path: string;
  bytes: number;
  status: "analyzed" | "error" | "no-report" | "skipped-non-pe" | "skipped-too-large" | "skipped-over-cap";
  detail?: string;
  counts?: Record<string, number>;
  decoded?: unknown[];
  stack?: unknown[];
  tight?: unknown[];
}

async function resolveDumpDir(workspace: Workspace, userPath: string): Promise<string> {
  const lexical = path.resolve(workspace.root, userPath);
  const relative = path.relative(workspace.root, lexical);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`path escapes the workspace: ${userPath}`);
  }
  const resolved = await realpath(lexical).catch(() => {
    throw new Error(`directory does not exist: ${userPath}`);
  });
  const stats = await stat(resolved);
  if (!stats.isDirectory()) throw new Error(`not a directory: ${userPath}`);
  return resolved;
}

async function sha256OfFile(absolutePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await readFile(absolutePath));
  return hash.digest("hex");
}

export async function flossDumpDirectory(
  workspace: Workspace,
  userPath: string,
  options: FlossDumpsOptions = {},
): Promise<{ report: string; artifactId: string; cacheHit: boolean }> {
  const dumpDirAbsolute = await resolveDumpDir(workspace, userPath);
  const dumpDir = workspace.relative(dumpDirAbsolute);
  const maxFiles = Math.min(Math.max(options.maxFiles ?? FLOSS_DUMPS_MAX_FILES, 1), FLOSS_DUMPS_MAX_FILES);
  const perFileTimeout = Math.min(
    FLOSS_DUMPS_MAX_TIMEOUT_SECONDS,
    Math.max(60, options.timeoutSeconds ?? FLOSS_DUMPS_DEFAULT_TIMEOUT_SECONDS),
  );
  const minLength = options.minLength ?? 4;

  const localFloss = await resolveLocalFloss();
  const image = resolveDockerImage(process.env.MINUSONE_FLOSS_IMAGE, DEFAULT_IMAGES.floss);
  if (localFloss === null && image === null) {
    throw new Error("floss is disabled: MINUSONE_FLOSS_IMAGE is explicitly empty and no local floss was found. Unset the variable to restore the pinned default image.");
  }
  const backend: "local" | "docker" = localFloss !== null ? "local" : "docker";

  // Deterministic walk: sorted relative paths, depth-bounded, hard scan cap.
  const found: Array<{ relative: string; absolute: string; bytes: number }> = [];
  const walk = async (directory: string, prefix: string, depth: number): Promise<void> => {
    if (found.length >= FLOSS_DUMPS_MAX_SCANNED || depth > 4) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (found.length >= FLOSS_DUMPS_MAX_SCANNED) return;
      const absolute = path.join(directory, entry.name);
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        await walk(absolute, relative, depth + 1);
      } else {
        const stats = await stat(absolute).catch(() => null);
        if (stats !== null) found.push({ relative, absolute, bytes: stats.size });
      }
    }
  };
  await walk(dumpDirAbsolute, "", 0);
  found.sort((a, b) => a.relative.localeCompare(b.relative));

  const files: FlossDumpFileResult[] = [];
  const manifest: Array<{ path: string; workspacePath: string; bytes: number; sha256: string }> = [];
  // Every scanned file participates in the cache key (with its PE verdict) so
  // a directory that gains or loses files never replays a stale report.
  const cacheFiles: Array<{ path: string; bytes: number; pe: boolean; sha256?: string }> = [];
  for (const file of found) {
    let isPe = false;
    try {
      const handle = await open(file.absolute, "r");
      try {
        const head = Buffer.alloc(2);
        const { bytesRead } = await handle.read(head, 0, 2, 0);
        isPe = bytesRead === 2 && head.toString("latin1") === "MZ";
      } finally {
        await handle.close();
      }
    } catch {
      isPe = false;
    }
    if (!isPe) {
      files.push({ path: file.relative, bytes: file.bytes, status: "skipped-non-pe" });
      cacheFiles.push({ path: file.relative, bytes: file.bytes, pe: false });
      continue;
    }
    if (file.bytes > FLOSS_DUMPS_MAX_FILE_BYTES) {
      files.push({ path: file.relative, bytes: file.bytes, status: "skipped-too-large" });
      cacheFiles.push({ path: file.relative, bytes: file.bytes, pe: true });
      continue;
    }
    if (manifest.length >= maxFiles) {
      files.push({
        path: file.relative,
        bytes: file.bytes,
        status: "skipped-over-cap",
        detail: `analysis cap reached (${maxFiles} files); rerun with a higher maxFiles`,
      });
      cacheFiles.push({ path: file.relative, bytes: file.bytes, pe: true });
      continue;
    }
    const sha256 = await sha256OfFile(file.absolute);
    manifest.push({ path: file.relative, workspacePath: workspace.relative(file.absolute), bytes: file.bytes, sha256 });
    cacheFiles.push({ path: file.relative, bytes: file.bytes, pe: true, sha256 });
  }

  const cacheKey = cacheKeyDigest({
    operation: "dumps.floss",
    dumpDir,
    files: cacheFiles,
    options: { minLength },
    image,
    local: process.env.MINUSONE_FLOSS_BIN ?? null,
    schema: 1,
  });
  const cached = await findArtifactByCacheKey(workspace, cacheKey);
  if (cached !== null) {
    return { report: await readArtifactFull(workspace, cached.id), artifactId: cached.id, cacheHit: true };
  }

  const decodedSeen = new Set<string>();
  const decodedHighlights: string[] = [];
  for (const candidate of manifest) {
    if (options.signal?.aborted) break;
    const entry: FlossDumpFileResult = { path: candidate.path, bytes: candidate.bytes, status: "analyzed" };
    try {
      const result = await runFlossExtraction(workspace, candidate.workspacePath, {
        minLength,
        timeoutSeconds: perFileTimeout,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (options.signal?.aborted) break;
      if (result.command.exitCode !== 0 || result.command.timedOut) {
        entry.status = "error";
        entry.detail = `floss exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 256)}`;
      } else if (result.report === undefined) {
        entry.status = "no-report";
        entry.detail = `floss produced no parsable JSON report (result file ${result.resultPath})`;
      } else {
        const summary = summarizeFlossReport(result.report, 30, 200);
        entry.counts = summary.counts;
        entry.decoded = summary.decoded;
        entry.stack = summary.stack;
        entry.tight = summary.tight;
        for (const item of summary.decoded) {
          const value = (item as { string?: unknown }).string;
          if (typeof value === "string" && value !== "" && !decodedSeen.has(value) && decodedHighlights.length < FLOSS_DUMPS_MAX_HIGHLIGHTS) {
            decodedSeen.add(value);
            decodedHighlights.push(value);
          }
        }
      }
    } catch (error) {
      entry.status = "error";
      entry.detail = error instanceof Error ? error.message : String(error);
    }
    files.push(entry);
  }

  const analyzed = files.filter((file) => file.status === "analyzed").length;
  const errored = files.filter((file) => file.status === "error" || file.status === "no-report").length;
  const report = JSON.stringify(
    {
      schema: 1,
      dumpDir,
      backend,
      filesScanned: found.length,
      filesAnalyzed: analyzed,
      filesErrored: errored,
      files,
      decodedHighlights,
      next: decodedHighlights.length > 0
        ? "decodedHighlights are the deobfuscated strings recovered from the dumps; cross-reference them with disassembly of the matching dump module, then fuse the evidence with report_correlate (dumpDirPath)"
        : "no decoded strings surfaced from the dumps; fall back to strings_extract_deep or function_decompile on the original sample",
    },
    null,
    2,
  );
  const artifact = await storeArtifact(workspace, report, {
    mediaType: "application/json",
    sourceOperation: "dumps.floss",
    description: `Auto-FLOSS over ${manifest.length} dumped module(s) in ${dumpDir} (${backend} backend)`,
    cacheKey,
    backend,
  });
  return { report, artifactId: artifact.id, cacheHit: false };
}
