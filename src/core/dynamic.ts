import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, open, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { readWorkspaceConfig } from "./config.js";
import { resolveSampleLaunch } from "./dllhost.js";
import { runBoundedCommand } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * The dynamic plane, local target mode. The analyst host becomes an
 * authorized execution target only by the OWNER'S explicit decision:
 * MINUSONE_ALLOW_DYNAMIC=1 AND MINUSONE_DYNAMIC_TARGET=local, OR a one-time
 * `minusone arm` that persists to `.minusone/config.json`. Env vars override
 * the config for one-shot use. There is no network isolation and no VM
 * boundary in this mode — the environment documents that in every result.
 */
export type DynamicTargetMode = "none" | "armed-no-target" | "local";

export async function resolveDynamicTarget(workspace?: Workspace): Promise<DynamicTargetMode> {
  // Env vars, when set, override the persisted config for one-shot use.
  const allowEnv = process.env.MINUSONE_ALLOW_DYNAMIC;
  const targetEnv = process.env.MINUSONE_DYNAMIC_TARGET;
  if (allowEnv !== undefined || targetEnv !== undefined) {
    if (allowEnv !== "1") return "none";
    if (targetEnv !== "local") return "armed-no-target";
    return "local";
  }
  if (workspace !== undefined) {
    const config = await readWorkspaceConfig(workspace);
    return config.dynamic === "local" ? "local" : "none";
  }
  return "none";
}

export const DYNAMIC_EXECUTE_MAX_SECONDS = 600;
export const DYNAMIC_EXECUTE_DEFAULT_SECONDS = 60;
export const DYNAMIC_UNPACK_MAX_RUN_SECONDS = 120;
const MAX_DROPPED_FILES = 200;

export interface ExecuteSampleOptions {
  args?: string[];
  timeoutSeconds?: number;
  /** Export for rundll32 to call when the sample is a DLL. */
  entryExport?: string;
  /** UTF-8 text piped to the sample's stdin (interactive crackmes, prompts). */
  stdin?: string;
  signal?: AbortSignal;
}

export interface DroppedFile {
  path: string;
  bytes: number;
}

export interface ExecuteSampleResult {
  runDir: string;
  command: CommandResult;
  droppedFiles: DroppedFile[];
  /** Set when the sample was launched through a host process (DLL via rundll32). */
  launchedVia?: string;
}

/** Bounded recursive listing used to diff files a sample dropped. */
async function listFiles(root: string, maxEntries = 1000): Promise<Map<string, number>> {
  const found = new Map<string, number>();
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (found.size >= maxEntries || depth > 4) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(full, depth + 1);
      } else {
        try {
          const stats = await stat(full);
          found.set(path.relative(root, full), stats.size);
        } catch {
          found.set(path.relative(root, full), 0);
        }
      }
      if (found.size >= maxEntries) return;
    }
  };
  await walk(root, 0);
  return found;
}

export async function executeSample(
  workspace: Workspace,
  userPath: string,
  options: ExecuteSampleOptions = {},
): Promise<ExecuteSampleResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });
  const before = await listFiles(runDir);

  const timeoutSeconds = Math.min(
    DYNAMIC_EXECUTE_MAX_SECONDS,
    options.timeoutSeconds ?? DYNAMIC_EXECUTE_DEFAULT_SECONDS,
  );
  // DLLs need a host process: rundll32 loads the DLL (DllMain runs) and
  // calls the chosen export; EXEs spawn directly.
  const launch = options.args !== undefined
    ? { command: absolutePath, args: options.args, host: "direct" as const, entryExport: null }
    : await resolveSampleLaunch(workspace, userPath, options.entryExport);
  const command = await runBoundedCommand(launch.command, launch.args, {
    cwd: runDir,
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 64 * 1024,
    ...(options.stdin === undefined ? {} : { stdinData: options.stdin }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  const after = await listFiles(runDir);
  const droppedFiles: DroppedFile[] = [];
  for (const [relative, bytes] of after) {
    if (before.has(relative)) continue;
    droppedFiles.push({ path: relative, bytes });
    if (droppedFiles.length >= MAX_DROPPED_FILES) break;
  }
  return {
    runDir: workspace.relative(runDir),
    command,
    droppedFiles,
    ...(launch.host === "rundll32" ? { launchedVia: `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}` } : {}),
  };
}

export interface UnpackSampleOptions {
  runSeconds?: number;
  /** Export for rundll32 to call when the sample is a DLL. */
  entryExport?: string;
  signal?: AbortSignal;
}

export interface UnpackSampleResult {
  pid: number;
  runDir: string;
  dumpDir: string;
  stillRunningAtScan: boolean;
  /** How the sample was launched (direct spawn, or rundll32 hosting a DLL). */
  launchedVia: string;
  sieve: CommandResult;
  dumpedFiles: DroppedFile[];
  sanitizedHeaders: { patched: number; skipped: number };
}

export function resolvePeSieve(): string | null {
  const explicit = process.env.MINUSONE_PESIEVE_BIN;
  if (explicit !== undefined && explicit !== "" && existsSync(explicit)) return explicit;
  const bundled = path.join(process.cwd(), "tools", "pe-sieve64.exe");
  return existsSync(bundled) ? bundled : null;
}

export interface DetachedLaunchOptions {
  args?: string[];
  /** Show the sample's console window (default hidden — the buffer is fully drivable without it). */
  visible?: boolean;
}

export interface DetachedLaunchResult {
  pid: number;
  runDir: string;
  visible: boolean;
  /** Set when the sample was launched through a host process (DLL via rundll32). */
  launchedVia?: string;
}

/**
 * Launch a sample DETACHED so it keeps running with its own console — the
 * prerequisite for the console.send/console.read interactive loop. The
 * launch goes through PowerShell Start-Process -WindowStyle Hidden because
 * the obvious Node route (spawn detached + windowsHide) passes
 * DETACHED_PROCESS/CREATE_NO_WINDOW — the child then has NO console at all
 * and every AttachConsole from the console plane fails. Start-Process gives
 * the console app a real (hidden) console whose screen buffer is fully
 * drivable through WriteConsoleInputW/ReadConsoleOutputCharacterW.
 * The caller owns the lifecycle: kill with `killProcessTree(pid)`.
 */
export async function launchDetachedSample(
  workspace: Workspace,
  userPath: string,
  options: DetachedLaunchOptions = {},
): Promise<DetachedLaunchResult> {
  if (process.platform !== "win32") {
    throw new Error("detached console launch is Windows-only: it relies on the Win32 console plane");
  }
  const absolutePath = await workspace.resolveFile(userPath);
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });
  const launch = options.args !== undefined
    ? { command: absolutePath, args: options.args, host: "direct" as const, entryExport: null }
    : await resolveSampleLaunch(workspace, userPath, undefined);
  // Single-quote PS strings; embedded quotes doubled — paths with spaces are safe.
  const psQuote = (value: string): string => `'${value.replace(/'/g, "''")}'`;
  const argList = launch.args.length > 0
    ? `$argList = @(${launch.args.map(psQuote).join(",")})`
    : "$argList = $null";
  const script = [
    argList,
    `$p = Start-Process -FilePath ${psQuote(launch.command)} -WorkingDirectory ${psQuote(runDir)} -WindowStyle ${options.visible === true ? "Normal" : "Hidden"} -PassThru`,
    "$p.Id",
  ].join("\n");
  const result = await runBoundedCommand(
    "powershell",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { timeoutMs: 30_000, maxOutputBytes: 16 * 1024 },
  );
  const pid = Number.parseInt(result.stdout.trim(), 10);
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`failed to launch ${userPath} detached: ${result.stderr.trim().slice(0, 400) || `unexpected output: ${result.stdout.trim().slice(0, 200)}`}`);
  }
  return {
    pid,
    runDir: workspace.relative(runDir),
    visible: options.visible === true,
    ...(launch.host === "rundll32"
      ? { launchedVia: `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}` }
      : {}),
  };
}

export async function killProcessTree(pid: number): Promise<void> {
  if (process.platform !== "win32") {
    process.kill(pid, "SIGKILL");
    return;
  }
  await runBoundedCommand("taskkill", ["/PID", String(pid), "/T", "/F"], {
    timeoutMs: 15_000,
    maxOutputBytes: 16 * 1024,
  });
}

const SCN_CNT_CODE = 0x20;
const SCN_CNT_UNINITIALIZED_DATA = 0x80;
const SCN_MEM_EXECUTE = 0x2000_0000;

/**
 * Section-header sanitizer for pe-sieve dumps. pe-sieve faithfully reproduces
 * the in-memory section table, so a UPX-packed sample carries UPX0 flagged
 * CNT_UNINITIALIZED_DATA (no CNT_CODE) even though the unpacker expanded real
 * code into it. Analyzers built on vivisect (FLOSS) refuse codeflow through
 * sections marked uninitialized, so decoded/stack string emulation silently
 * yields nothing. The fix is metadata-only: for any executable section that
 * actually carries raw bytes, clear CNT_UNINITIALIZED_DATA and assert
 * CNT_CODE. Section content is never touched.
 */
export function normalizeDumpedPe(buffer: Buffer): { patched: boolean; sections: number } {
  if (buffer.byteLength < 0x40 || buffer.readUInt16LE(0) !== 0x5a4d /* "MZ" */) {
    return { patched: false, sections: 0 };
  }
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 6 > buffer.byteLength) return { patched: false, sections: 0 };
  if (buffer.readUInt32LE(peOffset) !== 0x00004550 /* "PE\0\0" */) {
    return { patched: false, sections: 0 };
  }
  const numberOfSections = buffer.readUInt16LE(peOffset + 6);
  const sizeOfOptionalHeader = buffer.readUInt16LE(peOffset + 20);
  const sectionTable = peOffset + 24 + sizeOfOptionalHeader;
  if (sectionTable + numberOfSections * 40 > buffer.byteLength) {
    return { patched: false, sections: 0 };
  }
  let patched = false;
  for (let index = 0; index < numberOfSections; index += 1) {
    const entry = sectionTable + index * 40;
    const rawSize = buffer.readUInt32LE(entry + 16);
    const charsOffset = entry + 36;
    let chars = buffer.readUInt32LE(charsOffset);
    const executable = (chars & SCN_MEM_EXECUTE) !== 0;
    const uninitialized = (chars & SCN_CNT_UNINITIALIZED_DATA) !== 0;
    const hasCode = (chars & SCN_CNT_CODE) !== 0;
    if (rawSize > 0 && executable && uninitialized && !hasCode) {
      chars = (chars & ~SCN_CNT_UNINITIALIZED_DATA) | SCN_CNT_CODE;
      buffer.writeUInt32LE(chars, charsOffset);
      patched = true;
    }
  }
  return { patched, sections: numberOfSections };
}

async function normalizeDumpedPeFiles(dumpDir: string): Promise<{ patched: number; skipped: number }> {
  let patched = 0;
  let skipped = 0;
  const visit = async (directory: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      let handle;
      try {
        handle = await open(absolute, "r+");
      } catch {
        skipped += 1;
        continue;
      }
      try {
        const head = Buffer.alloc(0x40);
        const { bytesRead } = await handle.read(head, 0, 0x40, 0);
        if (bytesRead < 0x40 || head.readUInt16LE(0) !== 0x5a4d) {
          skipped += 1;
          continue;
        }
        const stats = await stat(absolute);
        const buffer = Buffer.alloc(stats.size);
        await handle.read(buffer, 0, stats.size, 0);
        const result = normalizeDumpedPe(buffer);
        if (result.patched) {
          await handle.write(buffer, 0, stats.size, 0);
          patched += 1;
        } else {
          skipped += 1;
        }
      } finally {
        await handle.close().catch(() => undefined);
      }
    }
  };
  await visit(dumpDir);
  return { patched, skipped };
}

/**
 * Run the sample for a bounded window, then scan its memory with pe-sieve
 * (BSD-2-Clause, pinned in tools/) and dump replaced/implanted modules —
 * the standard route to statically recovering the unpacked payload of a
 * packed sample without attaching a GUI debugger.
 */
export async function unpackSample(
  workspace: Workspace,
  userPath: string,
  options: UnpackSampleOptions = {},
): Promise<UnpackSampleResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const sieve = resolvePeSieve();
  if (sieve === null) {
    throw new Error("pe-sieve is not available. Set MINUSONE_PESIEVE_BIN or place tools/pe-sieve64.exe (release v0.4.1.1).");
  }
  const runSeconds = Math.min(DYNAMIC_UNPACK_MAX_RUN_SECONDS, options.runSeconds ?? 8);
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  const dumpDir = path.join(runDir, "dump");
  await mkdir(dumpDir, { recursive: true });

  // DLLs go through rundll32 so DllMain (where packers unpack) executes.
  const launch = await resolveSampleLaunch(workspace, userPath, options.entryExport);
  const child = spawn(launch.command, launch.args, { cwd: runDir, stdio: "ignore" });
  const pid = child.pid ?? -1;
  if (pid === -1) throw new Error(`failed to spawn ${userPath}`);
  const exited = new Promise<boolean>((resolve) => {
    child.once("exit", () => resolve(true));
  });

  try {
    const window = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), runSeconds * 1000);
      options.signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        resolve(false);
      }, { once: true });
    });
    const exitedEarly = await Promise.race([exited, window]);
    if (options.signal?.aborted) throw new Error("unpack cancelled before memory scan");

    const sieveResult = await runBoundedCommand(sieve, ["/pid", String(pid), "/dir", dumpDir, "/quiet"], {
      cwd: runDir,
      timeoutMs: 120_000,
      maxOutputBytes: 256 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const dumped = new Map<string, number>();
    for (const [relative, bytes] of await listFiles(dumpDir)) {
      dumped.set(relative, bytes);
    }
    // Section-flag sanitizer: pe-sieve carries UPX's uninitialized-data flag
    // into executable sections, which makes vivisect-based tools (FLOSS)
    // silently skip codeflow. Normalize the headers of every dumped PE so
    // downstream analyzers can disassemble. Content is never touched.
    const sanitized = await normalizeDumpedPeFiles(dumpDir).catch(() => ({ patched: 0, skipped: 0 }));
    return {
      pid,
      runDir: workspace.relative(runDir),
      dumpDir: workspace.relative(dumpDir),
      stillRunningAtScan: !exitedEarly,
      launchedVia: launch.host === "rundll32"
        ? `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}`
        : "direct",
      sieve: sieveResult,
      dumpedFiles: [...dumped.entries()].map(([file, bytes]) => ({ path: file, bytes })).slice(0, MAX_DROPPED_FILES),
      sanitizedHeaders: sanitized,
    };
  } finally {
    void killProcessTree(pid);
  }
}
