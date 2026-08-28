import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import { fileOffsetToRva, parsePeTablesFromBuffer } from "./peimports.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * radare2: analysis-backed function discovery and bounded disassembly — the
 * second disassembly provider behind the semantic operations. It finds
 * functions in stripped binaries where symbol-based objdump lookups fail.
 * The sample is opened read-only; nothing is executed.
 */
export const RADARE_DEFAULT_TIMEOUT_SECONDS = 180;
export const RADARE_MAX_TIMEOUT_SECONDS = 900;

export interface RadareFunctionListOptions {
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface RadareFunction {
  offset?: number;
  name?: string;
  size?: number;
  realsz?: number;
  nbbs?: number;
  signature?: string;
}

export interface RadareDumpOptions {
  address?: string;
  symbol?: string;
  count: number;
  mode: "code" | "hex";
  signal?: AbortSignal;
}

export interface RadareFunctionListResult {
  backend: "local" | "docker";
  command: CommandResult;
  functions?: RadareFunction[];
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

/**
 * r2 colorizes its output when it believes a terminal is attached (docker
 * without a tty still emits truecolor ESC sequences). The tool answer must
 * be plain text: strip residual ANSI/CSI sequences as a safety net on top
 * of `e scr.color=0` (set in radareCommandArgs).
 */
export function stripAnsiEscapes(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "");
}

export async function resolveLocalRadare(): Promise<string | null> {
  const explicit = process.env.MINUSONE_R2_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("r2", ["-v"]);
  if (probe !== null) return "r2";
  const fallback = await probeCommand("radare2", ["-v"]);
  return fallback !== null ? "radare2" : null;
}

// ---------------------------------------------------------------------------
// Long-lived r2 session (the analysis cache). One `docker run -i` (or local
// r2) per sample, speaking the r2pipe protocol (`-q0`: NUL-terminated
// responses). `-A` runs ONCE at boot; every later command reuses the analyzed
// session instead of paying a full re-analysis per call. Sessions die on an
// idle timeout and on host shutdown.
// ---------------------------------------------------------------------------

const R2_SESSION_IDLE_MS = 10 * 60 * 1000;
const R2_SESSION_SWEEP_MS = 60 * 1000;
const R2_SESSION_BOOT_TIMEOUT_MS = RADARE_MAX_TIMEOUT_SECONDS * 1000;
const R2_SESSION_COMMAND_TIMEOUT_MS = 120 * 1000;

interface R2Session {
  sampleId: string;
  containerName: string;
  child: ChildProcessWithoutNullStreams;
  backend: "local" | "docker";
  queue: Promise<unknown>;
  lastUsed: number;
  dead: boolean;
}

const r2Sessions = new Map<string, R2Session>();
let r2SweepTimer: NodeJS.Timeout | null = null;

function ensureSweepTimer(): void {
  if (r2SweepTimer !== null) return;
  r2SweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [sampleId, session] of r2Sessions) {
      if (session.dead || now - session.lastUsed > R2_SESSION_IDLE_MS) {
        void closeR2Session(session).catch(() => undefined);
        r2Sessions.delete(sampleId);
      }
    }
    if (r2Sessions.size === 0 && r2SweepTimer !== null) {
      clearInterval(r2SweepTimer);
      r2SweepTimer = null;
    }
  }, R2_SESSION_SWEEP_MS);
  r2SweepTimer.unref?.();
}

async function closeR2Session(session: R2Session): Promise<void> {
  session.dead = true;
  await new Promise<void>((resolve) => {
    const killTimer = setTimeout(() => {
      try {
        session.child.kill();
      } catch {
        // Best effort.
      }
      resolve();
    }, 3000);
    session.child.once("close", () => {
      clearTimeout(killTimer);
      resolve();
    });
    try {
      session.child.stdin.write("q\n");
      session.child.stdin.end();
    } catch {
      // stdin already gone — the kill timer handles it.
    }
  });
  if (session.backend === "docker") {
    // r2 exiting ends the container (--rm removes it); docker kill is the
    // belt-and-braces path for a wedged container.
    await runBoundedCommand("docker", ["kill", session.containerName], {
      timeoutMs: 15_000,
      maxOutputBytes: 64 * 1024,
    }).catch(() => null);
  }
}

/** Kill every cached r2 session (host shutdown hook). */
export async function shutdownRadareSessions(): Promise<void> {
  const closing = [...r2Sessions.values()].map((session) => closeR2Session(session).catch(() => undefined));
  r2Sessions.clear();
  if (r2SweepTimer !== null) {
    clearInterval(r2SweepTimer);
    r2SweepTimer = null;
  }
  await Promise.allSettled(closing);
}

async function bootR2Session(
  workspace: Workspace,
  absolutePath: string,
  sampleId: string,
  backend: "local" | "docker",
  localBin: string | null,
  image: string,
): Promise<R2Session> {
  const containerName = `minusone-r2-${sampleId}-${Date.now().toString(36)}`;
  // Boot WITHOUT -A: an in-argument analysis makes r2 treat the buffered
  // stdin as a batch script and exit once it completes. Instead the session
  // boots into the REPL first (fast NUL ping), then runs `aaa` as an in-band
  // command — the analysis cost is paid once, the session stays alive.
  const child =
    backend === "local"
      ? (spawn(localBin as string, ["-q0", absolutePath], {
          cwd: workspace.root,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        }) as ChildProcessWithoutNullStreams)
      : (spawn(
          "docker",
          [
            "run",
            "-i",
            "--rm",
            "--name",
            containerName,
            "--network",
            "none",
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--volume",
            dockerVolume(workspace.root, "/workspace", "ro"),
            image,
            "r2",
            "-q0",
            dockerPath(workspace.relative(absolutePath)),
          ],
          { cwd: workspace.root, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
        ) as ChildProcessWithoutNullStreams);

  const session: R2Session = {
    sampleId,
    containerName,
    child,
    backend,
    queue: Promise.resolve(),
    lastUsed: Date.now(),
    dead: false,
  };
  child.once("close", () => {
    session.dead = true;
    if (r2Sessions.get(sampleId) === session) r2Sessions.delete(sampleId);
  });

  // Boot ping + one-time analysis. A process that dies before the first
  // reply is almost always an infrastructure failure (docker daemon down,
  // image missing) — surface its stderr instead of a generic exit.
  try {
    await sessionExec(session, "e scr.color=0", 10_000);
    await sessionExec(session, "aaa", R2_SESSION_BOOT_TIMEOUT_MS);
  } catch (error) {
    const stderrTail = child.stderr.read();
    const detail = stderrTail === null ? "" : String(stderrTail).slice(-512).trim();
    const base = error instanceof Error ? error.message : String(error);
    throw new Error(
      detail !== ""
        ? `cached radare2 session failed to boot (${base}); backend stderr: ${detail}`
        : `cached radare2 session failed to boot (${base})`,
    );
  }
  return session;
}

interface SessionCommandOutcome {
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function sessionExec(session: R2Session, command: string, timeoutMs: number, signal?: AbortSignal): Promise<SessionCommandOutcome> {
  const run = session.queue.then(
    () =>
      new Promise<SessionCommandOutcome>((resolve, reject) => {
        if (session.dead) {
          reject(new Error("the cached radare2 session exited"));
          return;
        }
        session.lastUsed = Date.now();
        let stdout = "";
        let stderr = "";
        let settled = false;
        const stdoutChunks: Buffer[] = [];
        const onStdout = (chunk: Buffer): void => {
          stdoutChunks.push(chunk);
          const text = Buffer.concat(stdoutChunks).toString("utf8");
          const terminator = text.indexOf("\x00");
          if (terminator >= 0 && !settled) {
            settled = true;
            cleanup();
            resolve({ stdout: text.slice(0, terminator), stderr, timedOut: false });
          }
        };
        const stderrChunks: Buffer[] = [];
        const onStderr = (chunk: Buffer): void => {
          stderrChunks.push(chunk);
          stderr = Buffer.concat(stderrChunks).toString("utf8");
        };
        const onClose = (): void => {
          if (!settled) {
            settled = true;
            cleanup();
            reject(new Error("the cached radare2 session exited mid-command"));
          }
        };
        const onAbort = (): void => {
          if (!settled) {
            settled = true;
            cleanup();
            reject(signal?.reason instanceof Error ? signal.reason : new Error("radare2 command aborted"));
          }
        };
        const timer = setTimeout(() => {
          if (!settled) {
            settled = true;
            cleanup();
            resolve({ stdout: Buffer.concat(stdoutChunks).toString("utf8"), stderr, timedOut: true });
          }
        }, timeoutMs);
        const cleanup = (): void => {
          clearTimeout(timer);
          session.child.stdout.removeListener("data", onStdout);
          session.child.stderr.removeListener("data", onStderr);
          session.child.removeListener("close", onClose);
          signal?.removeEventListener("abort", onAbort);
        };
        session.child.stdout.on("data", onStdout);
        session.child.stderr.on("data", onStderr);
        session.child.once("close", onClose);
        signal?.addEventListener("abort", onAbort, { once: true });
        session.child.stdin.write(`${command}\n`);
      }),
  );
  session.queue = run.catch(() => undefined);
  return run;
}

/**
 * Run one r2 command against the cached session for this sample. Boots the
 * session (docker `run -i` + `-q0 -A`) on first use — the analysis cost is
 * paid once per sample, not once per call.
 */
export async function runRadareSessionCommand(
  workspace: Workspace,
  userPath: string,
  command: string,
  options: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<CommandResult & { backend: "local" | "docker" }> {
  const absolutePath = await workspace.resolveFile(userPath);
  const binary = await inspectBinary(workspace, userPath);
  const localRadare = await resolveLocalRadare();
  const image = resolveDockerImage(process.env.MINUSONE_R2_IMAGE, DEFAULT_IMAGES.radare2);
  if (localRadare === null && image === null) {
    throw new Error("radare2 is disabled: MINUSONE_R2_IMAGE is explicitly empty and no local r2 was found. Unset the variable to restore the pinned default image.");
  }
  const backend: "local" | "docker" = localRadare !== null ? "local" : "docker";

  let session = r2Sessions.get(binary.sampleId);
  if (session === undefined || session.dead) {
    // A wedged leftover container with a colliding name would break the new
    // spawn; kill by the old name first when we still know it.
    session = await bootR2Session(
      workspace,
      absolutePath,
      binary.sampleId,
      backend,
      localRadare,
      image ?? "",
    );
    r2Sessions.set(binary.sampleId, session);
    ensureSweepTimer();
  }
  const outcome = await sessionExec(session, command, options.timeoutMs ?? R2_SESSION_COMMAND_TIMEOUT_MS, options.signal);
  if (outcome.timedOut) {
    // A timed-out command may leave the session mid-output; drop it so the
    // next caller boots a clean one instead of reading a stale terminator.
    r2Sessions.delete(binary.sampleId);
    await closeR2Session(session).catch(() => undefined);
  }
  return {
    backend,
    command: "<cached-r2-session>",
    args: [command],
    exitCode: outcome.timedOut ? 124 : 0,
    timedOut: outcome.timedOut,
    stdout: stripAnsiEscapes(outcome.stdout),
    stderr: stripAnsiEscapes(outcome.stderr).slice(0, 64 * 1024),
    outputTruncated: false,
    aborted: false,
  };
}

export async function runRadareFunctionList(
  workspace: Workspace,
  userPath: string,
  options: RadareFunctionListOptions = {},
): Promise<RadareFunctionListResult> {
  const timeoutMs = (Math.min(RADARE_MAX_TIMEOUT_SECONDS, options.timeoutSeconds ?? RADARE_DEFAULT_TIMEOUT_SECONDS) + 60) * 1000;
  const command = await runRadareSessionCommand(workspace, userPath, "aflj", { timeoutMs, ...(options.signal === undefined ? {} : { signal: options.signal }) });
  if (command.exitCode !== 0 || command.timedOut) return { backend: command.backend, command };
  try {
    // Session output can carry leading noise before the JSON array; slice to
    // the outermost brackets so parsing survives it.
    const text = stripAnsiEscapes(command.stdout);
    const start = text.indexOf("[");
    const end = text.lastIndexOf("]");
    const parsed = JSON.parse(start >= 0 && end > start ? text.slice(start, end + 1) : text) as unknown;
    if (!Array.isArray(parsed)) return { backend: command.backend, command };
    return { backend: command.backend, command, functions: parsed as RadareFunction[] };
  } catch {
    return { backend: command.backend, command };
  }
}

export async function runRadareDump(
  workspace: Workspace,
  userPath: string,
  options: RadareDumpOptions,
): Promise<{ backend: "local" | "docker"; command: CommandResult }> {
  if (options.address === undefined && options.symbol === undefined) {
    throw new Error("radare dump requires address or symbol");
  }
  const symbol = options.symbol;
  const target = options.address ?? (symbol === undefined ? "" : symbol.includes(".") ? symbol : `sym.${symbol}`);
  const commandText =
    options.mode === "hex" ? `px ${options.count} @ ${target}` : `pd ${options.count} @ ${target}`;
  const command = await runRadareSessionCommand(workspace, userPath, commandText, {
    timeoutMs: RADARE_MAX_TIMEOUT_SECONDS * 1000,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return { backend: command.backend, command };
}

/** Compact model-facing summary of an aflj listing, offsets in hex. */
export function summarizeRadareFunctions(
  functions: RadareFunction[] | undefined,
  filter: string | undefined,
  maxFunctions = 100,
): { total: number; truncated: boolean; functions: unknown[] } {
  const all = functions ?? [];
  const needle = filter?.toLowerCase();
  const matched = needle === undefined || needle === ""
    ? all
    : all.filter(
        (fn) =>
          (fn.name ?? "").toLowerCase().includes(needle) ||
          (fn.offset !== undefined ? `0x${fn.offset.toString(16)}` : "").includes(needle),
      );
  return {
    total: matched.length,
    truncated: matched.length > maxFunctions,
    functions: matched.slice(0, maxFunctions).map((fn) => ({
      name: fn.name ?? "",
      offset: typeof fn.offset === "number" ? `0x${fn.offset.toString(16)}` : null,
      size: typeof fn.realsz === "number" ? fn.realsz : typeof fn.size === "number" ? fn.size : null,
      blocks: typeof fn.nbbs === "number" ? fn.nbbs : null,
      signature: typeof fn.signature === "string" ? fn.signature : null,
    })),
  };
}

// ---------------------------------------------------------------------------
// Cross-references (A1): "who references this address?" through the cached
// r2 session. axtj gives code+data refs collected by the boot analysis; each
// ref is enriched with the containing function from the same session.
// ---------------------------------------------------------------------------

export interface RadareXrefOptions {
  va?: string;
  rva?: string;
  offset?: number;
  signal?: AbortSignal;
}

export interface RadareXref {
  from: string;
  type: string;
  opcode: string | null;
  functionName: string | null;
  functionOffset: string | null;
}

export interface RadareXrefResult {
  backend: "local" | "docker";
  target: string;
  targetKind: "va" | "rva" | "offset";
  xrefs: RadareXref[];
  containingFunction: { name: string; offset: string } | null;
}

interface RawAxtEntry {
  from?: number;
  type?: string;
  opcode?: string;
  fcn_name?: string;
  fcn_addr?: number;
}

function containingFunction(functions: RadareFunction[], address: number): RadareFunction | null {
  let best: RadareFunction | null = null;
  for (const fn of functions) {
    const start = typeof fn.offset === "number" ? fn.offset : null;
    const size = typeof fn.realsz === "number" ? fn.realsz : typeof fn.size === "number" ? fn.size : null;
    if (start === null || size === null) continue;
    if (address >= start && address < start + size) {
      if (best === null || start > (best.offset ?? 0)) best = fn;
    }
  }
  return best;
}

export async function runRadareXrefs(
  workspace: Workspace,
  userPath: string,
  options: RadareXrefOptions,
): Promise<RadareXrefResult> {
  const binary = await inspectBinary(workspace, userPath);
  const absolutePath = await workspace.resolveFile(userPath);

  // Resolve the target to a VA (PE: also accept rva/offset through the
  // section table — the same arithmetic memory.read does).
  let va: number | null = null;
  let targetKind: "va" | "rva" | "offset" = "va";
  if (options.va !== undefined) {
    va = Number(options.va);
    targetKind = "va";
  } else if (options.rva !== undefined) {
    va = Number(options.rva);
    targetKind = "rva";
  } else if (options.offset !== undefined) {
    va = options.offset;
    targetKind = "offset";
  }
  if (va === null || !Number.isFinite(va) || va <= 0) {
    throw new Error("xref query needs one of va, rva or offset");
  }
  if (binary.format.kind === "pe") {
    const buffer = await readFile(absolutePath);
    const tables = await parsePeTablesFromBuffer(buffer);
    if (tables !== null) {
      if (targetKind === "rva") va = tables.imageBase + va;
      else if (targetKind === "offset") {
        const rva = fileOffsetToRva(tables.sections, va);
        if (rva === null) throw new Error(`file offset 0x${va.toString(16)} is outside any section`);
        va = tables.imageBase + rva;
      }
    }
  } else if (targetKind !== "va") {
    throw new Error(`rva/offset targeting requires a PE file (detected format: ${binary.format.kind}); pass va instead`);
  }
  const target = `0x${(va as number).toString(16)}`;

  const refsCommand = await runRadareSessionCommand(workspace, userPath, `axtj @ ${target}`, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (refsCommand.exitCode !== 0 || refsCommand.timedOut) {
    throw new Error(`radare2 xref query failed${refsCommand.timedOut ? " (timed out)" : ""}`);
  }
  let raw: RawAxtEntry[] = [];
  try {
    const text = stripAnsiEscapes(refsCommand.stdout);
    const start = text.indexOf("[");
    const end = text.lastIndexOf("]");
    const parsed = JSON.parse(start >= 0 && end > start ? text.slice(start, end + 1) : text) as unknown;
    if (Array.isArray(parsed)) raw = parsed as RawAxtEntry[];
  } catch {
    raw = [];
  }

  // axtj already carries fcn_name/fcn_addr per ref; the aflj pass enriches
  // refs r2 could not attribute and resolves the target's own function.
  const list = await runRadareFunctionList(workspace, userPath, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const functions = list.functions ?? [];

  const xrefs: RadareXref[] = raw
    .filter((entry) => typeof entry.from === "number")
    .map((entry) => {
      const fn = containingFunction(functions, entry.from as number);
      return {
        from: `0x${(entry.from as number).toString(16)}`,
        type: typeof entry.type === "string" ? entry.type : "UNKNOWN",
        opcode: typeof entry.opcode === "string" ? entry.opcode : null,
        functionName: typeof entry.fcn_name === "string" && entry.fcn_name !== "" ? entry.fcn_name : (fn?.name ?? null),
        functionOffset:
          typeof entry.fcn_addr === "number"
            ? `0x${entry.fcn_addr.toString(16)}`
            : fn?.offset !== undefined
              ? `0x${fn.offset.toString(16)}`
              : null,
      };
    });

  const targetFn = containingFunction(functions, va as number);
  return {
    backend: refsCommand.backend,
    target,
    targetKind,
    xrefs,
    containingFunction:
      targetFn === null
        ? null
        : { name: targetFn.name ?? "", offset: targetFn.offset !== undefined ? `0x${targetFn.offset.toString(16)}` : "" },
  };
}
