/**
 * The time-travel plane: TTD (Time Travel Debugging, Microsoft) records a
 * FULL instruction trace of a sample's execution; the trace replays
 * FORWARD and BACKWARD under WinDbg, so the analyst can walk from
 * "INVALID" back to the birth of the value — the question static analysis
 * cannot answer.
 *
 * Record: TTD.exe (extracted once from the WinDbg MSIX into tools/ttd by
 * `minusone setup`, or standalone aka.ms/ttd/download). Replay: WinDbgX
 * headless (-z trace.run -c "commands; qq") with a log file — cdb from
 * the Windows SDK cannot open .run files (the TTD engine ships with
 * WinDbg). Recording requires ELEVATION; the operation reports the
 * requirement honestly when it fails.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runBoundedCommand } from "./command.js";
import type { Workspace } from "./workspace.js";

export const TTD_RECORD_TIMEOUT_SECONDS = 300;
export const TTD_REPLAY_TIMEOUT_SECONDS = 300;
const TTD_MAX_COMMANDS_CHARS = 4000;
const TTD_OUTPUT_PREVIEW_CHARS = 32 * 1024;

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(moduleDirectory, "../..");

export interface TtdRecordOptions {
  args?: string[];
  /** Record child processes too (each into its own trace). Launch mode only. */
  children?: boolean;
  /** Ring buffer cap in MB (bounds the trace size). */
  maxFileMb?: number;
  timeoutSeconds?: number;
  /**
   * ATTACH MODE: record an already-running process (TTD -attach <pid>) —
   * the driven-instance pattern: launch the sample via console.launch, drive
   * the scenario with console.send while recording, kill the process to
   * finalize the trace. args/children are launch-only and ignored here.
   */
  pid?: number;
  /** Job-cancellation signal (kills the TTD recorder on abort; the trace is finalized by the kill). */
  signal?: AbortSignal;
}

export interface TtdRecordResult {
  status: "ok" | "error";
  tracePath: string | null;
  traceBytes: number;
  outLogPath: string | null;
  exitSummary: string | null;
  error?: string;
}

export interface TtdReplayResult {
  status: "ok" | "error";
  logPath: string | null;
  logBytes: number;
  /** The -z target that was replayed. */
  tracePath: string;
  /** Command OUTPUT captured via .logopen (A5) — the actual replay answers. */
  output?: string;
  /** Workspace path of the full untruncated .logopen capture. */
  outputLogPath?: string | null;
  error?: string;
}

/** Resolve the extracted TTD recorder (tools/ttd/TTD.exe). */
export function resolveTtdExe(): string | null {
  const explicit = process.env.MINUSONE_TTD_EXE;
  if (explicit !== undefined && explicit !== "" && existsSync(explicit)) return explicit;
  const bundled = path.join(packageRoot, "tools", "ttd", "TTD.exe");
  return existsSync(bundled) ? bundled : null;
}

/**
 * Resolve WinDbgX for headless replay. The MSIX alias is a reparse point
 * that existsSync() reports as EACCES and node spawn() as ENOENT — probe
 * it through where.exe instead; callers launch it via PowerShell
 * Start-Process, which resolves the reparse point correctly.
 */
export function resolveWindbgX(): string | null {
  const explicit = process.env.MINUSONE_WINDBGX;
  if (explicit !== undefined && explicit !== "") return explicit;
  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData !== undefined && localAppData !== "") {
    const alias = path.join(localAppData, "Microsoft", "WindowsApps", "WinDbgX.exe");
    if (existsSync(alias)) return alias;
    const where = spawnSync("where.exe", ["WinDbgX"], { encoding: "utf8" });
    if (where.status === 0) {
      const found = String(where.stdout ?? "").split(/\r?\n/).find((line) => line.trim() !== "");
      if (found !== undefined) return found.trim();
    }
  }
  return null;
}

export async function isTtdAvailable(): Promise<boolean> {
  return resolveTtdExe() !== null && resolveWindbgX() !== null;
}

/**
 * Record a TTD trace of the sample. The trace lands in the run directory;
 * the .out sidecar records the recording session (the honest health
 * report per the TTD docs).
 */
export async function recordTtdTrace(
  workspace: Workspace,
  userPath: string,
  options: TtdRecordOptions = {},
): Promise<TtdRecordResult> {
  const ttdExe = resolveTtdExe();
  if (ttdExe === null) {
    return {
      status: "error",
      tracePath: null,
      traceBytes: 0,
      outLogPath: null,
      exitSummary: null,
      error: "TTD.exe not found: run 'minusone setup' (extracts TTD from the WinDbg MSIX into tools/ttd) or install the standalone recorder from https://aka.ms/ttd/download and set MINUSONE_TTD_EXE",
    };
  }
  const attachPid = options.pid;
  if (attachPid !== undefined && (!Number.isInteger(attachPid) || attachPid <= 0)) {
    throw new Error(`pid must be a positive integer (got ${attachPid}) — attach mode records an already-running process`);
  }
  const absolutePath = await workspace.resolveFile(userPath);
  const runDir = path.join(workspace.root, ".minusone", "run", `ttd-${Date.now().toString(36)}`);
  const tracesDir = path.join(runDir, "traces");
  await mkdir(tracesDir, { recursive: true });
  const tracePath = path.join(tracesDir, "trace.run");
  const timeoutSeconds = Math.min(TTD_RECORD_TIMEOUT_SECONDS, Math.max(10, options.timeoutSeconds ?? 120));

  const args = attachPid === undefined
    ? [
        "-accepteula", "-noUI",
        "-out", tracePath,
        ...(options.children === true ? ["-children"] : []),
        ...(options.maxFileMb === undefined ? [] : ["-maxFile", String(Math.min(Math.max(options.maxFileMb, 1), 32768))]),
        absolutePath,
        ...(options.args ?? []),
      ]
    : [
        "-accepteula", "-noUI",
        "-out", tracePath,
        ...(options.maxFileMb === undefined ? [] : ["-maxFile", String(Math.min(Math.max(options.maxFileMb, 1), 32768))]),
        "-attach", String(attachPid),
      ];
  const command = await runBoundedCommand(ttdExe, args, {
    cwd: runDir,
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 256 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const outLog = `${tracePath.slice(0, -".run".length)}.out`;
  const outLogRelative = existsSync(outLog) ? workspace.relative(outLog) : null;
  const summaryLine = command.stdout.split(/\r?\n/).find((line) => /Process exited|Full trace dumped|Recording has started/i.test(line)) ?? null;

  // Attach mode may name the trace after the process (<app>NN.run next to the
  // requested path) — fall back to the first .run in the traces directory.
  let producedTrace: string | null = existsSync(tracePath) ? tracePath : null;
  if (producedTrace === null) {
    try {
      const entries = await readdir(tracesDir);
      const candidate = entries.find((entry) => entry.endsWith(".run"));
      if (candidate !== undefined) producedTrace = path.join(tracesDir, candidate);
    } catch { /* no traces dir */ }
  }

  if (producedTrace !== null) {
    const { stat } = await import("node:fs/promises");
    const stats = await stat(producedTrace);
    return {
      status: "ok",
      tracePath: workspace.relative(producedTrace),
      traceBytes: stats.size,
      outLogPath: outLogRelative,
      exitSummary: summaryLine,
    };
  }
  return {
    status: "error",
    tracePath: null,
    traceBytes: 0,
    outLogPath: outLogRelative,
    exitSummary: summaryLine,
    error: `no trace produced (TTD exit ${command.exitCode}${command.timedOut ? ", timed out" : ""}); ${command.stderr.split(/\r?\n/).slice(-2).join(" | ") || "recording requires ELEVATION — run the host elevated"}${summaryLine === null ? "" : `; ${summaryLine}`}`,
  };
}

/**
 * Replay a recorded trace headless under WinDbgX: the commands run at
 * position B:0 by default (append "!tt <pos>" to jump). Use the TTD
 * commands: !tt <position> (jump), g- (step back), !positions (list
 * interesting events), bp + g (breakpoint forward), t/g backwards. The
 * full log comes back (bounded) — read it with artifact_read when large.
 */
export async function replayTtdTrace(
  workspace: Workspace,
  traceUserPath: string,
  commands: string,
  options: { timeoutSeconds?: number; signal?: AbortSignal } = {},
): Promise<TtdReplayResult> {
  const windbgX = resolveWindbgX();
  if (windbgX === null) {
    return {
      status: "error",
      logPath: null,
      logBytes: 0,
      tracePath: traceUserPath,
      error: "WinDbgX not found: install WinDbg (winget install Microsoft.WinDbg) for TTD replay — the SDK cdb cannot open .run traces",
    };
  }
  const traceAbsolute = await workspace.resolveFile(traceUserPath);
  const runDir = path.dirname(traceAbsolute);
  const logPath = path.join(runDir, "replay.log");
  const outPath = path.join(runDir, "replay-out.txt");
  await rm(logPath, { force: true }).catch(() => undefined);
  await rm(outPath, { force: true }).catch(() => undefined);
  const boundedCommands = commands.slice(0, TTD_MAX_COMMANDS_CHARS);
  const timeoutSeconds = Math.min(TTD_REPLAY_TIMEOUT_SECONDS, Math.max(30, options.timeoutSeconds ?? 120));

  // WinDbgX is a GUI MSIX app whose alias node cannot spawn directly
  // (reparse point -> ENOENT): launch through PowerShell Start-Process,
  // wait bounded, then read the log file.
  // `-logo` captures only the startup banner — command OUTPUT must be
  // captured explicitly with .logopen/.logclose around the batch (A5: the
  // replay used to return an empty ModLoad-only log, which blocked the
  // backward-walk workflow entirely).
  const psQuote = (value: string): string => `'${value.replace(/'/g, "''")}'`;
  const commandBatch = `.logopen "${outPath}"; ${boundedCommands}; .logclose; qq`;
  const pidPath = path.join(runDir, "replay-windbgx.pid");
  await rm(pidPath, { force: true }).catch(() => undefined);
  const script = [
    `$p = Start-Process -FilePath ${psQuote(windbgX)} -ArgumentList ${psQuote("-z")}, ${psQuote(traceAbsolute)}, ${psQuote("-c")}, ${psQuote(`"${commandBatch}"`)}, ${psQuote("-logo")}, ${psQuote(logPath)} -PassThru -WindowStyle Hidden`,
    `$p.Id | Out-File -FilePath ${psQuote(pidPath)} -Encoding ascii`,
    "$null = $p | Wait-Process -Timeout " + timeoutSeconds + " -ErrorAction SilentlyContinue",
    "if ($null -ne $p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }",
  ].join("; ");
  const launched = spawn("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
    cwd: runDir,
    windowsHide: true,
    stdio: "ignore",
  });
  // Job-cancellation path: kill WinDbgX (via the pid file) and the wrapper.
  const onAbort = () => {
    void (async () => {
      try {
        const raw = await readFile(pidPath, "utf8");
        const windbgPid = Number.parseInt(raw.trim(), 10);
        if (Number.isInteger(windbgPid) && windbgPid > 0) {
          spawn("powershell", ["-NoProfile", "-NonInteractive", "-Command", `Stop-Process -Id ${windbgPid} -Force -ErrorAction SilentlyContinue`], { windowsHide: true, stdio: "ignore" }).unref();
        }
      } catch { /* pid file not written yet — the wrapper timeout still bounds */ }
      try { launched.kill(); } catch { /* already gone */ }
    })();
  };
  if (options.signal !== undefined) {
    if (options.signal.aborted) onAbort();
    else options.signal.addEventListener("abort", onAbort, { once: true });
  }
  const exited = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), (timeoutSeconds + 30) * 1000);
    launched.once("close", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
  if (!exited) {
    try { launched.kill(); } catch { /* already gone */ }
    await sleep(2000);
  }
  let logBytes = 0;
  try {
    const content = await readFile(logPath, "utf8");
    logBytes = Buffer.byteLength(content);
  } catch {
    return {
      status: "error",
      logPath: null,
      logBytes: 0,
      tracePath: traceUserPath,
      error: "WinDbgX produced no log — the trace may be corrupt or the debugger failed to start",
    };
  }
  // The command-output capture: .logopen wrote every command's answer here.
  let output = "";
  try {
    output = await readFile(outPath, "utf8");
  } catch {
    // .logopen may fail on odd paths — the banner log still proves the run.
  }
  const outputTrimmed =
    output.length > TTD_OUTPUT_PREVIEW_CHARS
      ? `${output.slice(0, TTD_OUTPUT_PREVIEW_CHARS)}\n... [truncated ${output.length - TTD_OUTPUT_PREVIEW_CHARS} chars; full capture: ${workspace.relative(outPath)}]`
      : output;
  return {
    status: "ok",
    logPath: workspace.relative(logPath),
    logBytes,
    tracePath: traceUserPath,
    output: outputTrimmed,
    outputLogPath: output.length > 0 ? workspace.relative(outPath) : null,
  };
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/** List recorded traces under a run directory (helper for the operation). */
export async function listTtdTraces(workspace: Workspace, dirUserPath: string): Promise<string[]> {
  const absolute = await workspace.resolveFile(dirUserPath);
  const entries = await readdir(absolute, { withFileTypes: true });
  return entries.filter((entry) => entry.isFile() && entry.name.endsWith(".run")).map((entry) => workspace.relative(path.join(absolute, entry.name)));
}
