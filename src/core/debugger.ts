/**
 * Scriptable debugger bridge. The gdb driver runs a sample under gdb on the
 * armed LOCAL dynamic plane (prompt-loop: create spawns gdb with --args and
 * stops at the entry instruction, send runs console commands framed by a
 * custom prompt, teardown kills gdb and the inferior and returns the
 * transcript). The cdb driver runs postmortem batches against a frozen
 * minidump (no execution, ungated). The two share the DebugDriver surface.
 *
 * No command denylist on gdb: the workspace owner arms the dynamic plane
 * explicitly (minusone arm), and gdb's full console — including python and
 * shell — is available to the agent. cdb keeps a small denylist of commands
 * that escape the dump-inspection sandbox (.shell / $< / .foreach).
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { stat, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { probeCommand } from "./command.js";
import { GDB_ANTI_ANTI_DEBUG_PY, antiAntiDebugSummary } from "./antidebug.js";
import { CdbDriver } from "./cdb.js";
import type { DebugCommandResult, DebugDriver, DebugTranscriptEntry, DebuggerKind } from "./debug-driver.js";
import { killProcessTree } from "./dynamic.js";
import type { Workspace } from "./workspace.js";
import { X64dbgDriver } from "./x64dbg.js";

export const DEBUG_PROMPT_MARKER = "(minusone-ready)";
export const DEBUG_DEFAULT_COMMAND_SECONDS = 30;
export const DEBUG_MAX_COMMAND_SECONDS = 300;
const DEBUG_STARTUP_SECONDS = 60;
const DEBUG_OUTPUT_CAP_CHARS = 256 * 1024;
const DEBUG_TRANSCRIPT_ENTRY_CHARS = 64 * 1024;
const DEBUG_TRANSCRIPT_MAX_ENTRIES = 1000;
const DEBUG_CLOSE_GRACE_MS = 3000;

export interface DebugSessionOptions {
  debugger?: DebuggerKind;
  args?: string[];
  stopAtEntry?: boolean;
  /** Anti-anti-debug hardening (gdb only): PEB/heap patching at every stop. */
  harden?: boolean;
}

export interface DebugSessionCreated {
  sessionId: string;
  debugger: DebuggerKind;
  backendPath: string;
  runDir: string;
  stopAtEntry: boolean;
  startup: DebugCommandResult;
  harden: { applied: boolean; what: string[]; limits: string[] };
}

export interface DebugSessionClosed {
  sessionId: string;
  target: string;
  runDir: string;
  commandsExecuted: number;
  transcript: DebugTranscriptEntry[];
}

interface GdbSessionState {
  target: string;
  runDir: string;
  gdbPath: string;
  child: ChildProcessWithoutNullStreams;
  buffer: string;
  exited: boolean;
  exitNote: string | null;
  queue: Promise<unknown>;
  transcript: DebugTranscriptEntry[];
  /** PID of the current inferior, parsed from gdb's "[New Thread PID.TID]" lines. */
  inferiorPid: number | null;
  /** Runs started (run/continue commands whose output mentioned a new inferior). */
  runCount: number;
}

interface SessionEntry {
  id: string;
  driver: DebugDriver;
}

const sessions = new Map<string, SessionEntry>();

export function activeDebugSessionIds(): string[] {
  return [...sessions.keys()];
}

export function activeDebugSessionKind(sessionId: string): DebuggerKind | null {
  return sessions.get(sessionId)?.driver.kind ?? null;
}

export async function resolveGdb(): Promise<string | null> {
  const explicit = process.env.MINUSONE_GDB_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("gdb", ["--version"]);
  if (probe) return "gdb";
  if (process.platform === "win32") {
    const msys2 = "C:\\msys64\\ucrt64\\bin\\gdb.exe";
    if (await stat(msys2).then(() => true, () => false)) return msys2;
  }
  return null;
}

function cap(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n[output truncated: ${text.length} chars total]`;
}

function cleanOutput(raw: string): string {
  return cap(raw.replace(/\r/g, "").trim(), DEBUG_OUTPUT_CAP_CHARS);
}

function waitForPrompt(state: GdbSessionState, timeoutMs: number): Promise<{ output: string; timedOut: boolean; exited: boolean }> {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const settle = (result: { output: string; timedOut: boolean; exited: boolean }) => {
      clearInterval(timer);
      resolve(result);
    };
    const timer = setInterval(() => {
      const markerIndex = state.buffer.indexOf(DEBUG_PROMPT_MARKER);
      if (markerIndex >= 0) {
        const output = state.buffer.slice(0, markerIndex);
        state.buffer = state.buffer.slice(markerIndex + DEBUG_PROMPT_MARKER.length);
        settle({ output, timedOut: false, exited: false });
        return;
      }
      if (state.exited) {
        const output = state.buffer;
        state.buffer = "";
        settle({ output, timedOut: false, exited: true });
        return;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        settle({ output: state.buffer, timedOut: true, exited: false });
      }
    }, 50);
  });
}

async function sendRaw(state: GdbSessionState, command: string, timeoutSeconds: number): Promise<DebugCommandResult> {
  if (state.exited) {
    return { ok: false, output: "", seconds: 0, error: state.exitNote ?? "the debugger has exited" };
  }
  // Stale-output hygiene (the field regression: after a timed-out command
  // gdb keeps printing, its prompt lands in the buffer, and the NEXT
  // command would answer with the dead command's output). Before writing
  // a new command, drop anything that accumulated without being asked
  // for — the only legitimate content between two prompts is the echo of
  // the previous exchange.
  if (state.buffer.includes(DEBUG_PROMPT_MARKER)) {
    const markerIndex = state.buffer.indexOf(DEBUG_PROMPT_MARKER);
    state.buffer = state.buffer.slice(markerIndex + DEBUG_PROMPT_MARKER.length);
  }
  const startedAt = Date.now();
  state.child.stdin.write(`${command}\n`);
  const wait = await waitForPrompt(state, timeoutSeconds * 1000);
  const seconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));
  if (wait.exited) {
    return {
      ok: false,
      output: cleanOutput(wait.output),
      seconds,
      error: state.exitNote ?? "the debugger exited while running the command",
    };
  }
  if (wait.timedOut) {
    return {
      ok: false,
      output: cleanOutput(wait.output),
      seconds,
      timedOut: true,
      error: `command did not return within ${timeoutSeconds}s (the inferior may still be running); use debug_kill to kill the inferior and keep the session`,
    };
  }
  return { ok: true, output: cleanOutput(wait.output), seconds };
}

/** gdb backend: prompt-loop driver over a live inferior. */
class GdbDriver implements DebugDriver {
  readonly kind = "gdb" as const;

  private constructor(
    private readonly state: GdbSessionState,
    public readonly backendPath: string,
    public readonly runDir: string,
    public readonly target: string,
  ) {}

  static async launch(
    workspace: Workspace,
    userPath: string,
    options: { args?: string[]; stopAtEntry?: boolean; harden?: boolean },
  ): Promise<{ driver: GdbDriver; startup: DebugCommandResult; stopAtEntry: boolean; runDir: string; gdbPath: string; harden: { applied: boolean; what: string[]; limits: string[] } }> {
    const absolutePath = await workspace.resolveFile(userPath);
    const relativeTarget = workspace.relative(absolutePath);
    const gdbPath = await resolveGdb();
    if (gdbPath === null) {
      throw new Error("no gdb backend found: set MINUSONE_GDB_BIN or install gdb (on MSYS2: pacman -S mingw-w64-ucrt-x86_64-gdb)");
    }

    const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
    await mkdir(runDir, { recursive: true });

    const child = spawn(
      gdbPath,
      [
        "-q", "--nx",
        "-iex", "set pagination off",
        "-iex", "set confirm off",
        "-iex", `set prompt ${DEBUG_PROMPT_MARKER}`,
        "--args", absolutePath, ...(options.args ?? []),
      ],
      { cwd: runDir, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
    );

    const state: GdbSessionState = {
      target: relativeTarget,
      runDir,
      gdbPath,
      child,
      buffer: "",
      exited: false,
      exitNote: null,
      queue: Promise.resolve(),
      transcript: [],
      inferiorPid: null,
      runCount: 0,
    };
    const append = (chunk: Buffer): void => {
      const text = chunk.toString("utf8");
      if (state.buffer.length < DEBUG_OUTPUT_CAP_CHARS * 2) state.buffer += text;
      // Track the inferior's PID from "[New Thread 1122.0x333]" lines —
      // the thread id prefix is the Windows PID. killInferior needs it to
      // stop a running inferior whose console is unreachable (gdb does not
      // read stdin while the target runs, and Ctrl-C bytes are ignored).
      const pidMatch = /\[New Thread (\d+)\./.exec(text);
      if (pidMatch !== null) {
        const pid = Number.parseInt(pidMatch[1] ?? "0", 10);
        if (Number.isInteger(pid) && pid > 0) state.inferiorPid = pid;
      }
      if (/\[Inferior 1 \(process \d+\) exited/.test(text)) state.inferiorPid = null;
    };
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    child.stdin.on("error", () => {});
    child.once("error", (error) => {
      state.exited = true;
      state.exitNote = `gdb failed to start: ${error.message}`;
    });
    child.once("close", (exitCode) => {
      state.exited = true;
      if (state.exitNote === null) state.exitNote = `gdb exited with code ${exitCode}`;
    });

    const greeting = await waitForPrompt(state, 20_000);
    if (greeting.exited) {
      throw new Error(`gdb exited before the session started: ${cleanOutput(greeting.output).slice(0, 512)}`);
    }

    const stopAtEntry = options.stopAtEntry ?? true;
    let startup: DebugCommandResult = { ok: true, output: cleanOutput(greeting.output), seconds: 0 };
    let harden = antiAntiDebugSummary(false);
    if (stopAtEntry) {
      startup = await sendRaw(state, "starti", DEBUG_STARTUP_SECONDS);
      if (!startup.ok && startup.error !== undefined) {
        startup = { ...startup, error: `starti did not stop cleanly: ${startup.error}` };
      }
    }
    if (options.harden === true) {
      // Load the anti-anti-debug layer AFTER the first stop: the PEB exists
      // once the loader has mapped the image. It re-arms itself at every
      // stop via gdb stop-events.
      const scriptPath = path.join(runDir, "antiantidebug.py");
      await writeFile(scriptPath, GDB_ANTI_ANTI_DEBUG_PY, "utf8");
      const hardened = await sendRaw(state, `source ${scriptPath.replace(/\\/g, "/")}`, 30);
      harden = antiAntiDebugSummary(hardened.ok);
      const lines = hardened.output.split(/\r?\n/).filter((line) => /minusone-antiantidebug/.test(line));
      if (lines.length > 0) {
        startup = { ...startup, output: `${startup.output}\n${lines.join("\n")}` };
      } else if (!hardened.ok) {
        startup = { ...startup, output: `${startup.output}\n[harden failed: ${hardened.error ?? "unknown"}]` };
      }
    }
    state.transcript.push({ command: "<create>", output: startup.output.slice(0, DEBUG_TRANSCRIPT_ENTRY_CHARS), seconds: startup.seconds });

    return { driver: new GdbDriver(state, gdbPath, runDir, relativeTarget), startup, stopAtEntry, runDir, gdbPath, harden };
  }

  send(command: string, timeoutSeconds: number): Promise<DebugCommandResult> {
    const state = this.state;
    const boundedSeconds = Math.min(Math.max(timeoutSeconds, 5), DEBUG_MAX_COMMAND_SECONDS);
    const task = state.queue.then(async () => {
      // Multi-line batches: when several lines hit gdb's stdin at once the
      // prompt reader returns after the FIRST command and the rest desync
      // (the field workaround was hand-writing a script and `source`-ing it).
      // Route multi-line input through a sourced batch file so every line
      // executes in order — python/define blocks included.
      let effective = command;
      let note = "";
      if (command.includes("\n")) {
        const scriptPath = path.join(state.runDir, `batch-${randomUUID().slice(0, 8)}.gdb`);
        await writeFile(scriptPath, command, "utf8");
        effective = `source ${scriptPath.replace(/\\/g, "/")}`;
        note = `[multi-line batch (${command.split("\n").length} lines) executed via source]\n`;
      }
      const result = await sendRaw(state, effective, boundedSeconds);
      if (note !== "") result.output = note + result.output;
      return result;
    }).then((result) => {
      if (state.transcript.length >= DEBUG_TRANSCRIPT_MAX_ENTRIES) state.transcript.shift();
      state.transcript.push({ command, output: result.output.slice(0, DEBUG_TRANSCRIPT_ENTRY_CHARS), seconds: result.seconds });
      return result;
    });
    state.queue = task.catch(() => {});
    return task;
  }

  /**
   * Kill the running inferior but keep gdb (and the session) alive: the
   * combat loss was a wedged `continue` forcing a full session close and
   * the loss of every breakpoint set so far. While the inferior runs, gdb
   * does not read its stdin (Ctrl-C bytes are ignored on Windows pipes),
   * so the reliable route is killing the inferior PROCESS TREE directly —
   * gdb notices the death and returns to its prompt on its own. `kill` is
   * still sent afterwards as a belt-and-braces cleanup.
   */
  async killInferior(): Promise<DebugCommandResult> {
    const state = this.state;
    if (state.exited) {
      return { ok: false, output: "", seconds: 0, error: state.exitNote ?? "the debugger has exited" };
    }
    // Drain any in-flight command first so we never interleave.
    await state.queue.catch(() => {});
    const startedAt = Date.now();
    const notes: string[] = [];
    if (state.inferiorPid !== null) {
      const pid = state.inferiorPid;
      state.inferiorPid = null;
      try {
        await killProcessTree(pid);
        notes.push(`[inferior process tree (pid ${pid}) killed]`);
      } catch (error) {
        notes.push(`[killing pid ${pid} failed: ${error instanceof Error ? error.message : String(error)}]`);
      }
      // gdb observes the child death and prints its prompt; wait for it so
      // the next queued command does not collide with the death report.
      await new Promise((resolve) => setTimeout(resolve, 600));
    } else {
      notes.push("[no inferior pid tracked — the inferior already exited or never started]");
    }
    const result = await this.send("kill", 30);
    return {
      ...result,
      seconds: Number(((Date.now() - startedAt) / 1000).toFixed(1)),
      output: result.ok
        ? `${result.output}\n${notes.join(" ")}\n[inferior killed; the gdb session stays alive — run restarts it, breakpoints persist]`.trim()
        : `${result.output}\n${notes.join(" ")}`.trim(),
    };
  }

  async teardown(): Promise<{ commandsExecuted: number; transcript: DebugTranscriptEntry[] }> {
    const state = this.state;
    if (!state.exited) {
      await state.queue.catch(() => {});
      // Best-effort graceful teardown; the kill tree below is the real guarantee.
      await sendRaw(state, "kill", 10).catch(() => {});
      await sendRaw(state, "quit", 10).catch(() => {});
      await new Promise<void>((resolve) => {
        if (state.exited) return resolve();
        const timer = setTimeout(() => resolve(), DEBUG_CLOSE_GRACE_MS);
        state.child.once("close", () => {
          clearTimeout(timer);
          resolve();
        });
      });
      if (state.child.pid !== undefined && !state.exited) {
        await killProcessTree(state.child.pid);
      }
    }
    return {
      commandsExecuted: Math.max(state.transcript.length - 1, 0),
      transcript: state.transcript,
    };
  }
}

/**
 * debug.break helper: build a gdb breakpoint command whose condition
 * dereferences a pointer-to-string. Raw gdb conditional syntax is a trap:
 *   break *0xaddr if $_streq(*(char**)rdi, "text")
 * fails when gdb cannot infer the pointer width, and $_streq is unavailable
 * on some builds. This builds the robust form explicitly:
 *   break *ADDR if ((char*)REG) && strcmp((char*)REG, "text") == 0
 * with substring semantics when requested (strstr != NULL). The call/skip
 * forms cover "break when the program is about to do something with X".
 */
export function buildStringBreakpoint(options: {
  address?: string;
  symbol?: string;
  register: string;
  text: string;
  mode?: "equals" | "contains";
}): { command: string; explanation: string } {
  const where = options.address !== undefined
    ? `*${options.address.startsWith("0x") || /^\d/.test(options.address) ? options.address : `0x${options.address}`}`
    : (options.symbol as string);
  const pointer = `((char*)$${options.register.replace(/^\$/, "")})`;
  const needle = JSON.stringify(options.text);
  // gdb refuses calls to functions with unknown return types in conditions
  // ("strcmp has unknown return type; cast the call") and silently degrades
  // the breakpoint to unconditional — the exact trap from the field report.
  // The explicit (int) cast fixes that. Null check first so a bad pointer
  // cannot abort the condition.
  const compare = options.mode === "contains"
    ? `(int)strstr(${pointer}, ${needle}) != 0`
    : `(int)strcmp(${pointer}, ${needle}) == 0`;
  const command = `break ${where} if ${pointer} != 0 && ${compare}`;
  return {
    command,
    explanation: `breakpoint at ${where} that hits only when the C string at the pointer in $${options.register.replace(/^\$/, "")} ${options.mode === "contains" ? "contains" : "equals"} ${JSON.stringify(options.text)}`,
  };
}

export async function createDebugSession(
  workspace: Workspace,
  userPath: string,
  options: DebugSessionOptions = {},
): Promise<DebugSessionCreated> {
  const kind = options.debugger ?? "gdb";
  const id = randomUUID().slice(0, 8);

  if (kind === "cdb") {
    const driver = await CdbDriver.create(workspace, userPath);
    sessions.set(id, { id, driver });
    return {
      sessionId: id,
      debugger: "cdb",
      backendPath: driver.backendPath,
      runDir: workspace.relative(driver.runDir),
      stopAtEntry: false,
      startup: { ok: true, output: "cdb postmortem session ready: dump is frozen, the sample is never executed", seconds: 0 },
      harden: antiAntiDebugSummary(false),
    };
  }

  if (kind === "x64dbg") {
    const driver = await X64dbgDriver.create(workspace, userPath, {
      ...(options.args === undefined ? {} : { args: options.args }),
    });
    sessions.set(id, { id, driver });
    return {
      sessionId: id,
      debugger: "x64dbg",
      backendPath: driver.backendPath,
      runDir: workspace.relative(driver.runDir),
      stopAtEntry: true,
      startup: { ok: true, output: "x64dbg headless session ready: send a complete script via debug_command (each command reloads the sample)", seconds: 0 },
      harden: antiAntiDebugSummary(false),
    };
  }

  if (kind !== "gdb") {
    throw new Error(`unknown debugger backend: ${kind} (supported: gdb, cdb, x64dbg)`);
  }

  const { driver, startup, stopAtEntry, runDir, gdbPath, harden } = await GdbDriver.launch(workspace, userPath, {
    ...(options.args === undefined ? {} : { args: options.args }),
    ...(options.stopAtEntry === undefined ? {} : { stopAtEntry: options.stopAtEntry }),
    ...(options.harden === undefined ? {} : { harden: options.harden }),
  });
  sessions.set(id, { id, driver });
  return {
    sessionId: id,
    debugger: "gdb",
    backendPath: gdbPath,
    runDir: workspace.relative(runDir),
    stopAtEntry,
    startup,
    harden,
  };
}

export function sendDebugCommand(sessionId: string, command: string, timeoutSeconds: number = DEBUG_DEFAULT_COMMAND_SECONDS): Promise<DebugCommandResult> {
  const entry = sessions.get(sessionId);
  if (entry === undefined) {
    return Promise.resolve({
      ok: false,
      output: "",
      seconds: 0,
      error: `unknown debug session ${JSON.stringify(sessionId)}; create one with debug_session_create (active: ${activeDebugSessionIds().join(", ") || "none"})`,
    });
  }
  return entry.driver.send(command, timeoutSeconds);
}

export async function killDebugInferior(sessionId: string): Promise<DebugCommandResult> {
  const entry = sessions.get(sessionId);
  if (entry === undefined) {
    return {
      ok: false,
      output: "",
      seconds: 0,
      error: `unknown debug session ${JSON.stringify(sessionId)}; active sessions: ${activeDebugSessionIds().join(", ") || "none"}`,
    };
  }
  if (entry.driver.killInferior === undefined) {
    return {
      ok: false,
      output: "",
      seconds: 0,
      error: `the ${entry.driver.kind} backend has no live inferior to kill (cdb postmortem inspects a frozen dump; x64dbg batches reload the sample per command)`,
    };
  }
  return await entry.driver.killInferior();
}

/**
 * Watchpoint honesty: gdb accepts `watch expr` and prints "Hardware
 * watchpoint N: expr" — or silently degrades when no hardware debug
 * registers are available (the field failure: half an hour on a watchpoint
 * that never fired). Parse the acknowledgment and report the real state.
 */
export function parseWatchpointResult(output: string): { watchpointNumber: number | null; hardware: boolean; degraded: boolean; note: string } {
  const hardwareMatch = /^Hardware watchpoint (\d+):/m.exec(output);
  if (hardwareMatch !== null) {
    return {
      watchpointNumber: Number.parseInt(hardwareMatch[1] ?? "0", 10),
      hardware: true,
      degraded: false,
      note: "hardware watchpoint confirmed by gdb",
    };
  }
  const softwareMatch = /^(?:Watchpoint|Software watchpoint) (\d+):/m.exec(output);
  if (softwareMatch !== null) {
    return {
      watchpointNumber: Number.parseInt(softwareMatch[1] ?? "0", 10),
      hardware: false,
      degraded: false,
      note: "software watchpoint (single-steps the target — slow but reliable)",
    };
  }
  if (/No symbol|not found|cannot|Cannot|Invalid|Syntax error|unrecognized/i.test(output)) {
    return {
      watchpointNumber: null,
      hardware: false,
      degraded: true,
      note: "gdb rejected the watchpoint expression — no watchpoint was set; do NOT build on it",
    };
  }
  return {
    watchpointNumber: null,
    hardware: false,
    degraded: true,
    note: "gdb did not acknowledge a watchpoint (no 'Hardware/Software watchpoint N:' line) — assume NO watchpoint is active; verify with info breakpoints",
  };
}

export async function closeDebugSession(sessionId: string): Promise<DebugSessionClosed> {
  const entry = sessions.get(sessionId);
  if (entry === undefined) {
    throw new Error(`unknown debug session ${JSON.stringify(sessionId)}; active sessions: ${activeDebugSessionIds().join(", ") || "none"}`);
  }
  sessions.delete(sessionId);
  const closed = await entry.driver.teardown();
  return {
    sessionId,
    target: entry.driver.target,
    runDir: entry.driver.runDir,
    commandsExecuted: closed.commandsExecuted,
    transcript: closed.transcript,
  };
}
