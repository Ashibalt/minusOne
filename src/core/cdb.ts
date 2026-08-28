/**
 * cdb (Windows Console Debugger) postmortem driver. A minidump is frozen
 * data — inspecting it never executes the captured process — so this plane
 * is NOT gated by the dynamic arm. Each debug_command appends to an
 * accumulated batch and re-runs cdb against the dump (`cdb -z <dump> -c
 * "<cmds>; q" -y <sympath>`); the dump's state is deterministic, so the
 * whole batch is reproducible every time. cdb exits after `q`, so there is
 * nothing to kill on teardown.
 *
 * A small denylist keeps commands that escape the dump-inspection sandbox
 * (.shell runs host code; $< loads a script file; .foreach can loop over
 * embedded commands) out of the batch. Everything else in the cdb console
 * — registers, stacks, modules, memory, !analyze, .ecxr, etc. — is open.
 */
import { randomUUID } from "node:crypto";
import { mkdir, open, stat } from "node:fs/promises";
import path from "node:path";
import { probeCommand, runBoundedCommand } from "./command.js";
import type { DebugCommandResult, DebugDriver, DebugTranscriptEntry, DebuggerKind } from "./debug-driver.js";
import type { Workspace } from "./workspace.js";

export const CDB_DEFAULT_COMMAND_SECONDS = 30;
export const CDB_MAX_COMMAND_SECONDS = 180;
const CDB_OUTPUT_CAP_CHARS = 256 * 1024;
const CDB_TRANSCRIPT_ENTRY_CHARS = 64 * 1024;
const CDB_TRANSCRIPT_MAX_ENTRIES = 1000;

const CDB_FORBIDDEN = new Set([".shell", "$<", ".foreach"]);

export function validateCdbCommand(command: string): string | null {
  const firstToken = command.trim().split(/\s+/)[0]?.toLowerCase() ?? "";
  if (CDB_FORBIDDEN.has(firstToken)) {
    return `command blocked: "${firstToken}" escapes the cdb sandbox (runs host code or loads a script file); use debug_command for dump inspection only`;
  }
  return null;
}

export async function resolveCdb(): Promise<string | null> {
  const explicit = process.env.MINUSONE_CDB_PATH;
  if (explicit) return explicit;
  if (process.platform === "win32") {
    const kits = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe";
    if (await stat(kits).then(() => true, () => false)) return kits;
  }
  const probe = await probeCommand("cdb", ["-version"]);
  return probe ? "cdb" : null;
}

function cap(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n[output truncated: ${text.length} chars total]`;
}

function cleanCdbOutput(raw: string): string {
  let text = raw.replace(/\r/g, "");
  // Drop the Debugger Extensions Gallery init blocks (verbose, repeated each run).
  text = text.replace(/\*+ Preparing the environment for Debugger Extensions Gallery[\s\S]*?completed, duration[^\n]*\n/g, "");
  text = text.replace(/\*+ Waiting for Debugger Extensions Gallery[\s\S]*?completed, duration[^\n]*\n/g, "");
  // Drop NatVis load/unload chatter from teardown.
  text = text
    .split("\n")
    .filter((line) => !/^\s*NatVis script (un)?loaded/.test(line))
    .join("\n");
  return cap(text.trim(), CDB_OUTPUT_CAP_CHARS);
}

export class CdbDriver implements DebugDriver {
  readonly kind: DebuggerKind = "cdb";
  private readonly commands: string[] = [];
  private readonly transcript: DebugTranscriptEntry[] = [];
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly dumpPath: string,
    private readonly relativeDump: string,
    public readonly backendPath: string,
    public readonly runDir: string,
    private readonly sympath: string,
  ) {}

  static async create(workspace: Workspace, dumpPath: string): Promise<CdbDriver> {
    const absolute = await workspace.resolveFile(dumpPath);
    await assertMinidumpMagic(absolute);
    const cdbPath = await resolveCdb();
    if (cdbPath === null) {
      throw new Error(
        "no cdb backend found: set MINUSONE_CDB_PATH or install Windows Debugging Tools (cdb.exe under Windows Kits\\10\\Debuggers\\x64)",
      );
    }
    const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
    await mkdir(runDir, { recursive: true });
    const symbolsDir = path.join(runDir, "symbols");
    await mkdir(symbolsDir, { recursive: true });
    const sympath = process.env.MINUSONE_SYMBOL_PATH ?? `srv*${symbolsDir.split(path.sep).join("/")}`;
    return new CdbDriver(absolute, workspace.relative(absolute), cdbPath, runDir, sympath);
  }

  get target(): string {
    return this.relativeDump;
  }

  send(command: string, timeoutSeconds: number): Promise<DebugCommandResult> {
    const blocked = validateCdbCommand(command);
    if (blocked !== null) {
      return Promise.resolve({ ok: false, output: "", seconds: 0, error: blocked });
    }
    const bounded = Math.min(Math.max(timeoutSeconds, 5), CDB_MAX_COMMAND_SECONDS);
    const task = this.queue
      .then(() => this.runBatch(command, bounded))
      .then((result) => {
        if (this.transcript.length >= CDB_TRANSCRIPT_MAX_ENTRIES) this.transcript.shift();
        this.transcript.push({ command, output: result.output.slice(0, CDB_TRANSCRIPT_ENTRY_CHARS), seconds: result.seconds });
        return result;
      });
    this.queue = task.catch(() => {});
    return task;
  }

  private async runBatch(command: string, timeoutSeconds: number): Promise<DebugCommandResult> {
    this.commands.push(command);
    // Re-run the whole accumulated batch against the frozen dump; q exits cdb.
    const batch = `${this.commands.join("; ")}; q`;
    const startedAt = Date.now();
    const cmd = await runBoundedCommand(this.backendPath, ["-z", this.dumpPath, "-c", batch, "-y", this.sympath], {
      cwd: this.runDir,
      timeoutMs: (timeoutSeconds + 30) * 1000,
      maxOutputBytes: 4 * 1024 * 1024,
    });
    const seconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));
    const output = cleanCdbOutput(cmd.stdout);
    if (cmd.exitCode !== 0 || cmd.timedOut) {
      return {
        ok: false,
        output,
        seconds,
        ...(cmd.timedOut ? { timedOut: true } : {}),
        error: `cdb exited with code ${cmd.exitCode ?? -1}${cmd.timedOut ? " (timed out)" : ""}`,
      };
    }
    return { ok: true, output, seconds };
  }

  async teardown(): Promise<{ commandsExecuted: number; transcript: DebugTranscriptEntry[] }> {
    // cdb exits after each batch; nothing to kill. Keep the run dir for the
    // transcript artifact; downloaded symbols are best-effort.
    return { commandsExecuted: this.commands.length, transcript: this.transcript };
  }
}

async function assertMinidumpMagic(absolute: string): Promise<void> {
  const handle = await open(absolute, "r");
  try {
    const buf = Buffer.alloc(4);
    await handle.read(buf, 0, 4, 0);
    if (buf.toString("ascii") !== "MDMP") {
      throw new Error(`debug.session.create (cdb): not a minidump (expected MDMP magic): ${absolute}`);
    }
  } finally {
    await handle.close();
  }
}
