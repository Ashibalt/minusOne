/**
 * x64dbg headless driver (batch-script model). x64dbg ships a headless.exe
 * build that loads a target, runs a native script file (-cf <path>), and
 * exits — no GUI. Each debug_command is a COMPLETE x64dbg script (newline-
 * separated commands: bp/run/mov/etc.); headless re-runs it from scratch on
 * the freshly loaded sample, so there is no shared state between commands
 * (unlike gdb's prompt loop or cdb's frozen-dump batch).
 *
 * IMPORTANT limitation: x64dbg's `log` command writes to the in-memory log
 * view, which headless does NOT surface to stdout or a file (verified
 * against stdout, logsave, and ini [Logs] AutoLog). What headless DOES
 * print to stdout is the debugger EVENT stream: module loads, breakpoint
 * hits, state transitions ([STATE] running/paused/stopped), exceptions, and
 * the exit code. So this driver is an EVENT debugger — "did it break here,
 * which DLLs loaded, did it crash, what was the exit code" — not a
 * structured register/memory-value reader. For register/memory VALUES use
 * gdb (live) or cdb (postmortem). Loading a sample is live execution, so
 * this plane is dynamic-gated like gdb.
 *
 * (A value-returning x64dbg path needs the x64dbgpy plugin, which can write
 * results to a file via Python I/O — not installed; deferred.)
 */
import { randomUUID } from "node:crypto";
import { mkdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { runBoundedCommand } from "./command.js";
import type { DebugCommandResult, DebugDriver, DebugTranscriptEntry, DebuggerKind } from "./debug-driver.js";
import type { Workspace } from "./workspace.js";

export const X64DBG_DEFAULT_COMMAND_SECONDS = 60;
export const X64DBG_MAX_COMMAND_SECONDS = 300;
const X64DBG_OUTPUT_CAP_CHARS = 256 * 1024;
const X64DBG_TRANSCRIPT_ENTRY_CHARS = 64 * 1024;
const X64DBG_TRANSCRIPT_MAX_ENTRIES = 500;

const X64DBG_FIXED_PATHS = [
  "C:\\x64dbg\\release\\x64\\headless.exe",
  "C:\\x64dbg\\release\\x32\\headless.exe",
  "C:\\x64dbg\\x64\\headless.exe",
  "C:\\x64dbg\\x32\\headless.exe",
];

export async function resolveX64dbgHeadless(): Promise<string | null> {
  const explicit = process.env.MINUSONE_X64DBG_HEADLESS;
  if (explicit) return explicit;
  if (process.platform !== "win32") return null;
  for (const candidate of X64DBG_FIXED_PATHS) {
    if (await stat(candidate).then(() => true, () => false)) return candidate;
  }
  const home = process.env.MINUSONE_X64DBG_HOME;
  if (home) {
    for (const sub of ["release\\x64\\headless.exe", "release\\x32\\headless.exe", "x64\\headless.exe", "x32\\headless.exe"]) {
      const candidate = path.join(home, sub);
      if (await stat(candidate).then(() => true, () => false)) return candidate;
    }
  }
  return null;
}

function cap(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n[output truncated: ${text.length} chars total]`;
}

function cleanX64dbgOutput(raw: string): string {
  // Keep the event stream (Breakpoint/DLL Loaded/[STATE]/Thread/exit) but
  // drop the verbose PDB-resolution and not-implemented chatter.
  const text = raw
    .replace(/\r/g, "")
    .split("\n")
    .filter((line) => !/^\[SYMBOL\]/.test(line) && !/^\[TODO\]/.test(line))
    .join("\n");
  return cap(text.trim(), X64DBG_OUTPUT_CAP_CHARS);
}

export class X64dbgDriver implements DebugDriver {
  readonly kind: DebuggerKind = "x64dbg";

  private readonly transcript: DebugTranscriptEntry[] = [];
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly targetAbs: string,
    private readonly relativeTarget: string,
    public readonly backendPath: string,
    private readonly runDirAbs: string,
    private readonly args: string[],
  ) {}

  static async create(workspace: Workspace, userPath: string, options: { args?: string[] }): Promise<X64dbgDriver> {
    const absolute = await workspace.resolveFile(userPath);
    const headlessPath = await resolveX64dbgHeadless();
    if (headlessPath === null) {
      throw new Error(
        "no x64dbg headless backend found: set MINUSONE_X64DBG_HEADLESS or MINUSONE_X64DBG_HOME, or install x64dbg (headless.exe under release/x64)",
      );
    }
    const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
    await mkdir(runDir, { recursive: true });
    return new X64dbgDriver(absolute, workspace.relative(absolute), headlessPath, runDir, options.args ?? []);
  }

  get target(): string {
    return this.relativeTarget;
  }

  get runDir(): string {
    return this.runDirAbs;
  }

  send(command: string, timeoutSeconds: number): Promise<DebugCommandResult> {
    const bounded = Math.min(Math.max(timeoutSeconds, 5), X64DBG_MAX_COMMAND_SECONDS);
    const task = this.queue
      .then(() => this.runScript(command, bounded))
      .then((result) => {
        if (this.transcript.length >= X64DBG_TRANSCRIPT_MAX_ENTRIES) this.transcript.shift();
        this.transcript.push({
          command,
          output: result.output.slice(0, X64DBG_TRANSCRIPT_ENTRY_CHARS),
          seconds: result.seconds,
        });
        return result;
      });
    this.queue = task.catch(() => {});
    return task;
  }

  private async runScript(script: string, timeoutSeconds: number): Promise<DebugCommandResult> {
    const scriptFile = path.join(this.runDirAbs, `script-${this.transcript.length}.txt`);
    const source = script.endsWith("\n") ? script : `${script}\n`;
    await writeFile(scriptFile, source, "utf8");
    const userdir = path.join(this.runDirAbs, "userdir");
    await mkdir(userdir, { recursive: true });

    // headless: -cf <script> -workingDir <runDir> -userdir <userdir> <target> -- <args>
    // Each send is a fresh load+run; headless exits when the script ends and the
    // debuggee terminates (or the timeout kills it).
    const startedAt = Date.now();
    const cmd = await runBoundedCommand(
      this.backendPath,
      [
        "-cf", scriptFile,
        "-workingDir", this.runDirAbs,
        "-userdir", userdir,
        this.targetAbs,
        ...(this.args.length > 0 ? ["--", ...this.args] : []),
      ],
      {
        cwd: this.runDirAbs,
        timeoutMs: (timeoutSeconds + 30) * 1000,
        maxOutputBytes: 8 * 1024 * 1024,
      },
    );
    const seconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));
    const output = cleanX64dbgOutput(cmd.stdout);
    // headless returns non-zero on a debuggee crash; treat a crash as the
    // event stream being the payload (the agent wants the crash events).
    if (cmd.timedOut) {
      return { ok: false, output, seconds, timedOut: true, error: `x64dbg headless did not exit within ${timeoutSeconds}s` };
    }
    return { ok: true, output, seconds };
  }

  async teardown(): Promise<{ commandsExecuted: number; transcript: DebugTranscriptEntry[] }> {
    // headless exits after each script run; nothing to kill.
    return { commandsExecuted: this.transcript.length, transcript: this.transcript };
  }
}
