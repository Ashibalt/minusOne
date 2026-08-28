import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  closeDebugSession,
  createDebugSession,
  killDebugInferior,
  parseWatchpointResult,
  resolveGdb,
  sendDebugCommand,
} from "../dist/core/debugger.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}

test("sendDebugCommand reports unknown sessions without crashing", async () => {
  const result = await sendDebugCommand("no-such-session", "info registers");
  assert.equal(result.ok, false);
  assert.match(result.error, /unknown debug session/);
});

test("killDebugInferior reports unknown sessions honestly", async () => {
  const result = await killDebugInferior("no-such-session");
  assert.equal(result.ok, false);
  assert.match(result.error, /unknown debug session/);
});

test("parseWatchpointResult: hardware, software, rejected, and silent-degradation shapes", () => {
  const hardware = parseWatchpointResult("Hardware watchpoint 2: *g_counter");
  assert.equal(hardware.watchpointNumber, 2);
  assert.equal(hardware.hardware, true);
  assert.equal(hardware.degraded, false);

  const software = parseWatchpointResult("Watchpoint 3: counter");
  assert.equal(software.watchpointNumber, 3);
  assert.equal(software.hardware, false);
  assert.equal(software.degraded, false);

  const rejected = parseWatchpointResult('No symbol "g_missing" in current context.');
  assert.equal(rejected.watchpointNumber, null);
  assert.equal(rejected.degraded, true);
  assert.match(rejected.note, /rejected/);

  const silent = parseWatchpointResult("(gdb) \nDone.");
  assert.equal(silent.watchpointNumber, null);
  assert.equal(silent.degraded, true);
  assert.match(silent.note, /did not acknowledge/, "a missing acknowledgment must read as NO watchpoint, not success");
});

test("debug.session.create returns a structured refusal when the plane is unarmed", async (context) => {
  const operation = operations.find((entry) => entry.id === "debug.session.create");
  assert.ok(operation, "debug.session.create operation exists");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dbg-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), "dummy");
  const workspace = await Workspace.create(root);

  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  delete process.env.MINUSONE_ALLOW_DYNAMIC;
  delete process.env.MINUSONE_DYNAMIC_TARGET;
  context.after(() => {
    if (previousAllow !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget !== undefined) process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });

  const refused = await operation.execute({ path: "sample.exe" }, { workspace });
  assert.equal(refused.status, "refused");
  assert.match(refused.reason, /disabled by policy/);
  assert.ok(refused.requirements.length > 0);
});

test("anti-anti-debug harden layer neutralizes PEB.BeingDebugged/NtGlobalFlag under gdb", { timeout: 300_000 }, async (context) => {
  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-harden-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "anticheck.exe");
  const compilation = await run("gcc", ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "anticheck.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);
  process.env.MINUSONE_ALLOW_DYNAMIC = process.env.MINUSONE_ALLOW_DYNAMIC ?? "1";

  const created = await createDebugSession(workspace, "anticheck.exe", { harden: true });
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });
  assert.equal(created.harden.applied, true);
  assert.ok(created.harden.what.some((entry) => entry.includes("BeingDebugged")));

  const result = await sendDebugCommand(created.sessionId, "continue", 60);
  assert.equal(result.ok, true, result.error);
  // Under a bare gdb this fixture prints VERDICT=debugged and exits 1; the
  // harden layer must flip the observable PEB state so the sample runs clean.
  assert.match(result.output, /VERDICT=clean/);
  assert.match(result.output, /BeingDebugged=0/);
  assert.match(result.output, /NtGlobalFlag=0x0/);
  assert.match(result.output, /exited normally/);
});

test("debug session lifecycle: stop at entry, breakpoint, registers, memory, transcript", { timeout: 420_000 }, async (context) => {
  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dbg-live-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "xorsecret.exe");
  const compilation = await run("gcc", ["-O0", "-g", "-o", binary, path.join(repository, "test", "fixtures", "xorsecret.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb (resolveGdb) and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);

  const created = await createDebugSession(workspace, "xorsecret.exe", { args: ["wrong-phrase"] });
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });
  assert.equal(created.debugger, "gdb");
  assert.equal(created.startup.ok, true, created.startup.error);
  assert.match(created.startup.output, /ntdll|stopped/i, "starti should stop inside the loader or at entry");

  const breakpoint = await sendDebugCommand(created.sessionId, "break decode");
  assert.equal(breakpoint.ok, true, breakpoint.error);
  assert.match(breakpoint.output, /Breakpoint 1/);

  const continued = await sendDebugCommand(created.sessionId, "continue", 60);
  assert.equal(continued.ok, true, continued.error);
  assert.match(continued.output, /Breakpoint 1/, "the decode breakpoint must be hit");

  const registers = await sendDebugCommand(created.sessionId, "info registers");
  assert.equal(registers.ok, true, registers.error);
  assert.match(registers.output, /r(?:ip|ax)/i, "register dump must contain x86-64 registers");

  const memory = await sendDebugCommand(created.sessionId, "x/16xb $pc");
  assert.equal(memory.ok, true, memory.error);
  assert.match(memory.output, /0x[0-9a-f]+\s/i, "memory dump must show bytes at the program counter");

  const scripted = await sendDebugCommand(created.sessionId, 'python print("minusone-unlocked")');
  assert.equal(scripted.ok, true, scripted.error);
  assert.match(scripted.output, /minusone-unlocked/);

  const closed = await closeDebugSession(created.sessionId);
  assert.ok(closed.commandsExecuted >= 4, `transcript should carry the lifecycle, got ${closed.commandsExecuted}`);
  assert.ok(closed.transcript.some((entry) => entry.command === "break decode"));
});

test("debug_command multi-line batch: every line executes in order (source routing, incl. python blocks)", { timeout: 300_000 }, async (context) => {
  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dbg-multiline-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "xorsecret.exe");
  const compilation = await run("gcc", ["-O0", "-g", "-o", binary, path.join(repository, "test", "fixtures", "xorsecret.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);
  const created = await createDebugSession(workspace, "xorsecret.exe", { stopAtEntry: true });
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });

  // Three plain commands in one batch: all three answers must come back.
  const batch = await sendDebugCommand(created.sessionId, "break decode\ninfo breakpoints\npython print(\"minusone-multiline-ok\")", 60);
  assert.equal(batch.ok, true, batch.error);
  assert.match(batch.output, /Breakpoint 1/, "the batch's break executed");
  assert.match(batch.output, /Num\s+Type|breakpoint/, "the batch's info breakpoints executed");
  assert.match(batch.output, /minusone-multiline-ok/, "the batch's python executed");

  // A python...end BLOCK — the case naive line-splitting destroys.
  const block = await sendDebugCommand(created.sessionId, "python\nprint(\"minusone-block-ok\")\nend", 30);
  assert.equal(block.ok, true, block.error);
  assert.match(block.output, /minusone-block-ok/, "python...end block executed as a unit");
});

test("debug.break builds null-checked, cast string conditions; LIVE: stops only on the matching string", { timeout: 300_000 }, async (context) => {
  const { buildStringBreakpoint } = await import("../dist/core/debugger.js");
  const built = buildStringBreakpoint({ symbol: "probe", register: "rcx", text: "MINU-GOOD" });
  // The exact field-report trap: an uncast strcmp silently degrades the
  // breakpoint to unconditional. The (int) cast is the fix.
  assert.match(built.command, /\(int\)strcmp/);
  assert.match(built.command, /\(\(char\*\)\$rcx\) != 0/);
  const contains = buildStringBreakpoint({ address: "0x140001234", register: "rdx", text: "config", mode: "contains" });
  assert.match(contains.command, /\(int\)strstr/);
  assert.match(contains.command, /\*0x140001234/);

  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-brk-"));
  context.after(() => rmRoot(root));
  const source = '#include <string.h>\nint probe(const char *s) { return strcmp(s, "MINU-GOOD") == 0; }\nint main(void) { probe("MINU-BAD"); probe("MINU-GOOD"); return 0; }\n';
  const { writeFile } = await import("node:fs/promises");
  await writeFile(path.join(root, "breakprobe.c"), source);
  const binary = path.join(root, "breakprobe.exe");
  const compilation = await run("gcc", ["-O0", "-g", "-o", binary, path.join(root, "breakprobe.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);
  process.env.MINUSONE_ALLOW_DYNAMIC = process.env.MINUSONE_ALLOW_DYNAMIC ?? "1";
  const created = await createDebugSession(workspace, "breakprobe.exe", { stopAtEntry: true });
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });
  const bp = await sendDebugCommand(created.sessionId, built.command, 30);
  assert.equal(bp.ok, true, bp.error);
  const first = await sendDebugCommand(created.sessionId, "continue", 30);
  // The BAD string must NOT stop; the GOOD string must.
  assert.match(first.output, /MINU-GOOD/);
  assert.doesNotMatch(first.output, /MINU-BAD/);
  const second = await sendDebugCommand(created.sessionId, "continue", 30);
  assert.match(second.output, /exited normally/);
});

test("debug.kill terminates a wedged run and the session stays alive for the next run", { timeout: 420_000 }, async (context) => {
  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-kill-"));
  context.after(() => rmRoot(root));
  // A sample that spins forever after printing a marker — the canonical
  // wedged `continue` from the field reports.
  const binary = path.join(root, "spinner.exe");
  const compilation = await run("gcc", ["-O0", "-g", "-o", binary, path.join(repository, "test", "fixtures", "spinner.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);
  process.env.MINUSONE_ALLOW_DYNAMIC = process.env.MINUSONE_ALLOW_DYNAMIC ?? "1";

  const created = await createDebugSession(workspace, "spinner.exe");
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });

  const bp = await sendDebugCommand(created.sessionId, "break main");
  assert.equal(bp.ok, true, bp.error);

  // Reach main first (the first continue stops at the breakpoint), then the
  // wedged run: the second continue enters the infinite loop and times out.
  const atMain = await sendDebugCommand(created.sessionId, "continue", 30);
  assert.equal(atMain.ok, true, atMain.error);
  assert.match(atMain.output, /Breakpoint 1/);
  const wedged = await sendDebugCommand(created.sessionId, "continue", 10);
  assert.equal(wedged.ok, false);
  assert.equal(wedged.timedOut, true, "the spin loop must wedge the command");

  // The recovery: kill the inferior WITHOUT closing the session.
  const killed = await killDebugInferior(created.sessionId);
  assert.equal(killed.ok, true, killed.error);
  assert.match(killed.output, /session stays alive/);

  // The session survived: the breakpoint list is still there and a fresh
  // run stops at it again.
  const bps = await sendDebugCommand(created.sessionId, "info breakpoints");
  assert.equal(bps.ok, true, bps.error);
  assert.match(bps.output, /main/);
  const rerun = await sendDebugCommand(created.sessionId, "run", 60);
  assert.equal(rerun.ok, true, rerun.error);
  assert.match(rerun.output, /Breakpoint 1/);
});

test("gdb channel stays coherent under a command queue with logging enabled (field regression)", { timeout: 420_000 }, async (context) => {
  const gdbPath = await resolveGdb();
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-queue-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "xorsecret.exe");
  const compilation = await run("gcc", ["-O0", "-g", "-o", binary, path.join(repository, "test", "fixtures", "xorsecret.c")]);
  if (gdbPath === null || compilation.exitCode !== 0) {
    context.skip(`needs gdb and gcc — gdb=${gdbPath ?? "missing"} gcc exit=${compilation.exitCode}`);
    return;
  }
  const workspace = await Workspace.create(root);
  process.env.MINUSONE_ALLOW_DYNAMIC = process.env.MINUSONE_ALLOW_DYNAMIC ?? "1";

  const created = await createDebugSession(workspace, "xorsecret.exe", { args: ["wrong-phrase"] });
  context.after(async () => {
    try { await closeDebugSession(created.sessionId); } catch { /* already closed */ }
  });

  // The retort-agent scenario: set logging on, then fire a burst of
  // commands concurrently. The queue must serialize them and each answer
  // must belong to its own command — no mixed or lagging output.
  const logPath = path.join(root, "gdb.log").split(path.sep).join("/");
  await sendDebugCommand(created.sessionId, `set logging file ${logPath}`);
  await sendDebugCommand(created.sessionId, "set logging enabled on");

  const burst = await Promise.all([
    sendDebugCommand(created.sessionId, 'python print("QUEUE-ALPHA")'),
    sendDebugCommand(created.sessionId, 'python print("QUEUE-BRAVO")'),
    sendDebugCommand(created.sessionId, 'python print("QUEUE-CHARLIE")'),
    sendDebugCommand(created.sessionId, "info registers"),
    sendDebugCommand(created.sessionId, "info breakpoints"),
  ]);
  const [alpha, bravo, charlie, registers, breakpoints] = burst;
  assert.equal(alpha.ok && bravo.ok && charlie.ok, true, `${alpha.error ?? ""} ${bravo.error ?? ""} ${charlie.error ?? ""}`);
  // Each response carries exactly its own marker — output interleaving or
  // one answer satisfying another command is the regression we guard.
  assert.match(alpha.output, /QUEUE-ALPHA/);
  assert.doesNotMatch(alpha.output, /QUEUE-BRAVO|QUEUE-CHARLIE/);
  assert.match(bravo.output, /QUEUE-BRAVO/);
  assert.doesNotMatch(bravo.output, /QUEUE-ALPHA|QUEUE-CHARLIE/);
  assert.match(charlie.output, /QUEUE-CHARLIE/);
  assert.doesNotMatch(charlie.output, /QUEUE-ALPHA|QUEUE-BRAVO/);
  assert.match(registers.output, /r(?:ip|ax)/i);
  assert.match(breakpoints.output, /No breakpoints|Num/);

  await sendDebugCommand(created.sessionId, "set logging enabled off");
});
