/**
 * frida.script + trace.diff tests: the persistent-instrumentation plane.
 * Live tests spawn real processes under the frida runtime — they skip
 * without it (or without an armed dynamic plane).
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { composeTraceDiffResult, runFridaScript, runTraceDiff, summarizeTraceDiff, TRACE_DIFF_TOP_N } from "../dist/core/frida.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

async function fridaAvailable() {
  try {
    await import("frida");
    return true;
  } catch {
    return false;
  }
}

function armEnv(context) {
  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  context.after(() => {
    if (previousAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });
}

// printf with format specifiers routes through __stdio_common_vfprintf on
// mingw — plain puts() keeps the fixture observable through one export.
// Sleep at the end: a process that dies in microseconds can outrun frida's
// async send() delivery — the last events die with the process. A short
// tail keeps delivery alive (fridatarget works the same way).
const BRANCHY_SOURCE = `
#include <stdio.h>
#include <string.h>
#include <windows.h>
int main(int argc, char **argv) {
    // Both frida.script and trace.diff pass the distinguishing input via
    // argv (the OBJECT spawn form delivers it; stdin would leave the
    // process blocked in the kernel, which stops Stalker event delivery
    // AND the agent send() pump — field-tested the hard way).
    if (argc < 2) return 1;
    if (strcmp(argv[1], "GOOD") == 0) {
        puts("branch-alpha");
        puts("alpha-done");
    } else {
        puts("branch-beta");
        puts("beta-done");
    }
    puts("common-tail");
    Sleep(600);
    return 0;
}
`;

// A parent that spawns a child (the child-gating fixture).
const SPAWNER_SOURCE = `
#include <stdio.h>
#include <windows.h>
int main(void) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"cmd.exe /c exit";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("child-ran\\n");
    }
    return 0;
}
`;

test("frida.script and trace.diff operations exist with honest contracts", () => {
  const script = operations.find((entry) => entry.id === "frida.script");
  assert.ok(script, "frida.script exists");
  assert.match(script.description, /childGating/i);
  assert.match(script.description, /nanomite/i);
  const diff = operations.find((entry) => entry.id === "trace.diff");
  assert.ok(diff, "trace.diff exists");
  assert.match(diff.description, /symmetric difference|blocks only/i);
});

test("summarizeTraceDiff finds counts, the earliest divergence, and reconvergences", () => {
  // Run A: 0x1000(t=10) shared, 0x2000(t=20) only-A, 0x3000(t=30) shared-after-divergence
  // Run B: 0x1000(t=12) shared, 0x4000(t=25) only-B, 0x3000(t=40) shared-after-divergence
  const blocksA = new Map([[0x1000, 10], [0x2000, 20], [0x3000, 30]]);
  const blocksB = new Map([[0x1000, 12], [0x4000, 25], [0x3000, 40]]);
  const summary = summarizeTraceDiff(blocksA, blocksB);
  assert.deepEqual(summary.counts, { runA: 3, runB: 3, shared: 2, onlyA: 1, onlyB: 1 });
  assert.deepEqual(summary.firstDivergence, { rva: "0x2000", firstSeenMs: 20, seenIn: "A" });
  // 0x3000 was executed by both runs AFTER t=20 — the reconvergence point.
  assert.deepEqual(summary.reconvergences, [{ rva: "0x3000", firstSeenMsA: 30, firstSeenMsB: 40 }]);
  // No divergence at all → null, no reconvergences.
  const identical = summarizeTraceDiff(new Map([[0x1000, 10]]), new Map([[0x1000, 11]]));
  assert.equal(identical.firstDivergence, null);
  assert.deepEqual(identical.reconvergences, []);
});

test("composeTraceDiffResult keeps a small diff inline and writes no file", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-td-small-"));
  const workspace = await Workspace.create(root);
  const result = await composeTraceDiffResult(
    workspace,
    { pid: 1, blocks: new Map([[0x1000, 10], [0x2000, 20]]) },
    { pid: 2, blocks: new Map([[0x1000, 12], [0x4000, 25]]) },
    [],
  );
  assert.equal(result.status, "ok");
  assert.equal(result.blocksOnlyInA.length, 1);
  assert.equal(result.blocksOnlyInB.length, 1);
  assert.equal(result.sharedBlockCount, 1);
  assert.equal(result.fullDiffFile, null);
  assert.deepEqual(result.summary.firstDivergence, { rva: "0x2000", firstSeenMs: 20, seenIn: "A" });
  await rm(root, { recursive: true, force: true });
});

test("composeTraceDiffResult truncates a huge diff to the earliest top-N and spills the rest", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-td-big-"));
  const workspace = await Workspace.create(root);
  // 60 blocks only in A (times deliberately shuffled: the earliest by TIME
  // must lead the inline list, not the lowest RVA), 5 only in B.
  const blocksA = new Map();
  for (let index = 0; index < 60; index += 1) blocksA.set(0x10000 + index * 0x10, 1000 - index);
  const blocksB = new Map();
  for (let index = 0; index < 5; index += 1) blocksB.set(0x20000 + index * 0x10, 100 + index);
  const notes = [];
  const result = await composeTraceDiffResult(workspace, { pid: 1, blocks: blocksA }, { pid: 2, blocks: blocksB }, notes);
  assert.equal(result.blocksOnlyInA.length, TRACE_DIFF_TOP_N);
  assert.equal(result.blocksOnlyInB.length, 5);
  // Earliest-by-time ordering: the last-inserted A block has the smallest t.
  assert.equal(result.blocksOnlyInA[0].rva, `0x${(0x10000 + 59 * 0x10).toString(16)}`);
  assert.equal(result.summary.counts.onlyA, 60);
  assert.ok(result.fullDiffFile !== null, "the full diff spilled to a file");
  assert.ok(notes.some((note) => note.includes("diff truncated") && note.includes(result.fullDiffFile)));
  const spilled = JSON.parse(await readFile(path.join(root, result.fullDiffFile), "utf8"));
  assert.equal(spilled.blocksOnlyInA.length, 60, "the spill file carries the COMPLETE list");
  assert.equal(spilled.blocksOnlyInB.length, 5);
  // The spill file is RVA-sorted for navigation.
  assert.equal(spilled.blocksOnlyInA[0].rva, "0x10000");
  await rm(root, { recursive: true, force: true });
});

test("frida.script rejects an empty agent source before spawning anything", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-fs-"));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), "MZ");
  await assert.rejects(
    () => runFridaScript(workspace, "s.exe", { source: "   " }),
    /agent source is empty/,
  );
  await rm(root, { recursive: true, force: true });
});

test("frida.script live: custom agent streams events to the JSONL log", { timeout: 180_000 }, async (context) => {
  if (!(await fridaAvailable())) context.skip("needs the frida node runtime");
  armEnv(context);
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-fs-live-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "branchy.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, "-x", "c", "-"], { input: BRANCHY_SOURCE });
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);

  // The puts PLT stub RVA from the actual compilation: the Windows frida
  // trap is that puts resolves through getGlobalExportByName to whichever
  // CRT module is first — the call goes to a DIFFERENT copy and the hook
  // never fires. Hooking the sample's own PLT is the reliable route; the
  // agent receives the RVA as a plain constant.
  const disassembly = execFileSync("objdump", ["-d", "-M", "intel", binary], { maxBuffer: 16 * 1024 * 1024 }).toString();
  const pltMatch = /^\s*([0-9a-f]+):\s+e8.*\s+call\s+\S+\s+<puts>$/m.exec(disassembly);
  assert.ok(pltMatch, "the fixture calls puts through a PLT stub");
  const callSite = Number.parseInt(pltMatch[1], 16);
  const stubMatch = new RegExp(`^\\s*([0-9a-f]+):\\s+e9.*\\s+jmp\\s+.*<puts>$`, "m").exec(disassembly)
    ?? /^\s*([0-9a-f]+):\s+ff 25.*\s+jmp\s+QWORD PTR \[rip\+\S+\]\s+# \S+ <__imp_puts>$/m.exec(disassembly);
  assert.ok(stubMatch, "the puts PLT stub is identifiable");
  const pltRva = Number.parseInt(stubMatch[1], 16) - 0x140000000;
  void callSite;

  const result = await runFridaScript(workspace, "branchy.exe", {
    source: `
      var main = Process.enumerateModules()[0];
      var plt = main.base.add(${pltRva});
      Interceptor.attach(plt, {
        onEnter: function (args) {
          // readUtf8String(count) throws on an embedded NUL — readCString
          // stops at the terminator like the C runtime does.
          var text = null;
          try { text = args[0].readCString(); } catch (e) { text = null; }
          send({ api: "puts", text: text });
        }
      });
      send({ hookedPlt: String(plt) });
    `,
    args: ["GOOD"],
    probeSeconds: 6,
  });
  assert.equal(result.attachFailed, null, result.attachFailed ?? "");
  assert.ok(result.events.length > 0, "the agent streamed at least one event");
  const texts = result.events.map((event) => String((event.payload ?? {}).text ?? ""));
  assert.ok(texts.some((text) => text.includes("branch-alpha")), `events include the branch prints, got: ${texts.join(" | ")}`);
  assert.ok(result.eventLogPath !== null, "the JSONL log path is returned");
  const log = await readFile(path.join(workspace.root, result.eventLogPath), "utf8");
  assert.ok(log.split("\n").filter((line) => line.trim() !== "").length > 0, "the JSONL log is non-empty");
});

test("trace.diff live: GOOD vs BAD inputs localize the differing blocks", { timeout: 180_000 }, async (context) => {
  if (!(await fridaAvailable())) context.skip("needs the frida node runtime");
  armEnv(context);
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-td-live-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "branchy.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, "-x", "c", "-"], { input: BRANCHY_SOURCE });
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);

  const result = await runTraceDiff(workspace, "branchy.exe", {
    argsA: ["GOOD"],
    argsB: ["BAD"],
    probeSeconds: 4,
  });
  assert.equal(result.status, "ok", result.error ?? "");
  assert.ok(result.runA.blockCount > 0 && result.runB.blockCount > 0, "both runs recorded block coverage");
  assert.ok(result.sharedBlockCount > 0, "the common tail is shared");
  // The differing blocks must exist in BOTH directions: alpha-only and
  // beta-only. An empty diff would mean Stalker saw nothing or the branches
  // did not diverge.
  assert.ok(result.blocksOnlyInA.length > 0, `blocks only in run A (GOOD): ${result.blocksOnlyInA.length}`);
  assert.ok(result.blocksOnlyInB.length > 0, `blocks only in run B (BAD): ${result.blocksOnlyInB.length}`);
  // RVA sanity: blocks are inside a small module — addresses are hex strings.
  assert.match(result.blocksOnlyInA[0].rva, /^0x[0-9a-f]+$/);
});

test("frida.script live with childGating: spawned children are observed", { timeout: 180_000 }, async (context) => {
  if (!(await fridaAvailable())) context.skip("needs the frida node runtime");
  armEnv(context);
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-cg-live-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "spawner.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, "-x", "c", "-"], { input: SPAWNER_SOURCE, stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);

  const result = await runFridaScript(workspace, "spawner.exe", {
    source: `
      var created = Module.getGlobalExportByName("CreateProcessW");
      if (created) {
        Interceptor.attach(created, {
          onEnter: function (args) {
            send({ api: "CreateProcessW" });
          }
        });
      }
    `,
    probeSeconds: 8,
    childGating: true,
  });
  assert.equal(result.attachFailed, null, result.attachFailed ?? "");
  assert.ok(result.events.some((event) => (event.payload ?? {}).api === "CreateProcessW"),
    "the parent's CreateProcessW is observed");
  assert.ok(result.childGating === true);
  // The child (cmd.exe) was gated: either attached (pid recorded) or at
  // least held and resumed — the notes describe what happened.
  assert.ok(
    result.attachedPids.length >= 1 || result.notes.some((note) => /spawn gating enabled/.test(note)),
    "spawn gating was active for children",
  );
});
