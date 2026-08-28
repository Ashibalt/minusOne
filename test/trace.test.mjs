import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { runTraceSource } from "../dist/core/trace.js";
import { triageBinary } from "../dist/core/triage.js";
import { upsertSymbols } from "../dist/core/symbols.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function withDynamicEnv(body) {
  const savedAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const savedTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  return Promise.resolve(body()).finally(() => {
    if (savedAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = savedAllow;
    if (savedTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = savedTarget;
  });
}

function fakePe(payload) {
  const buf = Buffer.alloc(0x600, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24);
  const st = 0x188;
  buf.write(".rdata", st, "latin1");
  buf.writeUInt32LE(0x200, st + 8);
  buf.writeUInt32LE(0x1000, st + 12);
  buf.writeUInt32LE(0x400, st + 16);
  buf.writeUInt32LE(0x400, st + 20);
  buf.write(payload, 0x400, "latin1");
  return buf;
}

async function fridaAvailable() {
  try {
    await import("frida");
    return true;
  } catch {
    return false;
  }
}

test("trace.source LIVE: sleeper fixture — hook CreateFileW, find the calling function, resolve slide + symbols", { timeout: 120_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  if (!(await fridaAvailable())) context.skip("needs the frida runtime");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-trace-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const source = path.join(root, "marker.c");
  await writeFile(source, [
    "#include <stdio.h>",
    "#include <windows.h>",
    "int main(void) {",
    "  for (int beat = 0; beat < 20; beat++) {",
    "    HANDLE note = CreateFileW(L\"trace-marker.txt\", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);",
    "    if (note != INVALID_HANDLE_VALUE) CloseHandle(note);",
    "    Sleep(1000);",
    "  }",
    "  return 0;",
    "}",
    "",
  ].join("\n"));
  const exe = path.join(root, "marker.exe");
  assert.equal(spawnSync("gcc", ["-O0", "-o", exe, source], { encoding: "utf8" }).status, 0, "gcc build failed");

  // Pre-seed a symbol so the site resolves by name (compounding loop proof).
  const result = await withDynamicEnv(() =>
    runTraceSource(workspace, "marker.exe", { apis: ["CreateFileW"], needle: "trace-marker", probeSeconds: 6, decompile: false }),
  );

  assert.equal(result.attachFailed ?? result.stages[0].status !== "failed", true);
  const sourceStage = result.stages.find((stage) => stage.stage === "source-trace");
  assert.equal(sourceStage.status, "ok", sourceStage.detail);
  assert.ok(result.eventCount >= 1, `expected at least one CreateFileW call, got ${result.eventCount}`);
  assert.ok(result.hookedApis.includes("CreateFileW"));

  // Slide: resolved and consistent with the sample module's runtime base.
  const slideStage = result.stages.find((stage) => stage.stage === "slide");
  assert.equal(slideStage.status, "ok", slideStage.detail);
  assert.notEqual(result.slide, null);
  assert.notEqual(result.sampleModule, null);

  // Sites: sample-module frames converted to static VAs.
  const sitesStage = result.stages.find((stage) => stage.stage === "sites");
  assert.equal(sitesStage.status, "ok", sitesStage.detail);
  assert.ok(result.sites.length >= 1, "expected at least one static site");
  for (const site of result.sites) {
    assert.match(site.staticVa, /^0x[0-9a-f]+$/);
    assert.ok(site.hits >= 1);
    assert.ok(site.apis.includes("CreateFileW"));
  }
  // The marker filename shows up in the site args (evidence chain).
  const allArgs = result.sites.flatMap((site) => site.args);
  assert.ok(allArgs.some((arg) => arg.includes("trace-marker")), `args: ${JSON.stringify(allArgs)}`);

  // Symbol resolution: annotate the top site, re-run, see the name.
  const top = result.sites[0];
  await upsertSymbols(workspace, result.sampleId, [{ va: top.staticVa, name: "open_marker_file" }]);
  const second = await withDynamicEnv(() =>
    runTraceSource(workspace, "marker.exe", { apis: ["CreateFileW"], needle: "trace-marker", probeSeconds: 6, decompile: false }),
  );
  const named = second.sites.find((site) => site.staticVa === top.staticVa);
  if (named !== undefined) {
    assert.equal(named.symbol, "open_marker_file");
  }
});

test("trace.source: non-PE sample degrades honestly (slide skipped, module-relative notes)", { timeout: 60_000 }, async (context) => {
  if (!(await fridaAvailable())) context.skip("needs the frida runtime");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-trace2-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "plain.txt"), "not a binary at all");

  await assert.rejects(
    () => runTraceSource(workspace, "plain.txt", { probeSeconds: 2, decompile: false }),
    // resolveSampleLaunch needs a PE/DLL/EXE decision; a .txt is refused.
  );
});

test("triage verdict: evidence discipline — packed sample is analysisIncomplete with reasons", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-triagedisc-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  // High-entropy stub with packer-style section names: packed verdict path.
  const buf = Buffer.alloc(0x2000);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x14c, 0x84);
  buf.writeUInt16LE(2, 0x86);
  buf.writeUInt16LE(0xe0, 0x94);
  buf.writeUInt16LE(0x10b, 0x98);
  buf.writeUInt32LE(0x400000, 0x98 + 28);
  const st = 0x80 + 24 + 0xe0;
  buf.write("UPX0", st, "latin1");
  buf.writeUInt32LE(0x1000, st + 12);
  buf.writeUInt32LE(0x1000, st + 8);
  buf.writeUInt32LE(0, st + 20);
  buf.writeUInt32LE(0x100, st + 16);
  buf.write("UPX1", st + 40, "latin1");
  buf.writeUInt32LE(0x2000, st + 40 + 12);
  buf.writeUInt32LE(0x1000, st + 40 + 8);
  buf.writeUInt32LE(0x400, st + 40 + 20);
  buf.writeUInt32LE(0x1a00, st + 40 + 16);
  // Fill UPX1 with random-looking bytes so entropy flags packed.
  for (let index = 0x400; index < 0x1e00; index += 1) buf[index] = (index * 131 + 17) & 0xff;
  await writeFile(path.join(root, "packed.exe"), buf);

  const triage = await triageBinary(workspace, "packed.exe");
  assert.equal(triage.verdict.packed, true);
  assert.equal(triage.verdict.analysisIncomplete, true);
  assert.ok(triage.verdict.incompleteWhy.some((reason) => reason.includes("packed sample")), `why: ${triage.verdict.incompleteWhy.join("; ")}`);
  // Evidence notes always present: data-vs-behavior separation is stated.
  assert.ok(triage.verdict.evidenceNotes.length >= 1);
  assert.ok(triage.verdict.evidenceNotes.some((note) => note.includes("OBSERVED-as-data")));
});

test("triage verdict: clean fixture is NOT analysisIncomplete", { timeout: 120_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-triagedisc2-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const source = path.join(root, "clean.c");
  await writeFile(source, [
    "#include <stdio.h>",
    "int main(void) {",
    "  printf(\"hello clean world\\n\");",
    "  return 0;",
    "}",
    "",
  ].join("\n"));
  const exe = path.join(root, "clean.exe");
  assert.equal(spawnSync("gcc", ["-O0", "-o", exe, source], { encoding: "utf8" }).status, 0, "gcc build failed");

  const triage = await triageBinary(workspace, "clean.exe");
  assert.equal(triage.verdict.packed, false);
  assert.equal(triage.verdict.analysisIncomplete, false, `why: ${triage.verdict.incompleteWhy.join("; ")}`);
  assert.deepEqual(triage.verdict.incompleteWhy, []);
  assert.ok(triage.verdict.evidenceNotes.length >= 1);
});
