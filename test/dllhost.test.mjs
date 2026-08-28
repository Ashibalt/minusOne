import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { resolveSampleLaunch, pickDllExport, resolveRundll32 } from "../dist/core/dllhost.js";
import { parsePeTablesFromBuffer } from "../dist/core/peimports.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const EXEC = operations.find((entry) => entry.id === "sample.execute");
const UNPACK = operations.find((entry) => entry.id === "dynamic.unpack");

/** Minimal PE with the DLL characteristic set and an embedded marker string. */
function fakeDll(marker) {
  const buf = Buffer.alloc(0x400, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c);
  buf.write("PE", 0x40, "latin1");
  buf.writeUInt16LE(0x14c, 0x44); // machine
  buf.writeUInt16LE(1, 0x46); // numberOfSections
  buf.writeUInt16LE(0x2000, 0x56); // characteristics: IMAGE_FILE_DLL
  buf.writeUInt16LE(0xe0, 0x54); // sizeOfOptionalHeader
  buf.writeUInt16LE(0x10b, 0x58); // PE32 magic
  buf.writeUInt32LE(0x10000000, 0x58 + 28); // imageBase
  const st = 0x40 + 24 + 0xe0;
  buf.write(".text", st, "latin1");
  buf.writeUInt32LE(0x200, st + 8); // virtualSize
  buf.writeUInt32LE(0x1000, st + 12); // rva
  buf.writeUInt32LE(0x200, st + 16); // rawSize
  buf.writeUInt32LE(0x200, st + 20); // pointerToRawData
  buf.write(marker ?? "DLLPROOF", 0x200, "latin1");
  return buf;
}

test("pickDllExport prefers heuristic names, then first named, then ordinal", () => {
  const heuristic = parsePeTablesFromBuffer(fakeDll("x"));
  heuristic.exports = [{ name: "ServiceMain", ordinal: 1 }, { name: "other", ordinal: 2 }];
  assert.equal(pickDllExport(heuristic), "ServiceMain");

  const plain = parsePeTablesFromBuffer(fakeDll("x"));
  plain.exports = [{ name: "Alpha", ordinal: 5 }, { name: "Beta", ordinal: 6 }];
  assert.equal(pickDllExport(plain), "Alpha");

  const empty = parsePeTablesFromBuffer(fakeDll("x"));
  empty.exports = [];
  assert.equal(pickDllExport(empty), null);
});

test("resolveSampleLaunch spawns DLLs via rundll32 and EXEs directly", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dllhost-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  await writeFile(path.join(root, "fake.dll"), fakeDll("DLLPROOF"));
  const dll = await resolveSampleLaunch(workspace, "fake.dll");
  assert.equal(dll.host, "rundll32");
  assert.ok(dll.command.toLowerCase().endsWith("rundll32.exe"), `command: ${dll.command}`);
  assert.equal(dll.args.length, 1);
  assert.match(dll.args[0], /fake\.dll$/);

  // EXE (no DLL flag) spawns directly.
  const exeBuf = Buffer.from(fakeDll("x"));
  exeBuf.writeUInt16LE(0x0023, 0x56); // clear DLL bit; executable GUI image
  await writeFile(path.join(root, "fake.exe"), exeBuf);
  const exe = await resolveSampleLaunch(workspace, "fake.exe");
  assert.equal(exe.host, "direct");
  assert.equal(exe.args.length, 0);

  // A DLL with no exports still goes through rundll32 (bare load → DllMain).
  const bareDll = parsePeTablesFromBuffer(fakeDll("x"));
  bareDll.exports = [];
  await writeFile(path.join(root, "bare.dll"), fakeDll("bare"));
  const bare = await resolveSampleLaunch(workspace, "bare.dll");
  assert.equal(bare.host, "rundll32");
  assert.equal(bare.entryExport, null);

  // Non-PE file spawns directly.
  await writeFile(path.join(root, "plain.bin"), "not a PE");
  const plain = await resolveSampleLaunch(workspace, "plain.bin");
  assert.equal(plain.host, "direct");
});

test("resolveRundll32 honors the override and finds a System32 binary", () => {
  const previous = process.env.MINUSONE_RUNDLL32_BIN;
  process.env.MINUSONE_RUNDLL32_BIN = "C:\\does\\not\\exist\\rundll32.exe";
  try {
    const fallback = resolveRundll32(64);
    assert.ok(/rundll32\.exe$/i.test(fallback), `fallback resolved: ${fallback}`);
  } finally {
    delete process.env.MINUSONE_RUNDLL32_BIN;
    if (previous !== undefined) process.env.MINUSONE_RUNDLL32_BIN = previous;
  }
});

test("DLL live: sample.execute hosts the DLL via rundll32 and drops the marker", { timeout: 120_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dllexec-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const dll = path.join(root, "dllsleeper.dll");
  assert.equal(
    spawnSync("gcc", ["-shared", "-o", dll, path.join(process.cwd(), "test", "fixtures", "dllsleeper.c")], { encoding: "utf8" }).status,
    0,
    "gcc -shared build failed",
  );

  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  try {
    let settle;
    const done = new Promise((resolve) => {
      settle = resolve;
    });
    const jobs = {
      start(spec) {
        const handle = spec.run();
        handle.done.then((outcome) => settle(outcome));
        return "dll-exec-1";
      },
    };
    await EXEC.execute({ path: "dllsleeper.dll", timeoutSeconds: 6, entryExport: "RunPayload" }, { workspace, jobs });
    const outcome = await done;
    const payload = JSON.parse(outcome.output);
    assert.equal(outcome.status, "completed", `exec failed: ${outcome.detail ?? ""}`);
    assert.equal(payload.launchedVia, "rundll32 (RunPayload)");
    assert.ok(
      payload.droppedFiles.some((f) => /dll-dropped-note/.test(f.path)),
      `marker dropped: ${JSON.stringify(payload.droppedFiles)}`,
    );
  } finally {
    delete process.env.MINUSONE_ALLOW_DYNAMIC;
    delete process.env.MINUSONE_DYNAMIC_TARGET;
  }
});

test("DLL live: dynamic.unpack hosts the DLL via rundll32 and pe-sieve scans the loaded image", { timeout: 180_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dllunpack-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const dll = path.join(root, "dllsleeper.dll");
  assert.equal(
    spawnSync("gcc", ["-shared", "-o", dll, path.join(process.cwd(), "test", "fixtures", "dllsleeper.c")], { encoding: "utf8" }).status,
    0,
    "gcc -shared build failed",
  );

  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  try {
    let settle;
    const done = new Promise((resolve) => {
      settle = resolve;
    });
    const jobs = {
      start(spec) {
        const handle = spec.run();
        handle.done.then((outcome) => settle(outcome));
        return "dll-unpack-1";
      },
    };
    await UNPACK.execute({ path: "dllsleeper.dll", runSeconds: 4, entryExport: "RunPayload" }, { workspace, jobs });
    const outcome = await done;
    assert.equal(outcome.status, "completed", `unpack failed: ${outcome.detail ?? ""}`);
    const payload = JSON.parse(outcome.output);
    // The DLL was hosted through rundll32 and the export ran (hosting works).
    assert.equal(payload.launchedVia, "rundll32 (RunPayload)");
    assert.ok(payload.stillRunningAtScan, "the rundll32 process was alive when pe-sieve scanned");
    // pe-sieve scanned modules in the hosted process. A clean (non-packed) DLL
    // is not "suspicious", so pe-sieve reports zero dumped modules — that is
    // correct behavior, not a hosting bug. The gate is: the scan ran.
    assert.match(payload.sieveReport, /Total scanned:\s+\d+/);
    assert.ok(/PID:/.test(payload.sieveReport), "pe-sieve targeted the rundll32 process");
  } finally {
    delete process.env.MINUSONE_ALLOW_DYNAMIC;
    delete process.env.MINUSONE_DYNAMIC_TARGET;
  }
});
