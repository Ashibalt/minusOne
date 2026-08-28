import assert from "node:assert/strict";
import { writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectBinary } from "../dist/core/binary.js";
import { runBoundedCommand } from "../dist/core/command.js";
import { extractStrings } from "../dist/core/strings.js";
import { Workspace, WorkspaceError } from "../dist/core/workspace.js";

function createPeFixture() {
  const buffer = Buffer.alloc(1024);
  buffer.write("MZ", 0, "ascii");
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write("PE\0\0", 0x80, "ascii");
  buffer.writeUInt16LE(0x8664, 0x84);
  buffer.writeUInt16LE(0x20b, 0x98);
  buffer.write("minusOne-visible-string", 0x200, "ascii");
  buffer.write("wide-secret", 0x280, "utf16le");
  return buffer;
}

async function fixtureWorkspace() {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-test-"));
  const root = path.join(parent, "workspace");
  await mkdir(root);
  await writeFile(path.join(root, "sample.exe"), createPeFixture());
  await writeFile(path.join(parent, "outside.bin"), "outside");
  return { parent, root, workspace: await Workspace.create(root) };
}

test("identifies a PE binary and produces a stable sample id", async (context) => {
  const fixture = await fixtureWorkspace();
  context.after(() => rm(fixture.parent, { recursive: true, force: true }));

  const info = await inspectBinary(fixture.workspace, "sample.exe");
  assert.equal(info.format.kind, "pe");
  assert.equal(info.format.architecture, "x86_64");
  assert.equal(info.format.bits, 64);
  assert.match(info.sha256, /^[a-f0-9]{64}$/);
  assert.equal(info.sampleId, info.sha256.slice(0, 16));
});

test("extracts bounded ASCII and UTF-16LE strings", async (context) => {
  const fixture = await fixtureWorkspace();
  context.after(() => rm(fixture.parent, { recursive: true, force: true }));

  const extracted = await extractStrings(fixture.workspace, "sample.exe", { minLength: 5, limit: 20 });
  assert.ok(extracted.strings.some((entry) => entry.value === "minusOne-visible-string" && entry.encoding === "ascii"));
  assert.ok(extracted.strings.some((entry) => entry.value === "wide-secret" && entry.encoding === "utf16le"));
  assert.equal(extracted.resultTruncated, false);
});

test("rejects traversal to an existing file outside the workspace", async (context) => {
  const fixture = await fixtureWorkspace();
  context.after(() => rm(fixture.parent, { recursive: true, force: true }));

  await assert.rejects(() => fixture.workspace.resolveFile("../outside.bin"), WorkspaceError);
});

test("bounds command output instead of feeding unlimited data to the agent", async () => {
  const result = await runBoundedCommand(
    process.execPath,
    ["-e", "process.stdout.write('x'.repeat(100000))"],
    { maxOutputBytes: 1024, timeoutMs: 5_000 },
  );
  assert.equal(result.outputTruncated, true);
  assert.ok(Buffer.byteLength(result.stdout) <= 1024);
});

test("aborts a long-running command through the signal", async () => {
  const controller = new AbortController();
  const resultPromise = runBoundedCommand(
    process.execPath,
    ["-e", "process.stdout.write('started\\n'); setTimeout(() => process.stdout.write('late\\n'), 5000)"],
    { timeoutMs: 60_000, maxOutputBytes: 4096, signal: controller.signal },
  );
  // Give the child a real window to flush "started" before the abort — 500ms
  // races the flush under full-suite parallel load on Windows.
  await new Promise((resolve) => setTimeout(resolve, 1500));
  controller.abort("test cancel");
  const result = await resultPromise;
  assert.equal(result.aborted, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.stdout, "started\n");
});
