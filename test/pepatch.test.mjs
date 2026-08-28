import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { parsePatchBytes, patchBinary } from "../dist/core/pepatch.js";
import { rmRoot } from "./helpers.mjs";
import { Workspace } from "../dist/core/workspace.js";

async function fakeWorkspace(content = "ORIGINAL-CONTENT-1234567890") {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-patch-"));
  await writeFile(path.join(root, "sample.bin"), content);
  return { root, workspace: await Workspace.create(root) };
}

test("parsePatchBytes validates hex", () => {
  assert.deepEqual([...parsePatchBytes("9090")], [0x90, 0x90]);
  assert.deepEqual([...parsePatchBytes("eb")], [0xeb]);
  assert.throws(() => parsePatchBytes(""), /empty/);
  assert.throws(() => parsePatchBytes("abc"), /even/);
  assert.throws(() => parsePatchBytes("zz"), /hex/);
});

test("binary.patch writes into a copy and leaves the original untouched", async (context) => {
  const { root, workspace } = await fakeWorkspace();
  context.after(() => rmRoot(root));
  const operation = operations.find((entry) => entry.id === "binary.patch");
  assert.ok(operation, "binary.patch operation exists");
  assert.equal(operation.toolName, "binary_patch");

  const result = await operation.execute(
    { path: "sample.bin", patches: [{ offset: 9, bytes: "434f5059" }] }, // "COPY" overwrites "CONT"
    { workspace },
  );
  assert.equal(result.patchesApplied, 1);
  assert.equal(result.originalSha256, createHash("sha256").update("ORIGINAL-CONTENT-1234567890").digest("hex"));
  assert.notEqual(result.originalSha256, result.patchedSha256);
  assert.equal(result.diff.length, 1);
  assert.equal(result.diff[0].offset, 9);
  assert.equal(result.diff[0].from, "434f4e54"); // "CONT"
  assert.equal(result.diff[0].to, "434f5059"); // "COPY"

  const patched = await readFile(path.join(workspace.root, result.patchedPath));
  assert.equal(patched.toString("utf8"), "ORIGINAL-COPYENT-1234567890");

  // The original file is untouched.
  const original = await readFile(path.join(workspace.root, "sample.bin"));
  assert.equal(original.toString("utf8"), "ORIGINAL-CONTENT-1234567890");
});

test("binary.patch applies multiple patches in one pass", async (context) => {
  const { root, workspace } = await fakeWorkspace("AAAABBBBCCCCDDDD");
  context.after(() => rmRoot(root));
  const result = await patchBinary(workspace, "sample.bin", [
    { offset: 0, bytes: "5a5a" }, // "ZZ" overwrites "AA"
    { offset: 8, bytes: "44444444" }, // "DDDD" (4 bytes) overwrites "CCCC"
  ]);
  assert.equal(result.patchesApplied, 2);
  const patched = await readFile(path.join(workspace.root, result.patchedPath));
  assert.equal(patched.toString("utf8"), "ZZAABBBBDDDDDDDD");
});

test("binary.patch rejects out-of-bounds and invalid patches", async (context) => {
  const { root, workspace } = await fakeWorkspace("0123456789"); // 10 bytes
  context.after(() => rmRoot(root));
  await assert.rejects(
    () => patchBinary(workspace, "sample.bin", [{ offset: 8, bytes: "414243" }]), // 8+3 > 10
    /overruns the file size/,
  );
  await assert.rejects(() => patchBinary(workspace, "sample.bin", []), /at least one patch/);
  await assert.rejects(
    () => patchBinary(workspace, "sample.bin", [{ offset: -1, bytes: "41" }]),
    /non-negative integer/,
  );
});

test("binary.patch honors a caller-chosen writable outputPath", async (context) => {
  const { root, workspace } = await fakeWorkspace("HELLO-WORLD");
  context.after(() => rmRoot(root));
  const result = await patchBinary(workspace, "sample.bin", [{ offset: 0, bytes: "4a" }], "exports/deep/patched.bin");
  assert.equal(result.patchedPath, path.join("exports", "deep", "patched.bin").split("/").join(path.sep));
  const patched = await readFile(path.join(workspace.root, "exports", "deep", "patched.bin"));
  assert.equal(patched.toString("utf8").slice(0, 1), "J");
});

test("binary.patch live: patch a printed string and confirm the behavior change", { timeout: 90_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the print-string fixture");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-patch-live-"));
  context.after(() => rmRoot(root));
  const src = path.join(root, "printstr.c");
  await writeFile(src, '#include <stdio.h>\nint main(void){printf("UNPATCHED!\\n");return 0;}\n');
  const exe = path.join(root, "printstr.exe");
  const cc = spawnSync("gcc", ["-O0", "-o", exe, src], { encoding: "utf8" });
  assert.equal(cc.status, 0, cc.stderr.slice(0, 300));

  const workspace = await Workspace.create(root);
  const buf = await readFile(exe);
  const offset = buf.indexOf(Buffer.from("UNPATCHED!"));
  assert.ok(offset >= 0, "the UNPATCHED! literal must be present in the compiled binary");

  const operation = operations.find((entry) => entry.id === "binary.patch");
  const result = await operation.execute(
    { path: "printstr.exe", patches: [{ offset, bytes: Buffer.from("PATCHED!!").toString("hex") }] },
    { workspace },
  );
  assert.equal(result.patchesApplied, 1);
  assert.notEqual(result.originalSha256, result.patchedSha256);

  // Run the patched copy — its behavior changed.
  const patchedRun = spawnSync(path.join(workspace.root, result.patchedPath), [], { encoding: "utf8" });
  assert.equal(patchedRun.status, 0, patchedRun.stderr.slice(0, 300));
  assert.match(patchedRun.stdout, /PATCHED!!/);
  assert.doesNotMatch(patchedRun.stdout, /UNPATCHED/);

  // The original is untouched and still prints UNPATCHED!.
  const origRun = spawnSync(exe, [], { encoding: "utf8" });
  assert.match(origRun.stdout, /UNPATCHED!/);
});
