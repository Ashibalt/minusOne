/**
 * D12 hygiene tests: collectHygiene reports sizes + cleanable flags,
 * cleanWorkspaceHygiene empties ONLY .minusone/tmp and reports the sidecar
 * action honestly. Nothing else in .minusone may be touched.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cleanWorkspaceHygiene, collectHygiene, formatBytes } from "../dist/core/hygiene.js";
import { Workspace } from "../dist/core/workspace.js";

async function tempWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-hyg-"));
  return { root, workspace: await Workspace.create(root) };
}

test("formatBytes renders human sizes", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 MB");
  assert.equal(formatBytes(Math.floor(2.7 * 1024 ** 3)), "2.7 GB");
});

test("collectHygiene on a workspace without .minusone reports present=false", async () => {
  const { root, workspace } = await tempWorkspace();
  const hygiene = await collectHygiene(workspace);
  assert.equal(hygiene.present, false);
  assert.equal(hygiene.totalBytes, 0);
  assert.equal(hygiene.cleanableBytes, 0);
  // The sidecar probe always answers, one honest state or another.
  assert.match(hygiene.sidecar.detail, /sidecar/i);
  await rm(root, { recursive: true, force: true });
});

test("collectHygiene sizes subdirectories and flags only tmp as cleanable", async () => {
  const { root, workspace } = await tempWorkspace();
  await mkdir(path.join(root, ".minusone", "tmp", "nested"), { recursive: true });
  await writeFile(path.join(root, ".minusone", "tmp", "wheel.whl"), Buffer.alloc(4096));
  await writeFile(path.join(root, ".minusone", "tmp", "nested", "part.bin"), Buffer.alloc(1024));
  await mkdir(path.join(root, ".minusone", "outputs"), { recursive: true });
  await writeFile(path.join(root, ".minusone", "outputs", "spill.txt"), Buffer.alloc(2048));

  const hygiene = await collectHygiene(workspace);
  assert.equal(hygiene.present, true);
  assert.equal(hygiene.totalBytes, 4096 + 1024 + 2048);
  const tmp = hygiene.entries.find((entry) => entry.name === "tmp");
  const outputs = hygiene.entries.find((entry) => entry.name === "outputs");
  assert.equal(tmp.bytes, 5120);
  assert.equal(tmp.cleanable, true);
  assert.equal(outputs.bytes, 2048);
  assert.equal(outputs.cleanable, false, "spill files are analyst data — never auto-cleaned");
  assert.equal(hygiene.cleanableBytes, 5120);
  await rm(root, { recursive: true, force: true });
});

test("cleanWorkspaceHygiene empties tmp, frees its bytes, and leaves everything else", async () => {
  const { root, workspace } = await tempWorkspace();
  await mkdir(path.join(root, ".minusone", "tmp"), { recursive: true });
  await writeFile(path.join(root, ".minusone", "tmp", "wheel.whl"), Buffer.alloc(8192));
  await mkdir(path.join(root, ".minusone", "outputs"), { recursive: true });
  await writeFile(path.join(root, ".minusone", "outputs", "spill.txt"), Buffer.alloc(2048));
  await mkdir(path.join(root, ".minusone", "run"), { recursive: true });
  await writeFile(path.join(root, ".minusone", "run", "job-state.json"), "{}");

  const result = await cleanWorkspaceHygiene(workspace);
  assert.equal(result.freedBytes, 8192);
  assert.ok(result.actions.some((action) => action.includes(".minusone/tmp") && action.includes("8.0 KB")));
  assert.ok(result.actions.some((action) => /sidecar:/.test(action)), "the sidecar action is always reported");

  // tmp itself still exists but is empty; outputs and run are untouched.
  const tmpContents = await readdir(path.join(root, ".minusone", "tmp"));
  assert.deepEqual(tmpContents, []);
  const outputsContents = await readdir(path.join(root, ".minusone", "outputs"));
  assert.deepEqual(outputsContents, ["spill.txt"]);
  const runContents = await readdir(path.join(root, ".minusone", "run"));
  assert.deepEqual(runContents, ["job-state.json"]);
  await rm(root, { recursive: true, force: true });
});

test("cleanWorkspaceHygiene on an empty workspace is a honest no-op", async () => {
  const { root, workspace } = await tempWorkspace();
  const result = await cleanWorkspaceHygiene(workspace);
  assert.equal(result.freedBytes, 0);
  assert.ok(result.actions.some((action) => /nothing to clean/.test(action)));
  await rm(root, { recursive: true, force: true });
});
