/**
 * E13 tests: strings.find is the ONE string/find plane with four modes;
 * binary_find / binary_search / strings_extract / strings_extract_deep stay
 * as working aliases. The core checks: mode routing behaves IDENTICALLY to
 * the alias for the same input, and mode/needle/kind validation is honest.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";

async function fixtureWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sfind-"));
  // A fixture with a marker string at a known spot and an MZ header.
  const content = Buffer.concat([
    Buffer.from("MZ"),
    Buffer.alloc(1024, 0x41),
    Buffer.from("minusone-marker-string\0"),
    Buffer.alloc(512, 0x42),
    Buffer.from([0xde, 0xad, 0xbe, 0xef]),
  ]);
  await writeFile(path.join(root, "sample.exe"), content);
  return { root, workspace: await Workspace.create(root) };
}

function findOperation(id) {
  const operation = operations.find((entry) => entry.id === id);
  assert.ok(operation, `${id} exists`);
  return operation;
}

test("strings.find exists with the four modes; all four aliases remain registered", () => {
  const unified = findOperation("strings.find");
  assert.equal(unified.toolName, "strings_find");
  assert.deepEqual(unified.parameters.properties.mode.enum, ["leading-window", "whole-file", "plain-strings", "deep-floss"]);
  assert.deepEqual(unified.parameters.required, ["path", "mode"]);

  // The aliases keep their old toolNames (no client breakage) and say so.
  const expectations = [
    ["binary.find", "binary_find", "leading-window"],
    ["binary.search", "binary_search", "whole-file"],
    ["strings.extract", "strings_extract", "plain-strings"],
    ["strings.extract.deep", "strings_extract_deep", "deep-floss"],
  ];
  for (const [id, toolName, mode] of expectations) {
    const alias = findOperation(id);
    assert.equal(alias.toolName, toolName);
    assert.match(alias.description, new RegExp(`Alias of strings_find mode '${mode}'`), `${id} declares the alias`);
  }
});

test("mode validation: search modes require needle, extract modes reject it, kind api/symbol is leading-window only", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");

  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "leading-window" }, { workspace }),
    /mode 'leading-window' requires needle/,
  );
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "whole-file" }, { workspace }),
    /mode 'whole-file' requires needle/,
  );
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "plain-strings", needle: "x" }, { workspace }),
    /mode 'plain-strings' does not take a needle/,
  );
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "deep-floss", needle: "x" }, { workspace }),
    /mode 'deep-floss' does not take a needle/,
  );
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "whole-file", needle: "x", kind: "api" }, { workspace }),
    /kind 'api' exists only in leading-window mode/,
  );
  await rm(root, { recursive: true, force: true });
});

test("leading-window mode behaves identically to the binary_find alias", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");
  const alias = findOperation("binary.find");

  const viaUnified = await unified.execute({ path: "sample.exe", mode: "leading-window", needle: "minusone-marker" }, { workspace });
  const viaAlias = await alias.execute({ path: "sample.exe", needle: "minusone-marker" }, { workspace });
  assert.equal(viaUnified.hitCount, viaAlias.hitCount);
  assert.deepEqual(
    viaUnified.hits.map((hit) => hit.offset ?? hit.fileOffset).sort(),
    viaAlias.hits.map((hit) => hit.offset ?? hit.fileOffset).sort(),
  );

  // kind 'bytes' works in the unified search mode too.
  const bytesHit = await unified.execute({ path: "sample.exe", mode: "leading-window", needle: "deadbeef", kind: "bytes" }, { workspace });
  assert.ok(bytesHit.hitCount >= 1, "hex needle found in leading-window mode");
  await rm(root, { recursive: true, force: true });
});

test("whole-file mode behaves identically to the binary_search alias", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");
  const alias = findOperation("binary.search");

  const viaUnified = await unified.execute({ path: "sample.exe", mode: "whole-file", needle: "minusone-marker" }, { workspace });
  const viaAlias = await alias.execute({ path: "sample.exe", needle: "minusone-marker" }, { workspace });
  assert.equal(viaUnified.hitCount, viaAlias.hitCount);
  assert.equal(viaUnified.scanComplete, viaAlias.scanComplete);
  assert.deepEqual(
    viaUnified.hits.map((hit) => hit.offset).sort(),
    viaAlias.hits.map((hit) => hit.offset).sort(),
  );
  await rm(root, { recursive: true, force: true });
});

test("plain-strings mode behaves identically to the strings_extract alias", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");
  const alias = findOperation("strings.extract");

  const viaUnified = await unified.execute({ path: "sample.exe", mode: "plain-strings", minLength: 8 }, { workspace });
  const viaAlias = await alias.execute({ path: "sample.exe", minLength: 8 }, { workspace });
  assert.deepEqual(
    viaUnified.strings.map((entry) => entry.value),
    viaAlias.strings.map((entry) => entry.value),
  );
  assert.ok(viaUnified.strings.some((entry) => (entry.value ?? "").includes("minusone-marker-string")));
  await rm(root, { recursive: true, force: true });
});

test("deep-floss mode requires a job registry, honestly", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "deep-floss" }, { workspace }),
    /requires a background job registry/,
  );
  // With a registry the mode submits the same job shape as the alias.
  let spec = null;
  const jobs = { start(received) { spec = received; return "job-1"; } };
  const result = await unified.execute({ path: "sample.exe", mode: "deep-floss" }, { workspace, jobs });
  assert.equal(result.status, "running");
  assert.equal(spec.kind, "floss");
  await rm(root, { recursive: true, force: true });
});

test("deep-floss mode caps minLength at 32 (FLOSS convention)", async () => {
  const { root, workspace } = await fixtureWorkspace();
  const unified = findOperation("strings.find");
  await assert.rejects(
    () => unified.execute({ path: "sample.exe", mode: "deep-floss", minLength: 64 }, { workspace, jobs: { start: () => "x" } }),
    /caps minLength at 32/,
  );
  await rm(root, { recursive: true, force: true });
});
