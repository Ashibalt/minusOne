import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { capToolOutput, resolveMaxOutput } from "../dist/core/outputbudget.js";
import { Workspace } from "../dist/core/workspace.js";

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-budget-"));
  return { root, workspace: await Workspace.create(root) };
}

test("resolveMaxOutput defaults to 8000 and respects caller values", () => {
  assert.equal(resolveMaxOutput(undefined), 8000);
  assert.equal(resolveMaxOutput(4000), 4000);
  assert.equal(resolveMaxOutput("junk"), 8000);
  assert.equal(resolveMaxOutput(100), 256, "the floor is 256");
  assert.equal(resolveMaxOutput(50000), 50000, "the model may raise it freely");
});

test("short answers pass through whole with NO file written", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const result = await capToolOutput(fixture.workspace, "probe", "x".repeat(2500), 4000);
  assert.equal(result.truncated, false);
  assert.equal(result.text.length, 2500);
  assert.equal(result.outputFile, undefined);
  const outputs = path.join(fixture.root, ".minusone", "outputs");
  assert.equal(existsSync(outputs), false, "no outputs directory created");
});

test("long answers: first max_output chars + full text in a file + path in the answer", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const full = "A".repeat(35_000);
  const result = await capToolOutput(fixture.workspace, "strings_extract", full, 4000);
  assert.equal(result.truncated, true);
  assert.equal(result.totalChars, 35_000);
  // The model receives first-4000 + the path note; the file holds all 35K.
  assert.ok(result.text.startsWith("A".repeat(4000)));
  assert.ok(result.text.includes("full output saved to "), "the answer carries the full-output path note");
  assert.ok(result.text.includes(result.outputFile), "the answer embeds the file path");
  assert.ok(result.outputFile !== undefined);
  const saved = await readFile(path.join(fixture.root, result.outputFile), "utf8");
  assert.equal(saved.length, 35_000, "the file carries the FULL output");
});
