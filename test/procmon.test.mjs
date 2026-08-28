import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { parseProcmonTrace } from "../dist/core/procmon.js";
import { Workspace } from "../dist/core/workspace.js";

async function fixtureWorkspace(context) {
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-procmon-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await copyFile(path.join(repository, "test", "fixtures", "procmon-trace.csv"), path.join(root, "trace.csv"));
  return { root, workspace: await Workspace.create(root) };
}

test("trace.procmon summarizes processes, operations, results, and path categories", async (context) => {
  const fixture = await fixtureWorkspace(context);
  const report = await parseProcmonTrace(fixture.workspace, "trace.csv");

  assert.equal(report.parseErrors, 0, JSON.stringify(report));
  assert.equal(report.truncated, false);
  assert.equal(report.scannedEvents, 8);
  assert.equal(report.eventCount, 8);

  // Quote-aware tokenizer joined the comma-bearing process name and kept the
  // escaped quotes inside the detail intact.
  const star = report.processes.find((entry) => entry.name === "malware, sample.exe");
  assert.ok(star, "process name with a comma survived");
  assert.equal(star.pid, "5678");
  assert.equal(star.events, 5);

  const operations = Object.fromEntries(report.operations.map((entry) => [entry.operation, entry.events]));
  assert.equal(operations["WriteFile"], 1);
  assert.equal(operations["TCP Connect"], 1);
  assert.equal(operations["TCP Send"], 1);
  assert.equal(operations["Process Create"], 1);
  assert.equal(operations["RegSetValue"], 1);

  const results = Object.fromEntries(report.results.map((entry) => [entry.result, entry.events]));
  assert.equal(results["SUCCESS"], 7);
  assert.equal(results["NAME NOT FOUND"], 1);

  const categories = Object.fromEntries(report.pathCategories.map((entry) => [entry.category, entry.events]));
  assert.equal(categories["registry"], 2);
  assert.equal(categories["network"], 2);
  assert.equal(categories["filesystem"], 3);
  assert.equal(categories["process"], 1);

  const runKey = report.topPaths.find((entry) => entry.path.includes("CurrentVersion\\Run"));
  assert.ok(runKey, "registry persistence path ranks in the top paths");
  assert.equal(runKey.category, "registry");
  assert.equal(runKey.events, 2);

  assert.equal(report.timeRange.first, "10:00:01.1234567");
  assert.equal(report.timeRange.last, "10:00:06.0000000");
});

test("trace.procmon applies filters and honors the event cap", async (context) => {
  const fixture = await fixtureWorkspace(context);

  const byProcess = await parseProcmonTrace(fixture.workspace, "trace.csv", { filterProcess: "malware" });
  assert.equal(byProcess.scannedEvents, 8);
  assert.equal(byProcess.eventCount, 5);

  const byOperation = await parseProcmonTrace(fixture.workspace, "trace.csv", { filterOperation: "tcp" });
  assert.equal(byOperation.eventCount, 2);
  assert.ok(byOperation.topPaths.every((entry) => entry.category === "network"));

  const byPath = await parseProcmonTrace(fixture.workspace, "trace.csv", {
    filterProcess: "malware",
    filterPath: "CurrentVersion\\Run",
  });
  assert.equal(byPath.eventCount, 1, "only the malware RegSetValue touches the Run key");
  assert.ok(byPath.topPaths.every((entry) => entry.path.includes("CurrentVersion\\Run")));

  const capped = await parseProcmonTrace(fixture.workspace, "trace.csv", { maxEvents: 3 });
  assert.equal(capped.eventCount, 3);
  assert.equal(capped.truncated, true);
});

test("trace_procmon operation renders the report and rejects non-CSV input", async (context) => {
  const operation = operations.find((entry) => entry.id === "trace.procmon");
  assert.ok(operation, "trace.procmon operation exists");
  assert.equal(operation.toolName, "trace_procmon");
  const fixture = await fixtureWorkspace(context);
  await writeFile(path.join(fixture.root, "garbage.csv"), "hello\nworld\nnot,a,procmon,trace\n");

  const result = await operation.execute({ path: "trace.csv" }, { workspace: fixture.workspace });
  assert.equal(result.eventCount, 8);
  assert.equal(result.processes.length, 4);
  assert.ok(Array.isArray(result.topPaths));

  await assert.rejects(
    () => operation.execute({ path: "garbage.csv" }, { workspace: fixture.workspace }),
    /not a recognizable Procmon CSV export/,
  );
});

test("trace.procmon tolerates a UTF-8 BOM and CRLF line endings", async (context) => {
  const fixture = await fixtureWorkspace(context);
  const raw = await readFile(path.join(fixture.root, "trace.csv"), "utf8");
  await writeFile(path.join(fixture.root, "bom.csv"), `\uFEFF${raw.replace(/\n/g, "\r\n")}`);
  const report = await parseProcmonTrace(fixture.workspace, "bom.csv");
  assert.equal(report.parseErrors, 0);
  assert.equal(report.eventCount, 8);
});