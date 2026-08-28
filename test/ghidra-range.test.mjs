/**
 * function.decompile.range tests: argument validation, the Ghidra range
 * export (functions intersecting the range, disassembly fallback), and
 * cache behavior. The live test needs docker (minusone/ghidra) or a local
 * Ghidra headless — it self-skips otherwise.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runGhidraAnalysis } from "../dist/core/ghidra.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const RANGE_SOURCE = `
#include <string.h>
#include <stdint.h>

static uint32_t round_a(uint32_t v) { return (v << 5) | (v >> 27); }
static uint32_t round_b(uint32_t v) { return v ^ 0x9E3779B9u; }
static uint32_t mix(uint32_t a, uint32_t b) { return round_a(a) + round_b(b); }

uint32_t small_checker(const char *input) {
    uint32_t acc = 0;
    for (const char *p = input; *p; p++) {
        acc = mix(acc, (uint32_t)*p);
    }
    return acc;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return (int)small_checker(argv[1]);
}
`;

async function compileFixture(root, name, source) {
  const sourcePath = path.join(root, `${name}.c`);
  await writeFile(sourcePath, source);
  const binary = path.join(root, `${name}.exe`);
  try {
    execFileSync("gcc", ["-O0", "-g", "-o", binary, sourcePath]);
    return binary;
  } catch {
    return null;
  }
}

function dockerAvailable() {
  try {
    execFileSync("docker", ["images", "--format", "{{.Repository}}"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

test("runGhidraAnalysis range mode validates its arguments", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-range-"));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), "MZ");
  await assert.rejects(
    () => runGhidraAnalysis(workspace, "s.exe", { rangeStart: "0x401000" }),
    /both rangeStart and rangeEnd/,
  );
  await assert.rejects(
    () => runGhidraAnalysis(workspace, "s.exe", { rangeStart: "0x401000", rangeEnd: "0x400000" }),
    /before rangeStart/,
  );
  await assert.rejects(
    () => runGhidraAnalysis(workspace, "s.exe", { rangeStart: "nothex", rangeEnd: "0x400000" }),
    /decimal or hexadecimal/,
  );
  await rmRoot(root);
});

test("function.decompile.range operation exists with honest parameters", () => {
  const operation = operations.find((entry) => entry.id === "function.decompile.range");
  assert.ok(operation, "function.decompile.range exists");
  assert.deepEqual(operation.parameters.required, ["path", "rangeStart", "rangeEnd"]);
  assert.match(operation.description, /megaprocedure/i);
  assert.match(operation.description, /disassemblyFallback|disassembly/i);
});

test("function.decompile.range live: exports functions intersecting the range with fallback listing", { timeout: 600_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-range-live-"));
  context.after(() => rmRoot(root));
  const binary = await compileFixture(root, "rangecheck", RANGE_SOURCE);
  if (binary === null) context.skip("needs gcc");
  if (!dockerAvailable() && !existsSync("C:/ghidra")) context.skip("needs docker ghidra or local ghidra");
  const workspace = await Workspace.create(root);

  // Locate the .text VAs first: the range must be expressed in image VAs.
  // A tiny PE from gcc defaults to base 0x140000000; find functions via a
  // full decompile of this small binary first (cheap), then range around
  // small_checker.
  const full = await runGhidraAnalysis(workspace, "rangecheck.exe", { maxFunctions: 10 });
  assert.equal(full.command.exitCode, 0, full.command.stderr.slice(0, 400));
  // A3: the second analysis over the same sample must REUSE the per-sample
  // project (-process, no re-import/re-analysis) instead of -import -overwrite.
  const reused = await runGhidraAnalysis(workspace, "rangecheck.exe", { maxFunctions: 10 });
  assert.equal(reused.command.exitCode, 0, reused.command.stderr.slice(0, 400));
  const reuseArgs = reused.command.args;
  assert.ok(reuseArgs.includes("-process"), `second call uses -process (got ${reuseArgs.join(" ").slice(0, 120)})`);
  assert.ok(reuseArgs.includes("-noanalysis"), "second call skips re-analysis");
  assert.ok(!reuseArgs.includes("-import"), "second call does NOT re-import");
  assert.ok((reused.report.functions ?? []).length > 0, "reused project still exports functions");
  const fullReport = full.report;
  const functions = fullReport.functions ?? [];
  // static round/mix helpers may inline at -O0 they do not; pick any
  // decompiled non-main function — the range must re-export exactly it.
  const checker = functions.find((fn) => (fn.decompiledCode ?? "").includes("0x9e3779b9"))
    ?? functions.find((fn) => fn.name === "mix" || fn.name === "round_a" || fn.name === "small_checker")
    ?? functions.find((fn) => !/main|_startup|entry/i.test(fn.name ?? "") && (fn.decompiledCode ?? "").length > 0);
  assert.ok(checker, `a non-main decompiled function exists (got ${functions.map((fn) => fn.name).join(", ")})`);
  const entry = Number.parseInt(checker.entryPoint, 16);

  // A range tightly around small_checker must export exactly the
  // intersecting functions, decompiled (this fixture is small, so the
  // decompile completes — the fallback path is exercised by megaprocedure
  // fixtures at combat time; here we assert the range plumbing).
  const rangeResult = await runGhidraAnalysis(workspace, "rangecheck.exe", {
    rangeStart: `0x${(entry - 0x40).toString(16)}`,
    rangeEnd: `0x${(entry + 0x140).toString(16)}`,
    maxFunctions: 10,
  });
  assert.equal(rangeResult.command.exitCode, 0, rangeResult.command.stderr.slice(0, 400));
  const report = rangeResult.report;
  assert.equal(report.rangeMode, true, "the report flags range mode");
  assert.ok(Array.isArray(report.functions), "functions array present");
  assert.ok(report.functions.length >= 1, "the range intersects at least the checker function");
  assert.ok(
    report.functions.every((fn) => fn.rangeOverlap && typeof fn.rangeOverlap.bytes === "number"),
    "every function carries its range overlap",
  );
  const inRange = report.functions.find((fn) => fn.entryPoint === checker.entryPoint);
  assert.ok(inRange, "small_checker is among the intersecting functions");
  assert.ok((inRange.decompiledCode ?? "").length > 0 || (inRange.disassemblyFallback ?? "").length > 0,
    "each function yields decompiled code or the disassembly fallback");
  assert.ok(report.functionsIntersecting >= report.functions.length, "intersecting count is reported");
});

test("computeFallbackSlices covers a megaprocedure with overlapping windows", async () => {
  const { computeFallbackSlices } = await import("../dist/core/operations.js");
  // 7053-byte function (a real-world flattened megaprocedure): one window.
  const single = computeFallbackSlices(0x140005170, 7053);
  assert.equal(single.length, 1);
  assert.equal(single[0].rangeStart, "0x140005170");
  assert.equal(single[0].rangeEnd, "0x140006cfc");
  // 53 KB function: overlapping 8 KiB windows, coverage is complete.
  const many = computeFallbackSlices(0x1000, 53_000);
  assert.ok(many.length >= 7, `expected ~7+ windows, got ${many.length}`);
  let previousEnd = null;
  for (const slice of many) {
    const start = Number.parseInt(slice.rangeStart, 16);
    const end = Number.parseInt(slice.rangeEnd, 16);
    assert.ok(end > start, "window is non-empty");
    if (previousEnd !== null) assert.ok(start < previousEnd, "consecutive windows overlap");
    previousEnd = end;
  }
  assert.ok(previousEnd >= 0x1000 + 53_000 - 1, "the last window covers the function tail");
  assert.deepEqual(computeFallbackSlices(Number.NaN, 100), []);
  assert.deepEqual(computeFallbackSlices(0x1000, 0), []);
});

test("function.decompile live: a whole-function failure auto-falls back to range slices", { timeout: 900_000 }, async (context) => {
  // Runs against a local obfuscated sample supplied by the owner through
  // MINUSONE_TEST_LIVE_SAMPLE — the sample never ships with the repo.
  const liveSample = process.env.MINUSONE_TEST_LIVE_SAMPLE ?? "";
  if (liveSample === "" || !existsSync(liveSample)) {
    context.skip("needs MINUSONE_TEST_LIVE_SAMPLE pointing at a local sample");
    return;
  }
  if (!dockerAvailable() && !existsSync("C:/ghidra")) {
    context.skip("needs docker ghidra or local ghidra");
    return;
  }
  const operation = operations.find((entry) => entry.id === "function.decompile");
  assert.ok(operation);
  const workspace = await Workspace.create(process.cwd());
  const jobs = [];
  const registry = {
    start(spec) {
      const id = `a4-${jobs.length}`;
      jobs.push(spec);
      return id;
    },
  };
  await operation.execute(
    { path: liveSample, addresses: ["0x140005170"], timeoutSeconds: 600 },
    { workspace, jobs: registry },
  );
  const outcome = await jobs[0].run().done;
  assert.equal(outcome.status, "completed", outcome.detail ?? "");
  // The output may carry a trailing "[cache: reused artifact ...]" line.
  const marker = outcome.output.indexOf("\n[cache: reused artifact");
  const jsonPart = marker >= 0 ? outcome.output.slice(0, marker) : outcome.output;
  const parsed = JSON.parse(jsonPart);
  const fn = parsed.summaryFunctions.find((entry) => entry.entryPoint === "140005170");
  assert.ok(fn, "the monster function is in the summary");
  assert.equal(fn.fallback, "sliced");
  assert.ok(fn.sliceCount >= 1);
});
