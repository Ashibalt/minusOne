/**
 * Symbolic plane tests: argument validation, the docker contract, and —
 * when the symbolic image is built — live angr solve (a real crackme
 * fixture whose key the solver must find) and claripy MBA simplification.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { symbolicSimplify, symbolicSolve } from "../dist/core/symbolic.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function dockerImageExists(image) {
  try {
    execFileSync("docker", ["image", "inspect", image], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

const SYMBOLIC_IMAGE = "minusone/symbolic:angr9.3.3";

// A validator whose check the solver can cross: accepted iff the byte sum
// equals 0x4F ('O'). (A multiplication like acc*7+3==550 makes gcc fold the
// check into a modular-inverse constant whose target sum is ~3 billion —
// unsolvable for short argv; keep the fixture honest.)
const SOLVE_SOURCE = `
#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage: sol KEY"); return 1; }
    const char *key = argv[1];
    uint32_t acc = 0;
    for (const char *p = key; *p; p++) acc += (uint32_t)*p;
    if (acc == 0x4F) {
        puts("VALID");
        return 0;
    }
    puts("INVALID");
    return 1;
}
`;

test("symbolic.solve validates its arguments before spawning anything", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sym-"));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), "MZ");
  await assert.rejects(
    () => symbolicSolve(workspace, "s.exe", { target: "   " }),
    /target is required/,
  );
  await rmRoot(root);
});

test("symbolic.simplify validates expression and vars", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sym-"));
  const workspace = await Workspace.create(root);
  await assert.rejects(() => symbolicSimplify(workspace, { expression: "", vars: ["x"] }), /expression is required/);
  await assert.rejects(() => symbolicSimplify(workspace, { expression: "x+1", vars: [] }), /vars is required/);
  await assert.rejects(
    () => symbolicSimplify(workspace, { expression: "x+1", vars: ["not a name!"] }),
    /vars is required/,
  );
  await rmRoot(root);
});

test("symbolic operations exist in the table with honest contracts", () => {
  const solve = operations.find((entry) => entry.id === "symbolic.solve");
  assert.ok(solve, "symbolic.solve exists");
  assert.match(solve.description, /never executes on the host/);
  assert.match(solve.description, /VERIFY/);
  const simplify = operations.find((entry) => entry.id === "symbolic.simplify");
  assert.ok(simplify, "symbolic.simplify exists");
  assert.match(simplify.description, /PROVE/i);
  assert.match(simplify.description, /candidate/);
});

test("symbolic.simplify live: MBA proven equal to the guessed form; wrong guess refuted", { timeout: 300_000 }, async (context) => {
  if (!dockerImageExists(SYMBOLIC_IMAGE)) context.skip("needs the symbolic docker image (npm run providers:build)");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sym-live-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  const proven = await symbolicSimplify(workspace, {
    expression: "(x ^ y) + 2*(x & y)",
    vars: ["x", "y"],
    bits: 32,
    candidate: "x + y",
  });
  assert.equal(proven.status, "ok", proven.error ?? "");
  assert.equal(proven.candidateEquivalent, true, "z3 ForAll proves the MBA wall equals x + y");

  const refuted = await symbolicSimplify(workspace, {
    expression: "(x ^ y) + 2*(x & y)",
    vars: ["x", "y"],
    bits: 32,
    candidate: "x - y",
  });
  assert.equal(refuted.status, "ok", refuted.error ?? "");
  assert.equal(refuted.candidateEquivalent, false, "a wrong guess is REFUTED, not accepted");
});

test("symbolic.solve live: angr finds the key of a real crackme fixture", { timeout: 600_000 }, async (context) => {
  if (!dockerImageExists(SYMBOLIC_IMAGE)) context.skip("needs the symbolic docker image");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sym-solve-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "sol.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, "-x", "c", "-"], { input: SOLVE_SOURCE });
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);

  // Find the VALID branch address inside main: the lea loading the "VALID"
  // string sits right after the comparison's jne. gcc folds acc*7+3==550
  // into a single cmp against a magic constant — the solver still has to
  // cross the loop that accumulates argv[1] bytes.
  const stdout = execFileSync("objdump", ["-d", "-M", "intel", binary], { maxBuffer: 16 * 1024 * 1024 }).toString();
  const mainBody = stdout
    .split(/\r?\n/)
    .slice(stdout.split(/\r?\n/).findIndex((line) => /<main>:/.test(line)))
    .slice(0, 60)
    .join("\n");
  const validLea = /^\s*([0-9a-f]+):\s+48 8d 05.*lea\s+rax,\[rip\+\S+\]\s+# \S+ <\.rdata\+0xf>/m.exec(mainBody);
  assert.ok(validLea, "objdump shows the VALID lea in main");
  const targetAddress = `0x${validLea[1]}`;

  const result = await symbolicSolve(workspace, "sol.exe", {
    target: targetAddress,
    args: ["SYMBOL"],
    maxStates: 500,
    timeoutSeconds: 240,
  });
  assert.equal(result.status, "ok", result.error ?? "");
  assert.ok(result.solutions.length > 0, "the solver found at least one accepted input");
  // Verify the solution REALLY passes the check: sum(key bytes) == 0x4F.
  const key = result.solutions[0].argv ?? "";
  const sum = [...key].reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  assert.equal(sum, 0x4F, `solution ${JSON.stringify(key)} must satisfy the validator`);
});

test("symbolic.solve refuses an unknown target symbol honestly", { timeout: 300_000 }, async (context) => {
  if (!dockerImageExists(SYMBOLIC_IMAGE)) context.skip("needs the symbolic docker image");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sym-err-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "sol.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, "-x", "c", "-"], { input: SOLVE_SOURCE });
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);
  const result = await symbolicSolve(workspace, "sol.exe", { target: "no_such_function" });
  assert.equal(result.status, "error");
  assert.match(result.error, /symbol not found/);
});
