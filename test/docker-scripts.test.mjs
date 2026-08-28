// Docker-level smoke tests for the three runner scripts (R3-4).
//
// Every other test file drives the TS wrappers; these drive the docker
// scripts THEMSELVES — the wrapper↔script seam had zero contract coverage,
// which is how the emu-run.py UnboundLocalError (R3-1) lived under a green
// test suite. The contract under test:
//   1. a golden job answers well-formed JSON on stdout (exit 0);
//   2. a BAD job answers a structured {"status":"error"} — never a Python
//      traceback, never a lost answer.
// Each test skips when its docker image is absent (CI without backends).

import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { rmRoot } from "./helpers.mjs";

function hasImage(image) {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}:{{.Tag}}", image], { encoding: "utf8" });
  return probe.status === 0 && probe.stdout.trim().includes(image);
}

function dockerRun(args, { stdinData } = {}) {
  return spawnSync("docker", args, {
    encoding: "utf8",
    input: stdinData === undefined ? undefined : Buffer.from(stdinData, "utf8"),
    timeout: 120_000,
  });
}

function parseStdoutJson(result, label) {
  assert.equal(result.status, 0, `${label}: docker run exited ${result.status}\nstderr: ${(result.stderr || "").slice(0, 400)}`);
  const stdout = result.stdout.trim();
  assert.ok(stdout.startsWith("{"), `${label}: stdout is not JSON (first 120 chars): ${stdout.slice(0, 120)}\nstderr: ${(result.stderr || "").slice(0, 400)}`);
  return JSON.parse(stdout);
}

// ---- emu-run.py (minusone/unicorn) --------------------------------------------

test("emu-run.py docker-level: golden job answers JSON with registers and memory", { timeout: 180_000 }, (context) => {
  if (!hasImage("minusone/unicorn:2.1.3")) context.skip("needs the minusone/unicorn image");
  // mov eax,0x2a; ret (x86) — the smallest job that touches a register.
  const result = dockerRun([
    "run", "--rm", "--network", "none",
    "-e", 'MINUSONE_EMU_JOB={"arch":"x86","codeHex":"b82a000000c3","until":"0x1000ff"}',
    "--entrypoint", "python", "minusone/unicorn:2.1.3",
    "/opt/minusone/emu-run.py",
  ]);
  const parsed = parseStdoutJson(result, "golden job");
  assert.equal(parsed.status, "ok", parsed.error ?? "emulation failed");
  assert.equal(parsed.registers.eax, "0x2a", "register visible in the final snapshot");
  assert.ok(Array.isArray(parsed.memory), "memory export array present");
});

test("emu-run.py docker-level: bad hex answers structured error, not a traceback", { timeout: 180_000 }, (context) => {
  if (!hasImage("minusone/unicorn:2.1.3")) context.skip("needs the minusone/unicorn image");
  const result = dockerRun([
    "run", "--rm", "--network", "none",
    "-e", 'MINUSONE_EMU_JOB={"arch":"x86","codeHex":"ZZZ"}',
    "--entrypoint", "python", "minusone/unicorn:2.1.3",
    "/opt/minusone/emu-run.py",
  ]);
  const parsed = parseStdoutJson(result, "bad hex");
  assert.equal(parsed.status, "error");
  assert.match(parsed.error, /hex/i);
  const stderr = result.stderr.toString();
  assert.ok(!stderr.includes("Traceback"), `python traceback leaked:\n${stderr.slice(0, 500)}`);
});

test("emu-run.py docker-level: non-JSON job answers structured error", { timeout: 180_000 }, (context) => {
  if (!hasImage("minusone/unicorn:2.1.3")) context.skip("needs the minusone/unicorn image");
  const result = dockerRun([
    "run", "--rm", "--network", "none",
    "-e", "MINUSONE_EMU_JOB=not json at all",
    "--entrypoint", "python", "minusone/unicorn:2.1.3",
    "/opt/minusone/emu-run.py",
  ]);
  const parsed = parseStdoutJson(result, "bad json");
  assert.equal(parsed.status, "error");
  assert.match(parsed.error, /JSON/i);
});

// ---- symbolic-run.py (minusone/symbolic) ---------------------------------------

test("symbolic-run.py docker-level: simplify golden job proves x+y equivalence", { timeout: 300_000 }, (context) => {
  if (!hasImage("minusone/symbolic:angr9.3.3")) context.skip("needs the minusone/symbolic image");
  const result = dockerRun([
    "run", "--rm", "--network", "none", "--cpus", "2", "--memory", "3g", "--interactive",
    "--entrypoint", "python", "minusone/symbolic:angr9.3.3",
    "/opt/minusone/symbolic-run.py",
  ], { stdinData: JSON.stringify({ mode: "simplify", expression: "(x ^ y) + 2*(x & y)", vars: ["x", "y"], bits: 32, candidate: "x + y" }) });
  const parsed = parseStdoutJson(result, "simplify golden");
  assert.equal(parsed.status, "ok", JSON.stringify(parsed).slice(0, 300));
  assert.equal(parsed.candidateEquivalent, true, "z3 ForAll proof of the classic MBA identity");
});

test("symbolic-run.py docker-level: unknown mode answers structured error", { timeout: 300_000 }, (context) => {
  if (!hasImage("minusone/symbolic:angr9.3.3")) context.skip("needs the minusone/symbolic image");
  const result = dockerRun([
    "run", "--rm", "--network", "none", "--interactive",
    "--entrypoint", "python", "minusone/symbolic:angr9.3.3",
    "/opt/minusone/symbolic-run.py",
  ], { stdinData: JSON.stringify({ mode: "wat" }) });
  const parsed = parseStdoutJson(result, "unknown mode");
  assert.equal(parsed.status, "error");
  assert.match(parsed.error, /mode/);
});

// ---- pe-rebuild.py (minusone/pe-tools) -----------------------------------------

test("pe-rebuild.py docker-level: a minimal dump rebuilds and reports repairs", { timeout: 300_000 }, async (context) => {
  if (!hasImage("minusone/pe-tools:lief")) context.skip("needs the minusone/pe-tools image");
  // A minimal-but-valid PE64 (same builder as borrowlist.test.mjs's fakePe),
  // standing in for a pe-sieve dump: rebased to an ASLR-style base so the
  // rebase repair has something to do.
  const dump = Buffer.alloc(0x800, 0);
  dump.write("MZ", 0, "latin1");
  dump.writeUInt32LE(0x80, 0x3c);
  dump.write("PE\0\0", 0x80, "latin1");
  dump.writeUInt16LE(0x8664, 0x84);
  dump.writeUInt16LE(1, 0x86);
  dump.writeUInt16LE(0xf0, 0x94);
  dump.writeUInt16LE(0x20b, 0x98);
  dump.writeBigUInt64LE(0x7ff600000000n, 0x98 + 24);
  const st = 0x188;
  dump.write(".rdata", st, "latin1");
  dump.writeUInt32LE(0x400, st + 8);
  dump.writeUInt32LE(0x1000, st + 12);
  dump.writeUInt32LE(0x400, st + 16);
  dump.writeUInt32LE(0x400, st + 20);
  dump.write("unpacked-content-MARKER", 0x400, "latin1");

  const host = await mkdtemp(path.join(os.tmpdir(), "minusone-docker-pe-"));
  context.after(() => rmRoot(host));
  const dumpPath = path.join(host, "dump.exe");
  const outPath = path.join(host, "rebuilt.exe");
  await writeFile(dumpPath, dump);

  const result = dockerRun([
    "run", "--rm", "--network", "none",
    "-v", `${host.replace(/\\/g, "/")}:/work`,
    "--entrypoint", "python", "minusone/pe-tools:lief",
    "/opt/minusone/pe-rebuild.py", "/work/dump.exe", "/work/rebuilt.exe",
  ]);
  assert.equal(result.status, 0, `docker run exited ${result.status}\nstderr: ${result.stderr.toString().slice(0, 400)}`);
  const stdout = result.stdout.toString().trim();
  assert.ok(stdout.startsWith("{"), `stdout is not JSON: ${stdout.slice(0, 200)}`);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.status, "ok", JSON.stringify(parsed).slice(0, 300));
  assert.ok(parsed.repairs.length > 0, "the rebase repair is reported");
  const rebuilt = await readFile(outPath);
  assert.ok(rebuilt.length > 0x400, "rebuilt PE written");
  assert.ok(rebuilt.subarray(0, 2).toString("latin1") === "MZ", "rebuilt file is a PE");
});

test("pe-rebuild.py docker-level: garbage dump answers structured error", { timeout: 180_000 }, async (context) => {
  if (!hasImage("minusone/pe-tools:lief")) context.skip("needs the minusone/pe-tools image");
  const host = await mkdtemp(path.join(os.tmpdir(), "minusone-docker-pe2-"));
  context.after(() => rmRoot(host));
  const dumpPath = path.join(host, "garbage.exe");
  await writeFile(dumpPath, Buffer.from("this is not a PE at all, just bytes"));

  // pe-rebuild's error contract: structured JSON on stdout, exit code 2
  // (parse) or 3 (rebuild) — the non-zero exit is the script's own signal,
  // not a crash. Only a MISSING JSON answer would be a broken contract.
  const result = dockerRun([
    "run", "--rm", "--network", "none",
    "-v", `${host.replace(/\\/g, "/")}:/work`,
    "--entrypoint", "python", "minusone/pe-tools:lief",
    "/opt/minusone/pe-rebuild.py", "/work/garbage.exe", "/work/out.exe",
  ]);
  const stdout = (result.stdout || "").trim();
  assert.ok(stdout.startsWith("{"), `stdout is not JSON: ${stdout.slice(0, 200)}`);
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.status, "error");
  assert.equal(parsed.stage, "parse-dump");
  const stderr = result.stderr || "";
  assert.ok(!stderr.includes("Traceback"), `python traceback leaked:\n${stderr.slice(0, 500)}`);
});
