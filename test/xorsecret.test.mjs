import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { disassemble } from "../dist/core/analyzer.js";
import { extractStrings } from "../dist/core/strings.js";
import { Workspace } from "../dist/core/workspace.js";

const SECRET = "minusone-xor-gate-7f3a";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}

async function compileFixture(context) {
  const repository = path.resolve(".");
  if (process.env.MINUSONE_SKIP_XOR_FIXTURE === "1") return null;
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-xor-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const binary = path.join(root, "xorsecret.exe");
  const compilation = await run(
    "gcc",
    ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "xorsecret.c")],
    { cwd: repository, env: process.env },
  );
  if (compilation.exitCode !== 0) {
    await rm(root, { recursive: true, force: true });
    return null;
  }
  return { root, binary, workspace: await Workspace.create(root) };
}

test("xor fixture: the access phrase is not recoverable from string dumps", { timeout: 120_000 }, async (context) => {
  const fixture = await compileFixture(context);
  assert.ok(fixture, "gcc is required for this test (set MINUSONE_SKIP_XOR_FIXTURE=1 to skip)");

  const dumped = await extractStrings(fixture.workspace, "xorsecret.exe", { minLength: 5, limit: 2000 });
  const values = dumped.strings.map((entry) => entry.value);
  for (const value of values) {
    assert.ok(!value.includes(SECRET), "plaintext secret leaked into the binary");
  }
  assert.ok(values.some((value) => value.includes("usage: xorsecret")), "banner string should remain visible");
  assert.ok(values.some((value) => value.includes("access granted")), "result strings should remain visible");
});

test("xor fixture: the decode loop and encoded bytes are visible to static analysis", { timeout: 120_000 }, async (context) => {
  const fixture = await compileFixture(context);
  assert.ok(fixture, "gcc is required for this test (set MINUSONE_SKIP_XOR_FIXTURE=1 to skip)");

  const decode = await disassemble(fixture.workspace, "xorsecret.exe", { symbol: "decode" });
  assert.equal(decode.exitCode, 0, decode.stderr);
  assert.match(decode.stdout, /xor/i, "the decode loop should show the XOR instruction");
  assert.match(decode.stdout, /0x5a/i, "the single-byte key constant should appear");

  const rdata = await disassemble(fixture.workspace, "xorsecret.exe", { section: ".rdata" });
  assert.equal(rdata.exitCode, 0, rdata.stderr);
  assert.match(rdata.stdout, /3733342f/, "the encoded byte run should be dumpable from .rdata");

  await assert.rejects(
    () => disassemble(fixture.workspace, "xorsecret.exe", { section: ".rdata", symbol: "decode" }),
    /cannot be combined/,
  );
});

test("xor fixture: the binary accepts the decoded phrase at runtime", { timeout: 120_000 }, async (context) => {
  const fixture = await compileFixture(context);
  assert.ok(fixture, "gcc is required for this test (set MINUSONE_SKIP_XOR_FIXTURE=1 to skip)");

  const granted = await run(fixture.binary, [SECRET], { env: process.env });
  assert.equal(granted.exitCode, 0);
  assert.match(granted.stdout, /access granted/);

  const denied = await run(fixture.binary, ["wrong-phrase"], { env: process.env });
  assert.equal(denied.exitCode, 1);
  assert.match(denied.stdout, /access denied/);
});
