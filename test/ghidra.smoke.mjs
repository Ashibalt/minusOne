import assert from "node:assert/strict";
import { mkdtemp, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

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

test("Ghidra Docker backend imports and saves a real PE", { timeout: 600_000 }, async (context) => {
  const repository = path.resolve(".");
  const workspace = await mkdtemp(path.join(os.tmpdir(), "minusone-ghidra-"));
  const binary = path.join(workspace, "hello.exe");
  context.after(() => rm(workspace, { recursive: true, force: true }));

  const compilation = await run(
    "gcc",
    ["-O0", "-g", "-o", binary, path.join(repository, "test", "fixtures", "hello.c")],
    { cwd: repository, env: process.env },
  );
  assert.equal(compilation.exitCode, 0, compilation.stderr || compilation.stdout);

  const image = process.env.MINUSONE_GHIDRA_IMAGE ?? "minusone/ghidra:12.1.2";
  const analysis = await run(
    process.execPath,
    [path.join(repository, "dist", "cli", "main.js"), "ghidra", "hello.exe", "--workspace", workspace],
    {
      cwd: repository,
      env: { ...process.env, MINUSONE_GHIDRA_IMAGE: image },
    },
  );
  assert.equal(analysis.exitCode, 0, analysis.stderr || analysis.stdout);

  const result = JSON.parse(analysis.stdout);
  assert.equal(result.backend, "docker");
  assert.equal(result.command.exitCode, 0);
  assert.equal(result.command.timedOut, false);
  assert.match(result.command.stdout, /REPORT: Analysis succeeded/);
  assert.match(result.command.stdout, /REPORT: Save succeeded/);
  assert.equal(result.report.schemaVersion, 2);
  assert.equal(result.report.program.executableFormat, "Portable Executable (PE)");
  assert.ok(result.report.functionsExported > 0 && result.report.functionsExported <= 40);
  assert.ok(result.report.functions.every((entry) =>
    entry.decompiledCode === null || entry.decompiledCode.length <= 2_500
  ));
  assert.ok(result.report.functions.some((entry) => entry.decompilationCompleted));

  const projectRoot = path.join(workspace, ".minusone", "ghidra");
  assert.equal((await stat(path.join(projectRoot, `${result.projectName}.gpr`))).isFile(), true);
  assert.equal((await stat(path.join(projectRoot, `${result.projectName}.rep`))).isDirectory(), true);
});
