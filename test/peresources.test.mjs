import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { parsePeResources } from "../dist/core/peresources.js";
import { Workspace } from "../dist/core/workspace.js";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
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
    child.once("error", () => resolve({ exitCode: -1, stdout, stderr }));
    child.once("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}

function commandAvailable(command) {
  const probe = spawnSync(command, ["--version"], { stdio: "ignore", shell: false });
  return probe.error === undefined && probe.status === 0;
}

async function compileFixture(context) {
  if (!commandAvailable("gcc") || !commandAvailable("windres")) return null;
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-peres-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const object = path.join(root, "versioninfo.res.o");
  const resources = await run(
    "windres",
    [path.join(repository, "test", "fixtures", "versioninfo.rc"), "-O", "coff", "-o", object],
    { cwd: repository },
  );
  if (resources.exitCode !== 0) return null;
  const binary = path.join(root, "versioninfo.exe");
  const compilation = await run(
    "gcc",
    ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "versioninfo.c"), object],
    { cwd: repository },
  );
  if (compilation.exitCode !== 0) return null;
  return { root, workspace: await Workspace.create(root) };
}

test("pe.resources parses version info, strings, translation, and manifest", { timeout: 120_000 }, async (context) => {
  const fixture = await compileFixture(context);
  assert.ok(fixture, "gcc and windres are required for this test");

  const report = await parsePeResources(fixture.workspace, "versioninfo.exe");
  assert.equal(report.truncated, false);

  const version = report.types.find((entry) => entry.typeId === 16);
  assert.ok(version, "the version resource type is listed");
  assert.equal(version.typeName, "version");
  assert.equal(version.entryCount, 1);
  const manifest = report.types.find((entry) => entry.typeId === 24);
  assert.ok(manifest, "the manifest resource type is listed");
  assert.equal(manifest.typeName, "manifest");

  assert.ok(report.versionInfo, "version info was extracted");
  assert.equal(report.versionInfo.fileVersion, "1.2.3.4");
  assert.equal(report.versionInfo.productVersion, "5.6.7.8");
  assert.equal(report.versionInfo.strings.CompanyName, "MinusOne Labs");
  assert.equal(report.versionInfo.strings.OriginalFilename, "versioninfo-fixture.exe");
  assert.equal(report.versionInfo.strings.ProductVersion, "5.6.7.8-rc1");
  assert.deepEqual(report.versionInfo.translations, ["0x0409:0x4b0"]);

  assert.ok(report.manifestPreview !== null, "manifest text was extracted");
  assert.match(report.manifestPreview, /assemblyIdentity/);
  assert.match(report.manifestPreview, /MinusOne\.VersionInfoFixture/);
  assert.equal(report.manifestTruncated, false);
});

test("pe_resources operation renders bounded output and rejects non-PE files", { timeout: 120_000 }, async (context) => {
  const operation = operations.find((entry) => entry.id === "pe.resources");
  assert.ok(operation, "pe.resources operation exists");
  assert.equal(operation.toolName, "pe_resources");

  const fixture = await compileFixture(context);
  assert.ok(fixture, "gcc and windres are required for this test");
  await writeFile(path.join(fixture.root, "notape.bin"), "plain text, not a PE");

  const result = await operation.execute({ path: "versioninfo.exe" }, { workspace: fixture.workspace });
  assert.equal(result.types.length, 2);
  assert.equal(result.versionInfo.strings.FileDescription, "minusone version-info fixture");
  assert.ok(typeof result.manifestPreview === "string");
  assert.equal(result.manifestTruncated, false);
  assert.equal(result.truncated, false);

  await assert.rejects(
    () => operation.execute({ path: "notape.bin" }, { workspace: fixture.workspace }),
    /requires a PE file/,
  );
});
