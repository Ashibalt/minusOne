import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { DEFAULT_IMAGES } from "../dist/core/backends.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";

const OPERATION = "dumps.floss";

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-floss-dumps-"));
  await mkdir(path.join(root, "dumps"));
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "dumps-floss-1";
    },
    get spec() {
      return spec;
    },
  };
}

/** The job output is the JSON report plus a trailing artifact/cache marker line. */
function parseReport(output) {
  return JSON.parse(output.split(/\n\[(artifact|cache):/)[0]);
}

async function settle(operation, fixture, args, extraEnv = {}) {
  const jobs = fakeJobs();
  const submission = await operation.execute(args, { workspace: fixture.workspace, jobs });
  assert.equal(submission.status, "running");
  assert.equal(jobs.spec.kind, "dumps-floss");
  return await jobs.spec.run().done;
}

test("dumps_floss requires a job registry and fails settled on a missing dir", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  assert.ok(operation, "dumps.floss operation exists");
  assert.equal(operation.toolName, "dumps_floss");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  await assert.rejects(
    () => operation.execute({ dumpDirPath: "dumps" }, { workspace: fixture.workspace }),
    /job registry/,
  );

  const outcome = await settle(operation, fixture, { dumpDirPath: "no-such-dir" });
  assert.equal(outcome.status, "failed");
  assert.match(outcome.detail, /does not exist/);
});

test("dumps_floss reports empty dirs and skips non-PE files honestly", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_FLOSS_IMAGE;
  const previousBin = process.env.MINUSONE_FLOSS_BIN;
  // Bogus image is fine: no PE file means no FLOSS invocation at all.
  process.env.MINUSONE_FLOSS_IMAGE = "registry.invalid/minusone/floss:test";
  delete process.env.MINUSONE_FLOSS_BIN;
  context.after(() => {
    if (previousImage === undefined) delete process.env.MINUSONE_FLOSS_IMAGE;
    else process.env.MINUSONE_FLOSS_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_FLOSS_BIN = previousBin;
  });

  const empty = await settle(operation, fixture, { dumpDirPath: "dumps" });
  assert.equal(empty.status, "completed");
  const emptyReport = parseReport(empty.output);
  assert.equal(emptyReport.filesScanned, 0);
  assert.equal(emptyReport.filesAnalyzed, 0);
  assert.deepEqual(emptyReport.files, []);
  assert.deepEqual(emptyReport.decodedHighlights, []);

  await writeFile(path.join(fixture.root, "dumps", "notes.txt"), "not a PE module");
  const skipped = await settle(operation, fixture, { dumpDirPath: "dumps" });
  assert.equal(skipped.status, "completed");
  const report = parseReport(skipped.output);
  assert.equal(report.filesScanned, 1);
  assert.equal(report.files[0].status, "skipped-non-pe");
  assert.equal(report.filesAnalyzed, 0);
});

test("dumps_floss enforces the analysis cap and surfaces per-file failures", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_FLOSS_IMAGE;
  const previousBin = process.env.MINUSONE_FLOSS_BIN;
  // node is a stand-in local floss that always exits non-zero ("bad option"),
  // so the analyzed file lands as a deterministic per-file error.
  process.env.MINUSONE_FLOSS_BIN = process.execPath;
  delete process.env.MINUSONE_FLOSS_IMAGE;
  context.after(() => {
    delete process.env.MINUSONE_FLOSS_BIN;
    if (previousImage !== undefined) process.env.MINUSONE_FLOSS_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_FLOSS_BIN = previousBin;
  });

  await writeFile(path.join(fixture.root, "dumps", "a-module.dll"), `MZ${"a".repeat(64)}`);
  await writeFile(path.join(fixture.root, "dumps", "b-module.dll"), `MZ${"b".repeat(64)}`);

  const outcome = await settle(operation, fixture, { dumpDirPath: "dumps", maxFiles: 1 });
  assert.equal(outcome.status, "completed");
  const report = parseReport(outcome.output);
  assert.equal(report.filesScanned, 2);
  assert.equal(report.filesAnalyzed, 0, "the fake floss exits non-zero");
  const analyzed = report.files.find((file) => file.path.includes("a-module"));
  assert.equal(analyzed.status, "error");
  assert.match(analyzed.detail, /floss exited with code/);
  const capped = report.files.find((file) => file.path.includes("b-module"));
  assert.equal(capped.status, "skipped-over-cap");
  assert.match(capped.detail, /maxFiles/);
});

test("dumps_floss rejects workspace escapes and plain files", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  await writeFile(path.join(fixture.root, "plain.txt"), "file, not a directory");

  const escape = await settle(operation, fixture, { dumpDirPath: "../escape" });
  assert.equal(escape.status, "failed");
  assert.match(escape.detail, /escapes the workspace/);

  const notDir = await settle(operation, fixture, { dumpDirPath: "plain.txt" });
  assert.equal(notDir.status, "failed");
  assert.match(notDir.detail, /not a directory/);
});

test("dumps_floss serves a cached report without invoking floss", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_FLOSS_IMAGE;
  const previousBin = process.env.MINUSONE_FLOSS_BIN;
  // An uninvokable local floss proves the cache hit short-circuits: any real
  // FLOSS attempt would fail the job instead of replaying the report.
  process.env.MINUSONE_FLOSS_BIN = path.join(fixture.root, "no-such-floss.exe");
  delete process.env.MINUSONE_FLOSS_IMAGE;
  context.after(() => {
    delete process.env.MINUSONE_FLOSS_BIN;
    if (previousImage !== undefined) process.env.MINUSONE_FLOSS_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_FLOSS_BIN = previousBin;
  });

  const payload = `MZ${"cached-dump".repeat(8)}`;
  await writeFile(path.join(fixture.root, "dumps", "cached.dll"), payload);
  const cacheKey = cacheKeyDigest({
    operation: OPERATION,
    dumpDir: "dumps",
    files: [{ path: "cached.dll", bytes: Buffer.byteLength(payload), pe: true, sha256: createHash("sha256").update(payload).digest("hex") }],
    options: { minLength: 4 },
    image: DEFAULT_IMAGES.floss,
    local: process.env.MINUSONE_FLOSS_BIN,
    schema: 1,
  });
  await storeArtifact(fixture.workspace, JSON.stringify({ schema: 1, marker: "cache-probe" }), {
    mediaType: "application/json",
    sourceOperation: OPERATION,
    description: "pre-seeded cache probe",
    cacheKey,
  });

  const outcome = await settle(operation, fixture, { dumpDirPath: "dumps" });
  assert.equal(outcome.status, "completed");
  assert.match(outcome.output, /cache-probe/);
  assert.match(outcome.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);
});

test("dumps_floss fails settled when every backend is disabled", async (context) => {
  const operation = operations.find((entry) => entry.id === OPERATION);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_FLOSS_IMAGE;
  const previousBin = process.env.MINUSONE_FLOSS_BIN;
  process.env.MINUSONE_FLOSS_IMAGE = "";
  delete process.env.MINUSONE_FLOSS_BIN;
  context.after(() => {
    delete process.env.MINUSONE_FLOSS_IMAGE;
    delete process.env.MINUSONE_FLOSS_BIN;
    if (previousImage !== undefined) process.env.MINUSONE_FLOSS_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_FLOSS_BIN = previousBin;
  });

  await writeFile(path.join(fixture.root, "dumps", "module.dll"), `MZ${"z".repeat(64)}`);
  const outcome = await settle(operation, fixture, { dumpDirPath: "dumps" });
  assert.equal(outcome.status, "failed");
  assert.match(outcome.detail, /disabled/);
});
