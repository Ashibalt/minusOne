import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { resolveIdat, summarizeIdaFunctions } from "../dist/core/ida.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const FUNCTIONS_OP = operations.find((entry) => entry.id === "ida.functions");
const DECOMPILE_OP = operations.find((entry) => entry.id === "ida.decompile");
assert.ok(FUNCTIONS_OP, "ida.functions operation exists");
assert.equal(FUNCTIONS_OP.toolName, "ida_functions");
assert.ok(DECOMPILE_OP, "ida.decompile operation exists");
assert.equal(DECOMPILE_OP.toolName, "ida_decompile");

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ida-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "ida-job-1";
    },
    get spec() {
      return spec;
    },
  };
}

function idaAvailable() {
  return resolveIdat() !== null;
}

test("summarizeIdaFunctions filters and bounds the function list", () => {
  const report = {
    functions: [
      { name: "__tmainCRTStartup", start: "0x140001010", end: "0x1400013da", size: 970, blocks: 47 },
      { name: "main", start: "0x140001600", end: "0x1400016c0", size: 192, blocks: 12 },
      { name: "decode_secret", start: "0x140001700", end: "0x140001780", size: 128, blocks: 8 },
    ],
  };
  const all = summarizeIdaFunctions(report, undefined);
  assert.equal(all.total, 3);
  assert.equal(all.truncated, false);

  const filtered = summarizeIdaFunctions(report, "main");
  assert.equal(filtered.total, 2, "matches both names containing 'main'");

  const byAddress = summarizeIdaFunctions(report, "0x1400017");
  assert.equal(byAddress.total, 1, "hex-address filtering works");
  assert.equal(byAddress.functions[0].name, "decode_secret");

  const truncated = summarizeIdaFunctions(report, undefined, 2);
  assert.equal(truncated.truncated, true);
  assert.deepEqual(summarizeIdaFunctions(null, "x"), { total: 0, truncated: false, functions: [] });
});

test("ida.functions resolves the job seam and reports missing IDA settled", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  await assert.rejects(
    () => FUNCTIONS_OP.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /job registry/,
  );

  const saved = { idat: process.env.MINUSONE_IDAT_PATH, home: process.env.MINUSONE_IDA_HOME };
  process.env.MINUSONE_IDA_DISABLED = "1";
  try {
    assert.equal(resolveIdat(), null, "the disable seam beats every discovery path");
    const jobs = fakeJobs();
    await FUNCTIONS_OP.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
    assert.equal(jobs.spec.kind, "idat");
    const outcome = await jobs.spec.run().done;
    assert.equal(outcome.status, "failed");
    assert.match(outcome.detail, /IDA is not available/);
  } finally {
    delete process.env.MINUSONE_IDA_DISABLED;
    if (saved.idat !== undefined) process.env.MINUSONE_IDAT_PATH = saved.idat;
    if (saved.home !== undefined) process.env.MINUSONE_IDA_HOME = saved.home;
  }
});

test("ida.functions serves a cached overview without invoking idat", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  const saved = { idat: process.env.MINUSONE_IDAT_PATH, home: process.env.MINUSONE_IDA_HOME };
  process.env.MINUSONE_IDA_DISABLED = "1";
  try {
    const { createHash } = await import("node:crypto");
    const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
    const cacheKey = cacheKeyDigest({
      sample: sha256,
      operation: "ida.functions",
      idat: null,
      schema: 1,
    });
    await storeArtifact(fixture.workspace, JSON.stringify({
      functions: [
        { name: "main", start: "0x140001600", end: "0x1400016c0", size: 192, blocks: 12 },
        { name: "secret_decoder", start: "0x140001700", end: "0x140001780", size: 128, blocks: 8 },
      ],
    }), {
      mediaType: "application/json",
      sourceOperation: "ida.functions",
      description: "pre-seeded cache probe",
      cacheKey,
    });

    const jobs = fakeJobs();
    await FUNCTIONS_OP.execute({ path: "sample.exe", functionFilter: "secret" }, { workspace: fixture.workspace, jobs });
    const cached = await jobs.spec.run().done;
    assert.equal(cached.status, "completed");
    assert.match(cached.output, /secret_decoder/);
    assert.match(cached.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);
  } finally {
    delete process.env.MINUSONE_IDA_DISABLED;
    if (saved.idat !== undefined) process.env.MINUSONE_IDAT_PATH = saved.idat;
    if (saved.home !== undefined) process.env.MINUSONE_IDA_HOME = saved.home;
  }
});

test("ida live: idat overview and Hex-Rays decompilation of a gcc fixture", { timeout: 600_000 }, async (context) => {
  if (!idaAvailable()) context.skip("needs a licensed local IDA installation");
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the fixture");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-idalive-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const exe = path.join(root, "sleeper.exe");
  assert.equal(
    spawnSync("gcc", ["-O0", "-o", exe, path.join(process.cwd(), "test", "fixtures", "sleeper.c")], { encoding: "utf8" }).status,
    0,
    "gcc build failed",
  );

  // Overview via the operation surface (job seam, CAS artifact, cache key).
  const functionsJobs = fakeJobs();
  let functionsSettled;
  const functionsDone = new Promise((resolve) => {
    functionsSettled = resolve;
  });
  const jobs = {
    start(spec) {
      const handle = spec.run();
      handle.done.then((outcome) => functionsSettled(outcome));
      return "ida-live-1";
    },
  };
  await FUNCTIONS_OP.execute({ path: "sleeper.exe", timeoutSeconds: 300 }, { workspace, jobs });
  const overview = await functionsDone;
  assert.equal(overview.status, "completed", `overview failed: ${overview.detail ?? ""}`);
  const overviewPayload = JSON.parse(overview.output);
  assert.equal(overviewPayload.backend, "idat");
  assert.match(overviewPayload.fileType, /Portable executable/i);
  assert.ok(overviewPayload.total >= 5, "IDA recovered a meaningful function set");
  assert.ok(overviewPayload.functions.some((fn) => /main/i.test(fn.name)), "main is in the list");

  // Decompile main through the operation surface.
  let decompileSettled;
  const decompileDone = new Promise((resolve) => {
    decompileSettled = resolve;
  });
  const decompileJobs = {
    start(spec) {
      const handle = spec.run();
      handle.done.then((outcome) => decompileSettled(outcome));
      return "ida-live-2";
    },
  };
  await DECOMPILE_OP.execute({ path: "sleeper.exe", targets: ["main"], timeoutSeconds: 300 }, { workspace, jobs: decompileJobs });
  const decompilation = await decompileDone;
  assert.equal(decompilation.status, "completed", `decompile failed: ${decompilation.detail ?? ""}`);
  const decompilePayload = JSON.parse(decompilation.output);
  assert.equal(decompilePayload.backend, "idat");
  assert.equal(decompilePayload.decompiled.length, 1);
  assert.equal(decompilePayload.decompiled[0].error, null);
  assert.match(decompilePayload.decompiled[0].pseudocodePreview, /int .*main|main\(/, "Hex-Rays pseudocode present");
});
