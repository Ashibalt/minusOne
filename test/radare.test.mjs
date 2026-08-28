import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { summarizeRadareFunctions } from "../dist/core/radare.js";
import { Workspace } from "../dist/core/workspace.js";

const FUNCTIONS = [
  { offset: 5368713296, name: "sym._init", realsz: 27, nbbs: 1, signature: "" },
  { offset: 5368714320, name: "sym.decode", realsz: 122, nbbs: 2, signature: "void sym.decode(char *dst, int len);" },
  { offset: 5368714483, name: "main", realsz: 140, nbbs: 5, signature: "" },
  { offset: 5368727360, name: "sym.imp.strcmp", size: 10, nbbs: 1 },
];

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-r2-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "r2-1";
    },
    get spec() {
      return spec;
    },
  };
}

test("summarizeRadareFunctions filters and converts offsets to hex", () => {
  const summary = summarizeRadareFunctions(FUNCTIONS, "decode");
  assert.equal(summary.total, 1);
  assert.equal(summary.truncated, false);
  assert.equal(summary.functions[0].name, "sym.decode");
  assert.equal(summary.functions[0].offset, "0x140001450");
  assert.equal(summary.functions[0].size, 122);
  assert.equal(summary.functions[0].blocks, 2);

  const byAddress = summarizeRadareFunctions(FUNCTIONS, "0x140001");
  assert.equal(byAddress.total, 3, "0x140004740 does not contain the 0x140001 prefix");

  const truncated = summarizeRadareFunctions(FUNCTIONS, undefined, 2);
  assert.equal(truncated.truncated, true);
  assert.equal(truncated.functions.length, 2);
  assert.deepEqual(summarizeRadareFunctions(undefined, "x"), { total: 0, truncated: false, functions: [] });
});

test("disassembly.functions uses the job seam, fails settled without a backend, serves cache", async (context) => {
  const listOperation = operations.find((entry) => entry.id === "disassembly.functions");
  assert.ok(listOperation, "disassembly.functions operation exists");
  const dumpOperation = operations.find((entry) => entry.id === "disassembly.dump");
  assert.ok(dumpOperation, "disassembly.dump operation exists");
  assert.equal(dumpOperation.toolName, "disassembly_dump");

  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_R2_IMAGE;
  const previousBin = process.env.MINUSONE_R2_BIN;
  // An explicitly empty image disables the Docker backend (pinned default off).
  process.env.MINUSONE_R2_IMAGE = "";
  delete process.env.MINUSONE_R2_BIN;

  await assert.rejects(
    () => listOperation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /job registry/,
  );
  const jobs = fakeJobs();
  await listOperation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
  assert.equal(jobs.spec.kind, "radare2");
  const failed = await jobs.spec.run().done;
  assert.equal(failed.status, "failed");
  assert.match(failed.detail, /disabled/);

  await assert.rejects(
    () => dumpOperation.execute({ path: "sample.exe", count: 16 }, { workspace: fixture.workspace }),
    /requires address or symbol/,
  );

  process.env.MINUSONE_R2_IMAGE = "registry.invalid/minusone/r2:test";
  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "disassembly.functions",
    image: process.env.MINUSONE_R2_IMAGE,
    local: null,
    schema: 1,
  });
  await storeArtifact(fixture.workspace, JSON.stringify(FUNCTIONS), {
    mediaType: "application/json",
    sourceOperation: "disassembly.functions",
    description: "pre-seeded cache probe",
    cacheKey,
  });
  const cacheJobs = fakeJobs();
  await listOperation.execute({ path: "sample.exe", functionFilter: "decode" }, { workspace: fixture.workspace, jobs: cacheJobs });
  const cached = await cacheJobs.spec.run().done;
  assert.equal(cached.status, "completed");
  assert.match(cached.output, /sym\.decode/);
  assert.match(cached.output, /0x140001450/);
  assert.match(cached.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);

  context.after(() => {
    delete process.env.MINUSONE_R2_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_R2_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_R2_BIN = previousBin;
  });
});
