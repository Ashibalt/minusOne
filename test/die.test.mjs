import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { summarizeDieReport } from "../dist/core/die.js";
import { Workspace } from "../dist/core/workspace.js";

const LIVE_REPORT = {
  detections: {
    detects: [
      {
        filetype: "PE64",
        info: "",
        offset: "0",
        parentfilepart: "Header",
        size: "132810",
        values: [{ info: "", name: "MinGW", string: "Compiler: MinGW", type: "compiler", version: "" }],
      },
    ],
  },
  entropy: {
    records: [
      { entropy: 5.85, name: 'Section (1) [".text"]', offset: 1536, size: 6656, status: "not packed" },
      { entropy: 4.88, name: 'Section (3) [".rdata"]', offset: 8704, size: 3072, status: "not packed" },
    ],
    status: "not packed",
    total: 5.35,
  },
};

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-die-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

test("summarizeDieReport extracts detections, packed verdict, and bounded entropy", () => {
  const summary = summarizeDieReport(LIVE_REPORT);
  assert.deepEqual(summary.filetypes, ["PE64"]);
  assert.equal(summary.detectionCount, 1);
  assert.equal(summary.detections[0].values[0].name, "MinGW");
  assert.equal(summary.detections[0].values[0].type, "compiler");
  assert.equal(summary.entropyAvailable, true);
  assert.equal(summary.packed, false);
  assert.equal(summary.entropyStatus, "not packed");
  assert.equal(summary.totalEntropy, 5.35);
  assert.equal(summary.entropyRecords.length, 2);
  assert.equal(summary.entropyRecords[0].name, 'Section (1) [".text"]');

  const packed = summarizeDieReport({
    detections: { detects: [] },
    entropy: { records: [], status: "packed", total: 7.6 },
  });
  assert.equal(packed.packed, true);
  assert.deepEqual(packed.filetypes, []);

  const withoutEntropy = summarizeDieReport({ detections: { detects: [] } });
  assert.equal(withoutEntropy.entropyAvailable, false);
  assert.equal(withoutEntropy.packed, false);
  assert.deepEqual(withoutEntropy.entropyRecords, []);

  const truncated = summarizeDieReport(LIVE_REPORT, 0, 0);
  assert.equal(truncated.truncated, true);
});

test("packer.detect is synchronous, fails loudly without a backend, serves cache", async (context) => {
  const operation = operations.find((entry) => entry.id === "packer.detect");
  assert.ok(operation, "packer.detect operation exists");
  assert.equal(operation.toolName, "packer_detect");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_DIE_IMAGE;
  const previousBin = process.env.MINUSONE_DIE_BIN;
  // An explicitly empty image disables the Docker backend (pinned default off).
  process.env.MINUSONE_DIE_IMAGE = "";
  delete process.env.MINUSONE_DIE_BIN;

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /disabled/,
  );

  process.env.MINUSONE_DIE_IMAGE = "registry.invalid/minusone/die:test";
  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "packer.detect",
    options: {},
    image: process.env.MINUSONE_DIE_IMAGE,
    local: null,
    schema: 1,
  });
  await storeArtifact(fixture.workspace, JSON.stringify(LIVE_REPORT), {
    mediaType: "application/json",
    sourceOperation: "packer.detect",
    description: "pre-seeded cache probe",
    cacheKey,
  });

  const result = await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace });
  assert.deepEqual(result.filetypes, ["PE64"]);
  assert.equal(result.detections[0].values[0].name, "MinGW");
  assert.equal(result.fullReport.cache, "reused");
  assert.match(result.fullReport.artifactId, /^sha256:[0-9a-f]{64}$/);

  context.after(() => {
    delete process.env.MINUSONE_DIE_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_DIE_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_DIE_BIN = previousBin;
  });
});
