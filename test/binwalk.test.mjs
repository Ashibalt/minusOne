import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { gzipSync, gunzipSync } from "node:zlib";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { parseBinwalkSignatures } from "../dist/core/binwalk.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const SAMPLE_STDOUT = [
  "DECIMAL       HEXADECIMAL     DESCRIPTION",
  "--------------------------------------------------------------------------------",
  "0             0x0             Microsoft executable, portable (PE)",
  "16472         0x4058          XML document, version: \"1.0\"",
  "",
].join("\n");

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-bw-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

test("parseBinwalkSignatures parses the table and bounds the list", () => {
  const { signatures, truncated } = parseBinwalkSignatures(SAMPLE_STDOUT);
  assert.equal(signatures.length, 2);
  assert.equal(signatures[0].decimalOffset, 0);
  assert.equal(signatures[0].offset, "0x0");
  assert.match(signatures[0].description, /portable \(PE\)/);
  assert.equal(signatures[1].offset, "0x4058");

  const many = Array.from({ length: 205 }, (_, i) => `${i}   0x${i.toString(16)}   desc`).join("\n");
  const bounded = parseBinwalkSignatures(many);
  assert.equal(bounded.signatures.length, 200);
  assert.equal(bounded.truncated, true);
  assert.deepEqual(parseBinwalkSignatures("noise\nno rows here"), { signatures: [], truncated: false, suppressedCount: 0 });
});

test("embedded.scan fails loudly without a backend and serves the cache", async (context) => {
  const operation = operations.find((entry) => entry.id === "embedded.scan");
  assert.ok(operation, "embedded.scan operation exists");
  assert.equal(operation.toolName, "embedded_scan");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  const previousImage = process.env.MINUSONE_BINWALK_IMAGE;
  const previousBin = process.env.MINUSONE_BINWALK_BIN;
  // An explicitly empty image disables the Docker backend (pinned default off).
  process.env.MINUSONE_BINWALK_IMAGE = "";
  delete process.env.MINUSONE_BINWALK_BIN;

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /disabled/,
  );

  process.env.MINUSONE_BINWALK_IMAGE = "registry.invalid/minusone/binwalk:test";
  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "embedded.scan",
    image: process.env.MINUSONE_BINWALK_IMAGE,
    local: null,
    schema: 1,
  });
  const signatures = [{ offset: "0x0", decimalOffset: 0, description: "Microsoft executable, portable (PE)" }];
  await storeArtifact(fixture.workspace, JSON.stringify({ signatures, truncated: false }), {
    mediaType: "application/json",
    sourceOperation: "embedded.scan",
    description: "pre-seeded cache probe",
    cacheKey,
  });
  const cached = await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace });
  assert.equal(cached.signatureCount, 1);
  assert.equal(cached.fullReport.cache, "reused");

  context.after(() => {
    delete process.env.MINUSONE_BINWALK_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_BINWALK_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_BINWALK_BIN = previousBin;
  });
});

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "bw-1";
    },
    get spec() {
      return spec;
    },
  };
}

test("embedded.extract requires a job registry and submits a binwalk job", async (context) => {
  const operation = operations.find((entry) => entry.id === "embedded.extract");
  assert.ok(operation, "embedded.extract operation exists");
  assert.equal(operation.toolName, "embedded_extract");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /job registry/,
  );

  const jobs = fakeJobs();
  const submission = await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
  assert.equal(submission.jobId, "bw-1");
  assert.equal(submission.status, "running");
  assert.equal(jobs.spec.kind, "binwalk");
});

test("embedded.extract serves a cached manifest without invoking any backend", async (context) => {
  const operation = operations.find((entry) => entry.id === "embedded.extract");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  process.env.MINUSONE_BINWALK_IMAGE = "registry.invalid/minusone/binwalk:test";
  context.after(() => delete process.env.MINUSONE_BINWALK_IMAGE);

  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "embedded.extract",
    image: process.env.MINUSONE_BINWALK_IMAGE,
    local: null,
    schema: 1,
  });
  const manifest = {
    outDirectory: ".minusone/binwalk/out",
    backend: "docker",
    carved: [{ path: ".minusone/binwalk/out/_sample.exe/0", name: "0", bytes: 32, sha256: "abc" }],
    signatures: [],
    truncated: false,
  };
  await storeArtifact(fixture.workspace, JSON.stringify(manifest), {
    mediaType: "application/json",
    sourceOperation: "embedded.extract",
    description: "pre-seeded cache probe",
    cacheKey,
  });

  const jobs = fakeJobs();
  await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
  const outcome = await jobs.spec.run().done;
  assert.equal(outcome.status, "completed");
  assert.match(outcome.output, /_sample\.exe/);
  assert.match(outcome.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);
});

function dockerImagePresent(image) {
  const result = spawnSync("docker", ["images", image, "-q"], { encoding: "utf8" });
  return result.status === 0 && result.stdout.trim().length > 0;
}

test("embedded.extract live: carves an appended gzip stream out of a sample", { timeout: 180_000 }, async (context) => {
  const image = "minusone/binwalk:2.3.3";
  if (!dockerImagePresent(image)) context.skip(`needs docker image ${image}`);

  const { runBinwalkExtract } = await import("../dist/core/binwalk.js");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-bw-live-"));
  context.after(() => rmRoot(root));

  const payload = Buffer.from("minusone-carved-payload");
  const gzip = gzipSync(payload);
  // Prepend a zero stub so the gzip stream is embedded, not at offset 0.
  const stub = Buffer.alloc(64, 0);
  const sample = Buffer.concat([stub, gzip]);
  await writeFile(path.join(root, "sample.bin"), sample);
  const workspace = await Workspace.create(root);

  const result = await runBinwalkExtract(workspace, "sample.bin", {
    maxFiles: 8,
    maxBytesPerFile: 1024 * 1024,
    depth: 1,
    timeoutSeconds: 120,
  });
  assert.equal(result.command.exitCode, 0, result.command.stderr.slice(0, 300));
  assert.ok(result.carved.length >= 1, `expected at least one carved file, got ${result.carved.length}`);

  // binwalk may emit several blobs (raw stream + sub-carves); find the gzip.
  let decoded = null;
  for (const carvedFile of result.carved) {
    try {
      decoded = gunzipSync(await readFile(path.join(workspace.root, carvedFile.path)));
      break;
    } catch {
      // not a gzip stream; try the next carved blob
    }
  }
  if (decoded === null) {
    // Fallback: some binwalk builds carve already-decompressed content.
    for (const carvedFile of result.carved) {
      const blob = await readFile(path.join(workspace.root, carvedFile.path));
      if (blob.includes(payload)) {
        return;
      }
    }
    assert.fail("no carved blob decompresses to or contains the embedded payload");
  }
  assert.equal(decoded.toString(), "minusone-carved-payload", "carved gzip must decompress to the embedded payload");
});

test("binwalk noise filter drops impossible firmware metadata (the Unity.dll 92-bix-headers lesson)", async () => {
  const { isNoiseSignature } = await import("../dist/core/binwalk.js");
  // Impossible dates, sizes, and firmware families on compiled x86:
  assert.equal(isNoiseSignature("bix header, header size: 4096 bytes, created on 1970-01-01"), true);
  assert.equal(isNoiseSignature("uimage header, 2098-12-31"), true);
  assert.equal(isNoiseSignature("some image, total size: 4.7 GB"), true);
  assert.equal(isNoiseSignature("file size 15000000000 bytes"), true);
  // Legitimate findings survive:
  assert.equal(isNoiseSignature("gzip compressed data, from FAT filesystem (MS-DOS, OS/2, NT)"), false);
  assert.equal(isNoiseSignature("Microsoft executable, portable (PE)"), false);
  assert.equal(isNoiseSignature("XML document, version: \"1.0\""), false);
  assert.equal(isNoiseSignature("copyright 2019-2024 example"), false);
});

