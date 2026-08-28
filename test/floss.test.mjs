import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { summarizeFlossReport } from "../dist/core/floss.js";
import { Workspace } from "../dist/core/workspace.js";

const LIVE_REPORT = {
  metadata: { min_length: 4, version: "v3.1.1", runtime: { total: 17.637 } },
  strings: {
    decoded_strings: [
      {
        address: 18446744072630828824,
        address_type: "STACK",
        decoded_at: 5368714483,
        decoding_routine: 5368714320,
        encoding: "ASCII",
        string: "minusone-xor-gate-7f3a",
      },
    ],
    stack_strings: [{ address: 5368715008, encoding: "ASCII", string: "stack-built" }],
    tight_strings: [],
    static_strings: [{ encoding: "ASCII", offset: 8704, string: "734/)54?w\"5(w=;.?" }],
    language_strings: [],
  },
};

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-floss-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "floss-1";
    },
    get spec() {
      return spec;
    },
  };
}

test("summarizeFlossReport converts addresses to hex and bounds per-class lists", () => {
  const summary = summarizeFlossReport(LIVE_REPORT, 200, 200);
  assert.equal(summary.version, "v3.1.1");
  assert.equal(summary.minLength, 4);
  assert.equal(summary.runtimeSeconds, 17.637);
  assert.deepEqual(summary.counts, { decoded: 1, stack: 1, tight: 0, static: 1, language: 0 });
  assert.equal(summary.truncated, false);
  assert.equal(summary.decoded[0].string, "minusone-xor-gate-7f3a");
  assert.equal(summary.decoded[0].decodedAt, "0x1400014f3");
  assert.equal(summary.decoded[0].decodingRoutine, "0x140001450");
  assert.equal(summary.stack[0].address, "0x140001700");
  assert.equal(summary.static[0].offset, "0x2200");

  const truncated = summarizeFlossReport(LIVE_REPORT, 0, 5);
  assert.equal(truncated.truncated, true);
  assert.equal(truncated.decoded.length, 0);
  const clipped = summarizeFlossReport(LIVE_REPORT, 200, 8);
  assert.equal(clipped.decoded[0].string.length, 9, "long strings are clipped with an ellipsis");
  const empty = summarizeFlossReport(null);
  assert.deepEqual(empty.counts, {});
});

test("strings.extract.deep requires a job registry and fails settled without a backend", async (context) => {
  const operation = operations.find((entry) => entry.id === "strings.extract.deep");
  assert.ok(operation, "strings.extract.deep operation exists");
  assert.equal(operation.toolName, "strings_extract_deep");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousImage = process.env.MINUSONE_FLOSS_IMAGE;
  const previousBin = process.env.MINUSONE_FLOSS_BIN;
  // An explicitly empty image disables the Docker backend (pinned default off).
  process.env.MINUSONE_FLOSS_IMAGE = "";
  delete process.env.MINUSONE_FLOSS_BIN;
  context.after(() => {
    delete process.env.MINUSONE_FLOSS_IMAGE;
    delete process.env.MINUSONE_FLOSS_BIN;
    if (previousImage !== undefined) process.env.MINUSONE_FLOSS_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_FLOSS_BIN = previousBin;
  });

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /job registry/,
  );

  const jobs = fakeJobs();
  const submission = await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
  assert.equal(submission.status, "running");
  assert.equal(jobs.spec.kind, "floss");
  const outcome = await jobs.spec.run().done;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.detail, /disabled/);
});

test("strings.extract.deep serves a cached report without invoking any backend", async (context) => {
  const operation = operations.find((entry) => entry.id === "strings.extract.deep");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  process.env.MINUSONE_FLOSS_IMAGE = "registry.invalid/minusone/floss:test";
  context.after(() => delete process.env.MINUSONE_FLOSS_IMAGE);

  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "strings.extract.deep",
    options: {},
    image: process.env.MINUSONE_FLOSS_IMAGE,
    local: process.env.MINUSONE_FLOSS_BIN ?? null,
    schema: 1,
  });
  await storeArtifact(fixture.workspace, JSON.stringify(LIVE_REPORT), {
    mediaType: "application/json",
    sourceOperation: "strings.extract.deep",
    description: "pre-seeded cache probe",
    cacheKey,
  });

  const jobs = fakeJobs();
  await operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs });
  const outcome = await jobs.spec.run().done;
  assert.equal(outcome.status, "completed");
  assert.match(outcome.output, /minusone-xor-gate-7f3a/);
  assert.match(outcome.output, /0x140001450/);
  assert.match(outcome.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);
});
