import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { resolveYaraRulesRef, rulesDigest, summarizeYaraReport, validateYaraRules } from "../dist/core/yara.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const RULES = 'rule marker { strings: $a = { 37 33 34 } condition: $a }';

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-yara-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "yara-1";
    },
    get spec() {
      return spec;
    },
  };
}

test("validateYaraRules enforces structural bounds", () => {
  assert.equal(validateYaraRules(RULES), null);
  assert.match(validateYaraRules("   \n  "), /empty/);
  assert.match(validateYaraRules(`rule x { strings: $a = "z\0" condition: $a }`), /NUL/);
  assert.match(validateYaraRules("x".repeat(64 * 1024 + 1)), /exceeds/);
});

test("summarizeYaraReport keeps matched rules, meta, and bounded string offsets", () => {
  const report = {
    version: "1.19.0",
    matches: [
      {
        rule: "minusone_xor_marker",
        file: "/workspace/sample.exe",
        meta: { author: "minusone" },
        tags: ["malware"],
        strings: [
          { identifier: "$magic", offset: 8704, match: '734/)54?w"5(' },
          { identifier: "$b", offset: 9000, match: "second" },
          { identifier: "$c", offset: 9100, match: "third" },
        ],
      },
      { rule: "no_strings_here" },
    ],
  };
  const summary = summarizeYaraReport(report, 40, 2);
  assert.equal(summary.engineVersion, "1.19.0");
  assert.equal(summary.ruleCount, 2);
  assert.equal(summary.truncated, false);
  assert.equal(summary.matches[0].rule, "minusone_xor_marker");
  assert.deepEqual(summary.matches[0].tags, ["malware"]);
  assert.equal(summary.matches[0].stringCount, 3);
  assert.equal(summary.matches[0].strings.length, 2, "strings per match are bounded");
  assert.equal(summary.matches[1].rule, "no_strings_here");
  assert.deepEqual(summary.matches[1].strings, []);
  const empty = summarizeYaraReport(null);
  assert.deepEqual(empty, { engineVersion: null, ruleCount: 0, truncated: false, matches: [] });
});

test("rules.scan rejects without a job registry and validates rules before submitting", async (context) => {
  const operation = operations.find((entry) => entry.id === "rules.scan");
  assert.ok(operation, "rules.scan operation exists");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  await assert.rejects(
    () => operation.execute({ path: "sample.exe", rules: RULES }, { workspace: fixture.workspace }),
    /job registry/,
  );

  const jobs = fakeJobs();
  await assert.rejects(
    () => operation.execute({ path: "sample.exe", rules: " " }, { workspace: fixture.workspace, jobs }),
    /empty/,
  );
  assert.equal(jobs.spec, null, "invalid rules never reach the job registry");

  const submission = await operation.execute(
    { path: "sample.exe", rules: RULES },
    { workspace: fixture.workspace, jobs },
  );
  assert.equal(submission.jobId, "yara-1");
  assert.equal(submission.status, "running");
  assert.equal(jobs.spec.kind, "yara");
});

test("rules.scan settles as failed when no yara backend is configured", async (context) => {
  const operation = operations.find((entry) => entry.id === "rules.scan");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  const previousImage = process.env.MINUSONE_YARA_IMAGE;
  const previousBin = process.env.MINUSONE_YARA_BIN;
  // An explicitly empty image disables the Docker backend (pinned default off).
  process.env.MINUSONE_YARA_IMAGE = "";
  delete process.env.MINUSONE_YARA_BIN;
  context.after(() => {
    delete process.env.MINUSONE_YARA_IMAGE;
    delete process.env.MINUSONE_YARA_BIN;
    if (previousImage !== undefined) process.env.MINUSONE_YARA_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_YARA_BIN = previousBin;
  });

  const jobs = fakeJobs();
  await operation.execute({ path: "sample.exe", rules: RULES }, { workspace: fixture.workspace, jobs });
  const outcome = await jobs.spec.run().done;
  assert.equal(outcome.status, "failed");
  assert.match(outcome.detail, /disabled/);
});

test("rules.scan serves a cached report without invoking any backend", async (context) => {
  const operation = operations.find((entry) => entry.id === "rules.scan");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  process.env.MINUSONE_YARA_IMAGE = "registry.invalid/minusone/yara-x:test";
  context.after(() => delete process.env.MINUSONE_YARA_IMAGE);

  const content = JSON.stringify({
    version: "1.19.0",
    matches: [{ rule: "cached_marker", strings: [{ identifier: "$a", offset: 42, match: "789" }] }],
  });
  const sha256 = createHash("sha256").update("dummy-sample-content").digest("hex");
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "rules.scan",
    rules: rulesDigest(RULES),
    image: process.env.MINUSONE_YARA_IMAGE,
    local: process.env.MINUSONE_YARA_BIN ?? null,
    schema: 1,
  });
  await storeArtifact(fixture.workspace, content, {
    mediaType: "application/json",
    sourceOperation: "rules.scan",
    description: "pre-seeded cache probe",
    cacheKey,
  });

  const jobs = fakeJobs();
  await operation.execute({ path: "sample.exe", rules: RULES }, { workspace: fixture.workspace, jobs });
  const outcome = await jobs.spec.run().done;
  assert.equal(outcome.status, "completed");
  assert.match(outcome.output, /cached_marker/);
  assert.match(outcome.output, /\[cache: reused artifact sha256:[0-9a-f]{64}\]/);
});

test("rules.scan requires exactly one of rules / rulesFile", async (context) => {
  const operation = operations.find((entry) => entry.id === "rules.scan");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  const jobs = fakeJobs();

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace, jobs }),
    /exactly one of/,
  );
  await assert.rejects(
    () => operation.execute({ path: "sample.exe", rules: RULES, rulesFile: "rules.yar" }, { workspace: fixture.workspace, jobs }),
    /exactly one of/,
  );
  assert.equal(jobs.spec, null, "invalid rules never reach the job registry");
});

test("resolveYaraRulesRef resolves workspace rule files and flags compiled", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  await writeFile(path.join(fixture.root, "pack.yar"), RULES);

  const sourceRef = await resolveYaraRulesRef(fixture.workspace, { rulesFile: "pack.yar" });
  assert.equal(sourceRef.kind, "file");
  assert.equal(sourceRef.compiled, false);
  assert.equal(sourceRef.digest, createHash("sha256").update(Buffer.from(RULES)).digest("hex"));

  const compiledRef = await resolveYaraRulesRef(fixture.workspace, { rulesFile: "pack.yar", compiled: true });
  assert.equal(compiledRef.compiled, true);
  assert.equal(compiledRef.digest, sourceRef.digest, "digest is over file bytes regardless of compiled flag");

  await assert.rejects(() => resolveYaraRulesRef(fixture.workspace, { rulesFile: "missing.yar" }), /does not exist/);
  await assert.rejects(() => resolveYaraRulesRef(fixture.workspace, { rules: RULES, compiled: true }), /applies to rulesFile only/);

  const inlineRef = await resolveYaraRulesRef(fixture.workspace, { rules: RULES });
  assert.equal(inlineRef.kind, "inline");
  assert.equal(inlineRef.digest, rulesDigest(RULES));
});

test("rules.scan submits a job from a workspace rules file", async (context) => {
  const operation = operations.find((entry) => entry.id === "rules.scan");
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));
  await writeFile(path.join(fixture.root, "pack.yar"), RULES);

  const jobs = fakeJobs();
  const submission = await operation.execute(
    { path: "sample.exe", rulesFile: "pack.yar" },
    { workspace: fixture.workspace, jobs },
  );
  assert.equal(submission.jobId, "yara-1");
  assert.equal(submission.status, "running");
  assert.equal(jobs.spec.kind, "yara");
});
