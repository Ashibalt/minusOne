import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const UNPACK_CHAIN = operations.find((entry) => entry.id === "unpack.chain");
const DYNAMIC_RECON = operations.find((entry) => entry.id === "dynamic.recon");
const FINDINGS = operations.find((entry) => entry.id === "report.findings");
assert.ok(UNPACK_CHAIN, "unpack.chain operation exists");
assert.equal(UNPACK_CHAIN.toolName, "unpack_chain");
assert.ok(DYNAMIC_RECON, "dynamic.recon operation exists");
assert.equal(DYNAMIC_RECON.toolName, "dynamic_recon");
assert.ok(FINDINGS, "report.findings operation exists");
assert.equal(FINDINGS.toolName, "report_findings");

const UPX = path.join(process.cwd(), "tools", "upx.exe");

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-chains-"));
  await writeFile(path.join(root, "sample.bin"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function withDynamicEnv(body) {
  const savedAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const savedTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  return Promise.resolve(body()).finally(() => {
    if (savedAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = savedAllow;
    if (savedTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = savedTarget;
  });
}

test("unpack.chain and dynamic.recon refuse unarmed and need the job seam", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  const savedAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const savedTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  delete process.env.MINUSONE_ALLOW_DYNAMIC;
  delete process.env.MINUSONE_DYNAMIC_TARGET;
  try {
    const refusal = await UNPACK_CHAIN.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs: { start: () => "x" } });
    assert.equal(refusal.status, "refused");
    assert.match(refusal.reason, /disabled by policy/);
    const reconRefusal = await DYNAMIC_RECON.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs: { start: () => "x" } });
    assert.equal(reconRefusal.status, "refused");
  } finally {
    if (savedAllow !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = savedAllow;
    if (savedTarget !== undefined) process.env.MINUSONE_DYNAMIC_TARGET = savedTarget;
  }

  await withDynamicEnv(async () => {
    await assert.rejects(
      () => UNPACK_CHAIN.execute({ path: "sample.bin" }, { workspace: fixture.workspace }),
      /job registry/,
    );
    await assert.rejects(
      () => DYNAMIC_RECON.execute({ path: "sample.bin" }, { workspace: fixture.workspace }),
      /job registry/,
    );
  });
});

test("report.findings records and lists the durable case file", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  const empty = await FINDINGS.execute({}, { workspace: fixture.workspace });
  assert.deepEqual(empty.findings, []);

  await assert.rejects(
    () => FINDINGS.execute({ title: "x" }, { workspace: fixture.workspace }),
    /requires title, severity, and notes/,
  );

  const saved = await FINDINGS.execute({
    title: "C2 endpoint confirmed",
    severity: "high",
    notes: "93.184.216.34:80 observed by both procmon and frida; static IOC in .rdata",
    evidence: ["sha256:" + "a".repeat(64)],
  }, { workspace: fixture.workspace });
  assert.ok(saved.saved.artifactId.startsWith("sha256:"));
  assert.equal(saved.findings.length, 1);
  assert.equal(saved.findings[0].title, "C2 endpoint confirmed");
  assert.equal(saved.findings[0].severity, "high");

  const listed = await FINDINGS.execute({}, { workspace: fixture.workspace });
  assert.equal(listed.findings.length, 1);
  assert.match(listed.findings[0].artifactId, /^sha256:[0-9a-f]{64}$/);
});

test("unpack.chain live: packed sleeper → dump → rebuild → re-triage", { timeout: 600_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  if (spawnSync(UPX, ["--version"], { encoding: "utf8" }).status !== 0) context.skip("needs the bundled upx.exe");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-chainlive-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const plain = path.join(root, "sleeper.exe");
  const packed = path.join(root, "sleeper.packed.exe");
  assert.equal(
    spawnSync("gcc", ["-O0", "-o", plain, path.join(process.cwd(), "test", "fixtures", "sleeper.c")], { encoding: "utf8" }).status,
    0,
    "gcc build failed",
  );
  assert.equal(spawnSync(UPX, ["-q", "-o", packed, plain], { encoding: "utf8" }).status, 0, "upx pack failed");

  await withDynamicEnv(async () => {
    let settle;
    const settled = new Promise((resolve) => {
      settle = resolve;
    });
    const jobs = {
      start(spec) {
        const handle = spec.run();
        handle.done.then((outcome) => settle(outcome));
        return "chain-1";
      },
    };
    await UNPACK_CHAIN.execute({ path: "sleeper.packed.exe", runSeconds: 4 }, { workspace, jobs });
    const outcome = await settled;
    assert.equal(outcome.status, "completed", `chain failed: ${outcome.detail ?? ""}`);
    const report = JSON.parse(outcome.output);

    const stages = Object.fromEntries(report.stages.map((stage) => [stage.stage, stage]));
    assert.equal(stages["pre-triage"].status, "ok");
    assert.match(stages["pre-triage"].detail, /packed=true/);
    assert.equal(stages["post-triage"].status, "ok", stages["post-triage"].detail);

    // Two valid routes: the UPX static fast-path (no execution, seconds) or
    // the dynamic pe-sieve + LIEF rebuild.
    if (stages["UPX static unpack"]?.status === "ok") {
      assert.ok(report.rebuiltPath.includes("unpack-static"), "static route produced the image");
    } else {
      assert.equal(stages["pe-sieve unpack"].status, "ok", stages["pe-sieve unpack"].detail);
      assert.equal(stages["LIEF rebuild"].status, "ok", stages["LIEF rebuild"].detail);
      assert.match(report.rebuiltSha256, /^[0-9a-f]{64}$/);
    }

    assert.ok(report.rebuiltPath.includes(".minusone"), "the rebuilt image is under .minusone");
    assert.ok(report.postTriage.stringsCount > 0, "strings are reachable in the rebuilt image");
    assert.ok(report.postTriage.importCount > 0, "imports are restored in the rebuilt image");
  });
});
