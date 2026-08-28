/**
 * TTD (time-travel) plane tests: recorder availability, a real record of
 * a test fixture, and a headless WinDbgX replay of the recorded trace.
 * Live tests need tools/ttd/TTD.exe (minusone setup) + WinDbgX.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { isTtdAvailable, recordTtdTrace, replayTtdTrace, resolveTtdExe, resolveWindbgX } from "../dist/core/ttd.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function armEnv(context) {
  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  context.after(() => {
    if (previousAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });
}

/** Job-seam driver: submit the operation through a stub registry and await settlement (F3/F4). */
async function submitAndAwait(operation, args, services) {
  let settle;
  const settled = new Promise((resolve) => {
    settle = resolve;
  });
  const jobs = {
    start(spec) {
      const handle = spec.run();
      handle.done.then((outcome) => settle(outcome));
      return "job-1";
    },
  };
  const submission = await operation.execute(args, { ...services, jobs });
  if (submission.status !== "running") return submission; // a refusal passes through synchronously
  const outcome = await settled;
  assert.equal(outcome.status, "completed", outcome.detail ?? "");
  return JSON.parse(outcome.output);
}

test("trace.record and trace.replay operations exist with honest contracts", () => {
  const record = operations.find((entry) => entry.id === "trace.record");
  assert.ok(record, "trace.record exists");
  assert.match(record.description, /ELEVATION/);
  assert.match(record.description, /backward/i);
  const replay = operations.find((entry) => entry.id === "trace.replay");
  assert.ok(replay, "trace.replay exists");
  assert.match(replay.description, /!tt/);
  assert.match(replay.description, /NOT dynamic-gated/);
});

test("ttd availability probe reports the pieces", () => {
  const ttdExe = resolveTtdExe();
  const windbgX = resolveWindbgX();
  assert.equal(typeof ttdExe, typeof windbgX);
});

test("trace.record live: records a fixture and trace.replay walks it backward", { timeout: 600_000 }, async (context) => {
  if (resolveTtdExe() === null || resolveWindbgX() === null) {
    context.skip("needs tools/ttd/TTD.exe (minusone setup) + WinDbgX");
  }
  armEnv(context);
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ttd-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "tttarget.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", binary, path.resolve(".", "test", "fixtures", "xorsecret.c")]);
  } catch {
    context.skip("needs gcc");
    return;
  }
  const workspace = await Workspace.create(root);

  const recordOp = operations.find((entry) => entry.id === "trace.record");
  const recorded = await submitAndAwait(
    recordOp,
    { path: "tttarget.exe", args: ["some-input"], maxFileMb: 64, timeoutSeconds: 90 },
    { workspace },
  );
  if (recorded.status !== "ok") {
    // Elevation is a hard requirement of TTD recording: report honestly,
    // do not fail the suite on an un-elevated host.
    assert.match(recorded.error ?? "", /ELEVATION|elevated/i);
    context.skip(`TTD recording needs elevation: ${recorded.error}`);
    return;
  }
  assert.ok(recorded.tracePath.endsWith(".run"));
  assert.ok(recorded.traceBytes > 0, "a trace file was produced");
  assert.ok(recorded.outLogPath !== undefined, "the .out sidecar is reported");

  const replayOp = operations.find((entry) => entry.id === "trace.replay");
  const replayed = await submitAndAwait(
    replayOp,
    { tracePath: recorded.tracePath, commands: "!tt 0; !positions; q", timeoutSeconds: 120 },
    { workspace },
  );
  assert.equal(replayed.status, "ok", replayed.error ?? "");
  assert.ok(replayed.logBytes > 0, "the replay log is non-empty");
  const log = await readFile(path.join(workspace.root, replayed.logPath), "utf8");
  assert.match(log, /Time Travel Position/i, "the replay reached the trace position machinery");
  // A5: command OUTPUT is captured via .logopen — the backward-walk answers
  // arrive in the response, not only the startup banner.
  assert.ok(typeof replayed.output === "string" && replayed.output.length > 0, "the replay captured command output");
  assert.match(replayed.output ?? "", /!positions|Time Travel|positions/i, "the output holds actual command answers");
  assert.ok(replayed.outputLogPath !== undefined && replayed.outputLogPath !== null, "the full capture path is reported");
});

test("recordTtdTrace degrades honestly on a garbage target (no crash, structured error)", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ttd-err-"));
  const workspace = await Workspace.create(root);
  // "MZ" alone is not a runnable PE: TTD fails to launch the guest and the
  // operation must report a structured error with the elevation hint —
  // never throw, never hang.
  await writeFile(path.join(root, "s.exe"), "MZ");
  const result = await recordTtdTrace(workspace, "s.exe", { timeoutSeconds: 30 });
  assert.equal(result.status, "error");
  assert.ok(typeof result.error === "string" && result.error.length > 0);
  await rm(root, { recursive: true, force: true });
});
