import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";

const TRACE_REPLAY = operations.find((operation) => operation.id === "trace.replay");

// trace_replay is a background job (F3): the response returns immediately with
// the job id AND both deterministic log paths, so the caller can poll
// job_output OR watch replay-out.txt grow — the 30s client timeout can no
// longer masquerade as a failure.
test("trace_replay submits a job and returns log paths up front", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ttdjob-"));
  // WinDbgX/powershell handles release asynchronously after the job settles.
  context.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 700 }));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "fake.run"), "not-a-real-trace");

  let settle;
  const settled = new Promise((resolve) => {
    settle = resolve;
  });
  let cancelCalled = false;
  const jobs = {
    start(spec) {
      assert.equal(spec.kind, "ttd-replay");
      const handle = spec.run();
      handle.done.then((outcome) => settle(outcome));
      return { cancel: () => { cancelCalled = true; }, done: handle.done, id: "ttd-1" };
    },
  };
  // Mirror the host registry contract: start returns the job id string.
  const jobsRegistry = { start: (spec) => jobs.start(spec).id };

  const submission = await TRACE_REPLAY.execute(
    { tracePath: "fake.run", commands: "r rip", timeoutSeconds: 30 },
    { workspace, jobs: jobsRegistry },
  );
  assert.equal(submission.jobId, "ttd-1");
  assert.equal(submission.status, "running");
  assert.ok(submission.logPath.endsWith("replay.log"), "carries the banner log path");
  assert.ok(submission.outputLogPath.endsWith("replay-out.txt"), "carries the command-output log path");
  assert.match(submission.poll, /job_output/);

  const outcome = await settled;
  // fake.run is not a real trace — the job must SETTLE (failed, or completed
  // with an "ok"/"error" payload depending on how far WinDbgX got), never hang
  // or vanish.
  assert.ok(["failed", "completed"].includes(outcome.status), `unexpected outcome: ${outcome.status}`);
  if (outcome.status === "completed") {
    const report = JSON.parse(outcome.output);
    assert.ok(["ok", "error"].includes(report.status), `unexpected report status: ${report.status}`);
  }
});

test("trace_replay refuses hosts without a job registry", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ttdjob-nohost-"));
  try {
    const workspace = await Workspace.create(root);
    await assert.rejects(
      () => TRACE_REPLAY.execute({ tracePath: "x.run", commands: "r" }, { workspace }),
      /background job registry/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
