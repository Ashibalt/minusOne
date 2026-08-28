import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const byId = (id) => operations.find((operation) => operation.id === id);

// F4: formerly-sync long operations are background jobs now. Contracts:
// (a) hosts without a job registry get an explicit error, never a silent hang;
// (b) submission through a registry returns the standard {jobId, running} shape
//     immediately and the job SETTLES (failed is fine without providers).
test("F4: job-ified operations refuse hosts without a job registry", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-f4-"));
  try {
    const workspace = await Workspace.create(root);
    await writeFile(path.join(root, "a.exe"), "MZ-a");
    await writeFile(path.join(root, "b.exe"), "MZ-b");

    await assert.rejects(
      () => byId("symbolic.solve").execute({ path: "a.exe", target: "0x401000" }, { workspace }),
      /background job registry/,
    );
    await assert.rejects(
      () => byId("binary.diff").execute({ oldPath: "a.exe", newPath: "b.exe" }, { workspace }),
      /background job registry/,
    );

    // Dynamic-gated operations: armed env pushes them past the gate to the registry check.
    const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
    const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
    process.env.MINUSONE_ALLOW_DYNAMIC = "1";
    process.env.MINUSONE_DYNAMIC_TARGET = "local";
    try {
      await assert.rejects(
        () => byId("frida.script").execute({ path: "a.exe", source: "send(1)" }, { workspace }),
        /background job registry/,
      );
      await assert.rejects(
        () => byId("trace.diff").execute({ path: "a.exe" }, { workspace }),
        /background job registry/,
      );
      await assert.rejects(
        () => byId("trace.record").execute({ path: "a.exe" }, { workspace }),
        /background job registry/,
      );
    } finally {
      if (previousAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
      else process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
      if (previousTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
      else process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("F4: submission returns immediately and the job settles", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-f4-submit-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "a.exe"), "MZ-a");

  let settle;
  const settled = new Promise((resolve) => {
    settle = resolve;
  });
  const jobs = {
    start(spec) {
      assert.equal(spec.kind, "symbolic-solve");
      const handle = spec.run();
      handle.done.then((outcome) => settle(outcome));
      return "f4-1";
    },
  };
  const submission = await byId("symbolic.solve").execute(
    { path: "a.exe", target: "0x401000", timeoutSeconds: 30 },
    { workspace, jobs },
  );
  assert.equal(submission.jobId, "f4-1");
  assert.equal(submission.status, "running");
  assert.match(submission.poll, /job_output/);
  const outcome = await settled;
  // "MZ-a" is not a solvable target and docker may be absent — either way the
  // job must SETTLE, not hang.
  assert.ok(["failed", "completed"].includes(outcome.status), `unexpected outcome: ${outcome.status}`);
});
