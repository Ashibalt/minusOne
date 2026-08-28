import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ops-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

test("operation table exposes unique, wire-safe tool names", () => {
  const names = new Set();
  for (const operation of operations) {
    assert.match(operation.id, /^[a-z]+(\.[a-z]+)+$/, `${operation.id} must be a dotted operation id`);
    assert.match(operation.toolName, /^[a-z][a-z0-9_]*$/, `${operation.toolName} must be wire-safe`);
    assert.ok(!names.has(operation.toolName), `duplicate tool name ${operation.toolName}`);
    names.add(operation.toolName);
    assert.ok(operation.description.length > 20, `${operation.id} needs a usable description`);
    assert.ok(operation.provider, `${operation.id} must name its provider`);
  }
  assert.ok(names.size >= 10);
});

test("every operation declares JSON Schema parameters and output", () => {
  for (const operation of operations) {
    assert.equal(operation.parameters.type, "object", `${operation.id} parameters must be an object schema`);
    assert.ok(
      operation.outputSchema.type === "object" || operation.outputSchema.type === "array",
      `${operation.id} output must be an object or array schema`,
    );
    const required = operation.outputSchema.required ?? [];
    for (const key of required) {
      assert.ok(
        Object.hasOwn(operation.outputSchema.properties ?? {}, key),
        `${operation.id} output schema lists required key "${key}" without a property`,
      );
    }
  }
});

test("function.decompile submits through the job seam and reports cancellation", async (context) => {
  const operation = operations.find((entry) => entry.id === "function.decompile");
  assert.ok(operation, "function.decompile operation exists");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  // Explicitly disable the Ghidra backends (an empty image turns the pinned
  // Docker default off) so the job settles as failed instead of spawning a
  // container.
  const previousGhidraImage = process.env.MINUSONE_GHIDRA_IMAGE;
  const previousGhidraHeadless = process.env.MINUSONE_GHIDRA_HEADLESS;
  process.env.MINUSONE_GHIDRA_IMAGE = "";
  process.env.MINUSONE_GHIDRA_HEADLESS = "";
  context.after(() => {
    delete process.env.MINUSONE_GHIDRA_IMAGE;
    delete process.env.MINUSONE_GHIDRA_HEADLESS;
    if (previousGhidraImage !== undefined) process.env.MINUSONE_GHIDRA_IMAGE = previousGhidraImage;
    if (previousGhidraHeadless !== undefined) process.env.MINUSONE_GHIDRA_HEADLESS = previousGhidraHeadless;
  });

  let started = null;
  const jobs = {
    start(spec) {
      started = spec;
      return "ghidra-1";
    },
  };

  // With no Ghidra backend available the job must settle as failed rather than
  // reject — and cancellation must map to the killed status rather than a
  // crashed producer.
  const withoutBackend = await operation.execute(
    { path: "sample.exe" },
    { workspace: fixture.workspace, jobs },
  );
  assert.equal(withoutBackend.jobId, "ghidra-1");
  assert.equal(withoutBackend.status, "running");
  assert.ok(started, "job seam received the spec");
  assert.equal(started.kind, "ghidra");

  const outcome = await started.run().done;
  assert.equal(outcome.status, "failed");
  assert.ok(outcome.detail.length > 0, "failure carries a diagnostic");

  const cancelProbe = new AbortController();
  const cancelled = await new Promise((resolve) => {
    const spec = {
      kind: "ghidra",
      label: "cancel probe",
      run: () => ({
        cancel: () => cancelProbe.abort("killed by test"),
        done: Promise.resolve({ status: "killed", detail: "analysis cancelled" }),
      }),
    };
    const hooks = spec.run();
    hooks.cancel();
    resolve(hooks.done);
  });
  assert.equal(cancelled.status, "killed");
});

test("function.decompile refuses hosts without a job registry", async (context) => {
  const operation = operations.find((entry) => entry.id === "function.decompile");
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /job registry/,
  );
});
