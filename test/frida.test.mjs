import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { probeFridaAvailability, runFridaProbe } from "../dist/core/frida.js";
import { Workspace } from "../dist/core/workspace.js";

test("probeFridaAvailability returns a boolean verdict without throwing", async () => {
  const availability = await probeFridaAvailability();
  assert.equal(typeof availability.available, "boolean");
  if (availability.available) {
    assert.ok(typeof availability.version === "string" || availability.version === null);
  } else {
    assert.ok(availability.error !== null, "unavailable runtime carries its probe error");
  }
});

test("dynamic.frida exists, is a job, and refuses when the plane is unarmed", async (context) => {
  const operation = operations.find((entry) => entry.id === "dynamic.frida");
  assert.ok(operation, "dynamic.frida operation exists");
  assert.equal(operation.toolName, "dynamic_frida");
  assert.equal(operation.provider, "frida-runtime");

  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  delete process.env.MINUSONE_ALLOW_DYNAMIC;
  delete process.env.MINUSONE_DYNAMIC_TARGET;
  context.after(() => {
    delete process.env.MINUSONE_ALLOW_DYNAMIC;
    delete process.env.MINUSONE_DYNAMIC_TARGET;
    if (previousAllow !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget !== undefined) process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-frida-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "sample.exe"), "dummy");
  const workspace = await Workspace.create(root);

  const refusal = await operation.execute({ path: "sample.exe" }, { workspace });
  assert.equal(refusal.status, "refused");
  assert.match(refusal.reason, /disabled by policy/);
});

function compileSleeper() {
  const probe = spawnSync("gcc", ["--version"], { stdio: "ignore", shell: false });
  if (probe.error !== undefined || probe.status !== 0) return null;
  return path.resolve(".");
}

/**
 * End-to-end probe: spawns the trusted fridatarget fixture (rewrites
 * frida-note.txt every second via the CRT, which funnels through
 * CreateFileW/WriteFile) and observes the hooks firing inside the window.
 * Skipped when frida is not installed.
 */
test("runFridaProbe hooks file APIs of the running fixture", { timeout: 120_000 }, async (context) => {
  if (!(await probeFridaAvailability()).available) {
    context.skip("frida runtime is not installed on this host");
    return;
  }
  const repository = compileSleeper();
  if (repository === null) {
    context.skip("gcc is required to compile the fridatarget fixture");
    return;
  }
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-frida-live-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const binary = path.join(root, "fridatarget.exe");
  const compilation = spawnSync("gcc", ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "fridatarget.c")], {
    stdio: "ignore",
    shell: false,
  });
  if (compilation.status !== 0) {
    context.skip("fridatarget.c failed to compile");
    return;
  }
  const workspace = await Workspace.create(root);

  const result = await runFridaProbe(workspace, "fridatarget.exe", { probeSeconds: 5 });
  assert.equal(result.attachFailed, null);
  assert.ok(result.moduleCount >= 5, "at least the sample plus core system DLLs");
  assert.ok(result.modules.some((module) => module.name.toLowerCase() === "fridatarget.exe"), "sample module listed");
  assert.ok(result.hookedApis.includes("CreateFileW"), "CreateFileW hook installed");
  assert.ok(result.hookedApis.includes("WriteFile"), "WriteFile hook installed");
  const fileEvents = result.callEvents.filter((event) => event && event.api === "CreateFileW");
  assert.ok(fileEvents.length >= 1, "the CRT file write surfaces CreateFileW events within the window");
  const noteEvent = result.callEvents.some(
    (event) => typeof event?.path === "string" && event.path.includes("frida-note.txt"),
  );
  assert.ok(noteEvent, "the fixture's frida-note.txt path appears in the call log");
});

test("dynamic.frida settles through the job seam on the armed local plane", { timeout: 120_000 }, async (context) => {
  if (!(await probeFridaAvailability()).available) {
    context.skip("frida runtime is not installed on this host");
    return;
  }
  const repository = compileSleeper();
  if (repository === null) {
    context.skip("gcc is required to compile the sleeper fixture");
    return;
  }
  const operation = operations.find((entry) => entry.id === "dynamic.frida");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-frida-job-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const binary = path.join(root, "probe-target.exe");
  const compilation = spawnSync("gcc", ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "fridatarget.c")], {
    stdio: "ignore",
    shell: false,
  });
  assert.equal(compilation.status, 0, "fridatarget.c must compile for this test");
  const workspace = await Workspace.create(root);

  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  context.after(() => {
    delete process.env.MINUSONE_ALLOW_DYNAMIC;
    delete process.env.MINUSONE_DYNAMIC_TARGET;
    if (previousAllow !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget !== undefined) process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });

  let spec = null;
  const jobs = {
    start(received) {
      spec = received;
      return "frida-1";
    },
  };
  const submission = await operation.execute(
    { path: "probe-target.exe", probeSeconds: 4 },
    { workspace, jobs },
  );
  assert.equal(submission.status, "running");
  assert.equal(spec.kind, "frida");
  const outcome = await spec.run().done;
  assert.equal(outcome.status, "completed", outcome.detail ?? "");
  const parsed = JSON.parse(outcome.output);
  assert.equal(parsed.target, "local");
  assert.ok(parsed.callEventCount >= 1);
  assert.ok(Array.isArray(parsed.modules));
});
test("runFridaProbe spawn-gate captures a FAST-EXIT sample the attach race always lost", { timeout: 120_000 }, async (context) => {
  const fridaOk = await probeFridaAvailability();
  if (!fridaOk.available) context.skip("needs the frida node binding");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-fastexit-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const source = '#include <windows.h>\nint main(void) { HANDLE h = CreateFileA("fast-exit-proof.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); if (h != INVALID_HANDLE_VALUE) CloseHandle(h); return 0; }\n';
  await writeFile(path.join(root, "fastexit.c"), source);
  const compiled = spawnSync("gcc", ["-O2", "-o", path.join(root, "fastexit.exe"), path.join(root, "fastexit.c")]);
  if (compiled.status !== 0) context.skip("needs gcc");
  const workspace = await Workspace.create(root);
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

  const result = await runFridaProbe(workspace, "fastexit.exe", { probeSeconds: 3 });
  assert.equal(result.launchMode, "spawn-gate");
  assert.equal(result.attachFailed, null, result.attachFailed ?? "");
  const apis = result.callEvents.map((event) => String((event && typeof event === "object" ? event.api : undefined) ?? ""));
  assert.ok(apis.some((api) => /CreateFile/i.test(api)), `CreateFile must be captured on a fast-exit sample (got: ${apis.join(", ") || "none"})`);
});
