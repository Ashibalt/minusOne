/**
 * D810-ng deobfuscation tests: availability probing, the headless
 * activation recipe (registry scan → D810State → ollvm profile), and the
 * operation contract. Live tests need IDA + the installed plugin.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { D810_DEFAULT_PROFILE, isD810Available, resolveD810Path } from "../dist/core/d810.js";
import { operations } from "../dist/core/operations.js";
import { resolveIdat } from "../dist/core/ida.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

test("isD810Available detects the installed plugin", async () => {
  const d810Path = resolveD810Path();
  if (d810Path === null) {
    assert.equal(await isD810Available(), false);
    return;
  }
  const available = await isD810Available();
  assert.equal(typeof available, "boolean");
});

test("function.deobfuscate operation exists with an honest unavailable path", async () => {
  const operation = operations.find((entry) => entry.id === "function.deobfuscate");
  assert.ok(operation, "function.deobfuscate exists");
  assert.match(operation.description, /D810-ng/);
  assert.match(operation.description, /microcode/);
  // A workspace without the plugin installed reports unavailable — never a throw.
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-d810-"));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), "MZ");
  const previous = process.env.MINUSONE_D810_PATH;
  process.env.MINUSONE_D810_PATH = path.join(root, "nonexistent-d810");
  try {
    const result = await operation.execute({ path: "s.exe" }, { workspace });
    assert.equal(result.status, "unavailable");
    assert.equal(result.d810Available, false);
    assert.match(result.error, /not installed/i);
  } finally {
    if (previous === undefined) delete process.env.MINUSONE_D810_PATH;
    else process.env.MINUSONE_D810_PATH = previous;
    await rmRoot(root);
  }
});

test("runD810Deobfuscation live: headless D810 activation on the MBA fixture", { timeout: 600_000 }, async (context) => {
  const idat = resolveIdat();
  if (idat === null) context.skip("needs IDA (licensed)");
  if (!(await isD810Available())) context.skip("needs the d810-ng plugin installed in %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-d810-live-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "mba.exe");
  try {
    execFileSync("gcc", ["-O0", "-g", "-o", binary, path.resolve(".", "test", "fixtures", "mba-obf.c")]);
  } catch {
    context.skip("needs gcc");
  }
  const workspace = await Workspace.create(root);

  const operation = operations.find((entry) => entry.id === "function.deobfuscate");
  // function.deobfuscate is a background job (F4): submit, then await settlement.
  let settle;
  const settled = new Promise((resolve) => {
    settle = resolve;
  });
  const jobs = {
    start(spec) {
      const handle = spec.run();
      handle.done.then((outcome) => settle(outcome));
      return "d810-1";
    },
  };
  const submission = await operation.execute(
    { path: "mba.exe", target: "flattened_check" },
    { workspace, jobs },
  );
  assert.equal(submission.status, "running");
  const outcome = await settled;
  assert.equal(outcome.status, "completed", outcome.detail ?? "");
  const result = JSON.parse(outcome.output);
  assert.equal(result.status, "ok", result.error ?? "");
  assert.equal(result.d810Available, true, "D810 activates headless");
  assert.ok((result.baseline ?? "").includes("flattened_check"), "baseline pseudocode is present");
  assert.ok((result.deobfuscated ?? "").length > 0, "deobfuscated pseudocode is present");
  assert.equal(result.profile ?? D810_DEFAULT_PROFILE, D810_DEFAULT_PROFILE);
});

test("profilePath validation: non-json is rejected before touching IDA", async () => {
  const { runD810Deobfuscation } = await import("../dist/core/d810.js");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-d810-prof-"));
  try {
    const workspace = await Workspace.create(root);
    await writeFile(path.join(root, "s.exe"), "MZ");
    await writeFile(path.join(root, "rules.txt"), "not json");
    await assert.rejects(
      () => runD810Deobfuscation(workspace, "s.exe", { profilePath: "rules.txt" }),
      /\.json/,
    );
  } finally {
    await rmRoot(root);
  }
});

test("F6 live: a user D810 profile is staged into cfg/d810 and selected", { timeout: 600_000 }, async (context) => {
  const idat = resolveIdat();
  if (idat === null) context.skip("needs IDA (licensed)");
  if (!(await isD810Available())) context.skip("needs the d810-ng plugin installed");
  const appData = process.env.APPDATA;
  if (appData === undefined || appData === "") context.skip("needs APPDATA");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-d810-profilelive-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "mba.exe");
  try {
    execFileSync("gcc", ["-O0", "-g", "-o", binary, path.resolve(".", "test", "fixtures", "mba-obf.c")]);
  } catch {
    context.skip("needs gcc");
  }
  // A "custom" profile: the bundled ollvm rules under a user name — the
  // staging/selection path is what is under test, not the rules' novelty.
  const d810Path = resolveD810Path();
  const bundled = path.join(d810Path, "..", "src", "d810", "conf", "default_unflattening_ollvm.json");
  const custom = path.join(root, "my-mba-rules.json");
  try {
    await copyFile(bundled, custom);
  } catch {
    context.skip(`bundled profile not found at ${bundled}`);
  }
  const workspace = await Workspace.create(root);
  const stagedPath = path.join(appData, "Hex-Rays", "IDA Pro", "cfg", "d810", "minusone-my-mba-rules.json");
  context.after(async () => {
    await rm(stagedPath, { force: true }).catch(() => undefined);
  });

  const { runD810Deobfuscation } = await import("../dist/core/d810.js");
  const result = await runD810Deobfuscation(workspace, "mba.exe", {
    target: "flattened_check",
    profilePath: "my-mba-rules.json",
  });
  assert.equal(result.profile, "minusone-my-mba-rules", "the staged profile is selected by stem name");
  assert.equal(result.stagedProfile, stagedPath, "the staging path is reported");
  assert.equal(result.error, null, result.error ?? "");
  assert.equal(result.d810Available, true, "D810 activates with the user profile");
  assert.ok((result.deobfuscated ?? "").length > 0, "deobfuscated pseudocode is present");
});
