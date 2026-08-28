import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { rm, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { killExternalModelsSidecar } from "../dist/core/models.js";

const SIDECAR = path.resolve("tools/models/sidecar.py");
const PYTHON = process.env.MINUSONE_MODELS_PYTHON ?? "python";

test("killExternalModelsSidecar is honest without a sidecar", async () => {
  const result = await killExternalModelsSidecar();
  assert.equal(result.killed, false);
  // Any of: no pid file at all, a dead pid left by an earlier run, or stale
  // content — all are "nothing to unload", never a kill.
  assert.match(result.detail, /no models sidecar is running|already exited|stale/);
});

test("killExternalModelsSidecar clears a stale pid file", async (context) => {
  const pidFile = path.resolve(".minusone/run/models-sidecar.pid");
  await mkdir(path.dirname(pidFile), { recursive: true });
  const previous = existsSync(pidFile) ? await import("node:fs/promises").then((fs) => fs.readFile(pidFile, "utf8")) : null;
  await writeFile(pidFile, "not-a-pid", "utf8");
  context.after(async () => {
    if (previous !== null) await writeFile(pidFile, previous, "utf8");
    else await rm(pidFile, { force: true });
  });
  const result = await killExternalModelsSidecar();
  assert.equal(result.killed, false);
  assert.match(result.detail, /stale/);
  assert.equal(existsSync(pidFile), false, "stale pid file removed");
});

test("sidecar self-exits after the idle window (VRAM leak fix)", { timeout: 60_000 }, async (context) => {
  if (!existsSync(PYTHON) && !existsSync(SIDECAR)) context.skip("needs python + sidecar");
  const child = spawn(PYTHON, [SIDECAR], {
    env: { ...process.env, MINUSONE_MODELS_IDLE_SECONDS: "2" },
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  let ready = false;
  const readyPromise = new Promise((resolve) => {
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      if (chunk.includes('"ready"')) { ready = true; resolve(); }
    });
  });
  const timeout = setTimeout(() => { if (!ready) { child.kill(); context.skip("sidecar did not boot (python env?)"); } }, 20_000);
  await Promise.race([readyPromise, new Promise((r) => setTimeout(r, 20_000))]);
  clearTimeout(timeout);
  if (!ready) return;
  const t0 = Date.now();
  const exited = await new Promise((resolve) => child.once("close", (code) => resolve(code)));
  const elapsed = Date.now() - t0;
  assert.notEqual(exited, null, "the sidecar exited on its own");
  assert.ok(elapsed < 30_000, `idle exit came fast (got ${elapsed}ms)`);
});

test("live: models off unloads a booted sidecar (kill by pid file)", { timeout: 180_000, skip: process.env.MINUSONE_EVAL_MODELS_LIVE !== "1" ? "needs MINUSONE_EVAL_MODELS_LIVE=1 (boots CLAP on CUDA)" : false }, async () => {
  const { rankAssembly } = await import("../dist/core/models.js");
  const { Workspace } = await import("../dist/core/workspace.js");
  const workspace = await Workspace.create(process.cwd());
  const ranked = await rankAssembly(workspace, { assembly: "mov eax, 1", prompts: ["nop test"] });
  assert.equal(ranked.status, "ok");
  const pidFile = path.resolve(".minusone/run/models-sidecar.pid");
  assert.ok(existsSync(pidFile), "the sidecar recorded its pid");
  const kill = await killExternalModelsSidecar();
  assert.equal(kill.killed, true, kill.detail);
  assert.ok(typeof kill.pid === "number" && kill.pid > 0);
  // The process must be gone: tasklist by pid exits non-zero for dead pids.
  let alive = true;
  try {
    execFileSync("tasklist", ["/FI", `PID eq ${kill.pid}`], { encoding: "utf8" });
  } catch {
    alive = false;
  }
  // taskkill /T /F is asynchronous at the driver level; the CUDA-teardown on
  // the python side can take a moment — poll the pid for a bounded window.
  let listing = "";
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      listing = execFileSync("tasklist", ["/FI", `PID eq ${kill.pid}`], { encoding: "utf8" });
    } catch {
      listing = "";
    }
    if (!listing.includes(String(kill.pid))) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.equal(listing.includes(String(kill.pid)), false, "pid no longer in tasklist");
  const result = await killExternalModelsSidecar();
  assert.equal(result.killed, false, "second kill finds nothing");
});
