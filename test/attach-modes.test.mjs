import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runFridaScript } from "../dist/core/frida.js";
import { recordTtdTrace } from "../dist/core/ttd.js";
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

// F1: frida attach-by-pid mode — instrument an already-running process and
// leave it ALIVE at teardown (the caller owns the lifecycle).
test("frida attach mode: instruments a live pid and does not kill it", { timeout: 120_000 }, async (context) => {
  armEnv(context);
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-attach-"));
  context.after(() => rmRoot(root));
  const sleeper = path.join(root, "sleeper.exe");
  try {
    execFileSync("gcc", ["-O0", "-o", sleeper, path.resolve(".", "test", "fixtures", "sleeper.c")]);
  } catch {
    context.skip("needs gcc");
    return;
  }
  const frida = await import("frida").catch(() => null);
  if (frida === null) {
    context.skip("needs the frida node runtime");
    return;
  }
  const workspace = await Workspace.create(root);

  const child = spawn(sleeper, [], { stdio: "ignore" });
  const childPid = child.pid;
  assert.ok(childPid !== undefined && childPid > 0, "sleeper spawned");
  context.after(() => {
    try { process.kill(childPid); } catch { /* already gone */ }
  });
  await new Promise((resolve) => setTimeout(resolve, 800));

  const result = await runFridaScript(workspace, "sleeper.exe", {
    source: `send({t:"alive", answer: 40 + 2});`,
    pid: childPid,
    probeSeconds: 4,
  });
  assert.equal(result.attachFailed, null, `attach failed: ${result.attachFailed ?? ""}`);
  assert.equal(result.launchMode, "attach-pid");
  assert.equal(result.pid, childPid);
  assert.ok(
    result.events.some((event) => event.payload !== null && typeof event.payload === "object" && event.payload.t === "alive"),
    `the agent's event arrived: ${JSON.stringify(result.events.slice(0, 5))}`,
  );
  // THE contract: the attached process is left running — the caller owns it.
  const alive = spawnSync("tasklist", ["/FI", `PID eq ${childPid}`], { encoding: "utf8" }).stdout;
  assert.ok(alive.includes(String(childPid)), "attached process is still alive after teardown");
  assert.ok(result.notes.some((note) => /left running|caller owns/i.test(note)), "the no-kill behavior is reported in notes");
});

// F2: TTD attach mode validates the pid.
test("TTD attach mode rejects an invalid pid before touching the recorder", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-ttd-attach-"));
  try {
    const workspace = await Workspace.create(root);
    await assert.rejects(
      () => recordTtdTrace(workspace, "s.exe", { pid: -3 }),
      /positive integer/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
