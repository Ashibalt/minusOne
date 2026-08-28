import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { resolveX64dbgHeadless, X64dbgDriver } from "../dist/core/x64dbg.js";
import { closeDebugSession, createDebugSession, sendDebugCommand } from "../dist/core/debugger.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function withEnv(overrides, body) {
  const saved = Object.fromEntries(Object.keys(overrides).map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve(body()).finally(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

async function freshWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-x64-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

test("resolveX64dbgHeadless prefers an explicit path", async () => {
  await withEnv({ MINUSONE_X64DBG_HEADLESS: "C:/fake/headless.exe" }, async () => {
    assert.equal(await resolveX64dbgHeadless(), "C:/fake/headless.exe");
  });
});

test("debug.session.create with debugger=x64dbg is dynamic-gated", async (context) => {
  const operation = operations.find((entry) => entry.id === "debug.session.create");
  const fixture = await freshWorkspace();
  context.after(() => rmRoot(fixture.root));

  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    const refusal = await operation.execute({ path: "sample.exe", debugger: "x64dbg" }, { workspace: fixture.workspace });
    assert.equal(refusal.status, "refused");
    assert.match(refusal.reason, /disabled by policy/);
  });
});

test("X64dbgDriver.create builds a session with an env-overridden headless path", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rmRoot(root));
  await withEnv({ MINUSONE_X64DBG_HEADLESS: "C:/fake/headless.exe" }, async () => {
    const driver = await X64dbgDriver.create(workspace, "sample.exe", {});
    assert.equal(driver.kind, "x64dbg");
    assert.equal(driver.backendPath, "C:/fake/headless.exe");
    assert.match(driver.target, /sample\.exe/);
  });
});

test("x64dbg headless live: loads a sample and reports the event stream", { timeout: 120_000 }, async (context) => {
  const headlessPath = await resolveX64dbgHeadless();
  if (headlessPath === null) context.skip("needs x64dbg headless.exe");
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the sample");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-x64-live-"));
  context.after(() => rmRoot(root));
  // A sample that returns 42 and exits immediately.
  const src = path.join(root, "quick.c");
  await writeFile(src, "int main(void){return 42;}\n");
  const exe = path.join(root, "quick.exe");
  const cc = spawnSync("gcc", ["-O2", "-o", exe, src], { encoding: "utf8" });
  assert.equal(cc.status, 0, cc.stderr.slice(0, 300));

  const workspace = await Workspace.create(root);
  // x64dbg loads a live sample — arm the dynamic plane for this test.
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: "local" }, async () => {
    const created = await createDebugSession(workspace, "quick.exe", { debugger: "x64dbg" });
    assert.equal(created.debugger, "x64dbg");
    context.after(async () => {
      try {
        await closeDebugSession(created.sessionId);
      } catch {
        /* already closed */
      }
    });

    // A minimal script: let headless run the freshly loaded sample to exit.
    const result = await sendDebugCommand(created.sessionId, "ret", 90);
    assert.equal(result.ok, true, result.error ?? result.output);
    assert.match(result.output, /quick\.exe/i, "the sample module must appear in the event stream");
    assert.match(result.output, /exit code 0x[0-9a-f]+/i, "the debuggee exit code must be reported");

    const closed = await closeDebugSession(created.sessionId);
    assert.ok(closed.commandsExecuted >= 1, "the transcript must carry the script run");
  });
});
