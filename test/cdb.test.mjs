import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { CdbDriver, resolveCdb, validateCdbCommand } from "../dist/core/cdb.js";
import { closeDebugSession, createDebugSession, sendDebugCommand } from "../dist/core/debugger.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

/** Minimal buffer with the MDMP magic so the magic-check passes hermetically. */
function mdmpMagicBuffer() {
  const buf = Buffer.alloc(64, 0);
  buf.write("MDMP", 0, "ascii");
  return buf;
}

async function freshWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-cdb-"));
  return { root, workspace: await Workspace.create(root) };
}

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

test("validateCdbCommand blocks sandbox-escape commands only", () => {
  for (const blocked of [".shell calc.exe", ".shell", "$< evil.txt", ".foreach"]) {
    assert.match(validateCdbCommand(blocked), /blocked/, blocked);
  }
  for (const allowed of ["lm", "r", "kv", "!analyze -v", ".ecxr", "s -b 04 L4 0x1000"]) {
    assert.equal(validateCdbCommand(allowed), null, allowed);
  }
});

test("resolveCdb prefers an explicit path", async () => {
  await withEnv({ MINUSONE_CDB_PATH: "C:/fake/cdb.exe" }, async () => {
    assert.equal(await resolveCdb(), "C:/fake/cdb.exe");
  });
});

test("CdbDriver.create rejects non-minidump files at the magic check", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "notadump.bin"), "not a dump");
  await withEnv({ MINUSONE_CDB_PATH: "C:/fake/cdb.exe" }, async () => {
    await assert.rejects(() => CdbDriver.create(workspace, "notadump.bin"), /not a minidump/);
  });
});

test("debug.session.create with debugger=cdb is NOT dynamic-gated", async (context) => {
  const operation = operations.find((entry) => entry.id === "debug.session.create");
  const { root, workspace } = await freshWorkspace();
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "dump.dmp"), mdmpMagicBuffer());

  // No dynamic arm — cdb postmortem must still create (a dump is data).
  await withEnv(
    { MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined, MINUSONE_CDB_PATH: "C:/fake/cdb.exe" },
    async () => {
      const created = await operation.execute({ path: "dump.dmp", debugger: "cdb" }, { workspace });
      assert.equal(created.status, "created");
      assert.equal(created.debugger, "cdb");
      assert.equal(created.stopAtEntry, false);
    },
  );
});

test("debug.command on a cdb session is ungated (errors, never refused, without arming)", async (context) => {
  const op = operations.find((entry) => entry.id === "debug.command");
  const { root, workspace } = await freshWorkspace();
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "dump.dmp"), mdmpMagicBuffer());

  await withEnv(
    { MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined, MINUSONE_CDB_PATH: "C:/fake/cdb.exe" },
    async () => {
      const created = await createDebugSession(workspace, "dump.dmp", { debugger: "cdb" });
      // The fake cdb path makes send fail to spawn — but it must error, not
      // refuse, proving the cdb session is not behind the dynamic gate.
      await assert.rejects(
        () => sendDebugCommand(created.sessionId, "lm", 10),
        /spawn|ENOENT|cdb/i,
      );
      try {
        await closeDebugSession(created.sessionId);
      } catch {
        /* session already torn down */
      }
      void op;
    },
  );
});

test("cdb postmortem live: dump a process and inspect modules + threads", { timeout: 180_000 }, async (context) => {
  const cdbPath = await resolveCdb();
  if (cdbPath === null) context.skip("needs cdb (Windows Debugging Tools)");
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the self-dump fixture");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-cdb-live-"));
  context.after(() => rmRoot(root));
  const selfdumpSrc = path.resolve("test", "fixtures", "selfdump.c");
  const selfdumpExe = path.join(root, "selfdump.exe");
  const cc = spawnSync("gcc", ["-O2", "-o", selfdumpExe, selfdumpSrc, "-ldbghelp"], { encoding: "utf8" });
  assert.equal(cc.status, 0, cc.stderr.slice(0, 300));

  const dumpPath = path.join(root, "self.dmp");
  const dumpRun = spawnSync(selfdumpExe, [dumpPath], { encoding: "utf8" });
  assert.equal(dumpRun.status, 0, `${dumpRun.stdout}${dumpRun.stderr}`.slice(0, 300));

  const workspace = await Workspace.create(root);
  const created = await createDebugSession(workspace, "self.dmp", { debugger: "cdb" });
  assert.equal(created.debugger, "cdb");
  context.after(async () => {
    try {
      await closeDebugSession(created.sessionId);
    } catch {
      /* already closed */
    }
  });

  const modules = await sendDebugCommand(created.sessionId, "lm", 90);
  assert.equal(modules.ok, true, modules.error ?? modules.output);
  assert.match(modules.output, /selfdump/, "cdb must list the selfdump module");

  // A second command accumulates into the batch and re-runs against the dump.
  const threads = await sendDebugCommand(created.sessionId, "~", 90);
  assert.equal(threads.ok, true, threads.error ?? threads.output);
  assert.ok(threads.output.length > 0, "thread listing must produce output");

  const closed = await closeDebugSession(created.sessionId);
  assert.ok(closed.commandsExecuted >= 2, `transcript should carry lm + ~, got ${closed.commandsExecuted}`);
  assert.ok(closed.transcript.some((entry) => entry.command === "lm"));
  assert.ok(closed.transcript.some((entry) => entry.command === "~"));
});
