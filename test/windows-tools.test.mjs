import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { detectWindowsTool, detectWindowsToolchain, TOOL_SPECS } from "../dist/core/windows-tools.js";

async function fakeInstall(root, toolDir, executable, content = "MZ fake") {
  const directory = path.join(root, toolDir);
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, executable), content);
  return directory;
}

test("tool specs cover the native Windows debugging and instrumentation spectrum", () => {
  const names = TOOL_SPECS.map((spec) => spec.name);
  for (const expected of ["x64dbg", "x32dbg", "windbg", "cdb", "cheat-engine", "system-informer", "procmon", "procexp", "frida"]) {
    assert.ok(names.includes(expected), `${expected} must be detected`);
  }
  for (const spec of TOOL_SPECS) {
    assert.match(spec.env, /^MINUSONE_[A-Z0-9_]+$/, `${spec.name} needs an env override`);
  }
});

test("override resolution finds executables inside a directory and rejects stale overrides", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-wtools-"));
  context.after(() => rm(root, { recursive: true, force: true }));

  const cdbSpec = TOOL_SPECS.find((spec) => spec.name === "cdb");
  const cdbHome = await fakeInstall(root, "Debuggers", "cdb.exe");
  process.env.MINUSONE_CDB_PATH = cdbHome;
  const found = await detectWindowsTool(cdbSpec);
  assert.equal(found.available, true);
  assert.equal(found.path, path.resolve(path.join(cdbHome, "cdb.exe")));

  const x64Spec = TOOL_SPECS.find((spec) => spec.name === "x64dbg");
  process.env.MINUSONE_X64DBG_HOME = path.join(root, "missing-dir");
  const stale = await detectWindowsTool(x64Spec);
  assert.equal(stale.available, false, "an override pointing nowhere is reported missing");
  assert.match(stale.note, /resolves to nothing/);

  delete process.env.MINUSONE_CDB_PATH;
  delete process.env.MINUSONE_X64DBG_HOME;
  context.after(() => {
    delete process.env.MINUSONE_CDB_PATH;
    delete process.env.MINUSONE_X64DBG_HOME;
  });
});

test("toolchain summary flags debugger drivers and the scriptable bridge", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-wchain-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const home = await fakeInstall(root, "x64dbg", "x64dbg.exe");
  process.env.MINUSONE_X64DBG_HOME = home;
  try {
    const toolchain = await detectWindowsToolchain();
    assert.equal(toolchain.tools.length, TOOL_SPECS.length);
    assert.equal(toolchain.hasDebuggerDriver, true);
    assert.equal(toolchain.hasScriptableBridge, toolchain.tools.find((tool) => tool.name === "cdb")?.available === true);
  } finally {
    delete process.env.MINUSONE_X64DBG_HOME;
  }
  assert.equal(
    (await detectWindowsToolchain()).tools.length,
    TOOL_SPECS.length,
    "detection never throws without overrides",
  );
});
