import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { resolveDynamicTarget } from "../dist/core/dynamic.js";
import { Workspace } from "../dist/core/workspace.js";

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dyn-"));
  await writeFile(path.join(root, "sample.bin"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

function fakeJobs() {
  let spec = null;
  return {
    start(received) {
      spec = received;
      return "exec-1";
    },
    get spec() {
      return spec;
    },
  };
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

const EXEC = operations.find((entry) => entry.id === "sample.execute");
const UNPACK = operations.find((entry) => entry.id === "dynamic.unpack");
assert.ok(EXEC, "sample.execute exists");
assert.ok(UNPACK, "dynamic.unpack exists");

test("dynamic target modes resolve from the environment", async () => {
  const mode = (overrides) => withEnv(overrides, () => Promise.resolve(resolveDynamicTarget()));
  assert.equal(await mode({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }), "none");
  assert.equal(await mode({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: undefined }), "armed-no-target");
  assert.equal(await mode({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: "local" }), "local");
});

test("sample.execute refuses unless the local target is armed", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    const refusal = await EXEC.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs: fakeJobs() });
    assert.equal(refusal.status, "refused");
    assert.match(refusal.reason, /disabled by policy/);
  });

  await withEnv({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    const refusal = await EXEC.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs: fakeJobs() });
    assert.equal(refusal.status, "refused");
    assert.match(refusal.reason, /MINUSONE_DYNAMIC_TARGET=local/);
  });
});

test("armed sample.execute needs the job seam and fails settled on a non-executable", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  await withEnv({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: "local" }, async () => {
    await assert.rejects(
      () => EXEC.execute({ path: "sample.bin" }, { workspace: fixture.workspace }),
      /job registry/,
    );

    const jobs = fakeJobs();
    const submission = await EXEC.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs });
    assert.equal(submission.status, "running");
    assert.equal(jobs.spec.kind, "exec");
    const outcome = await jobs.spec.run().done;
    assert.equal(outcome.status, "failed", "spawning a text file cannot succeed");
    assert.match(outcome.detail, /spawn|EFTYPE|ENOENT|EACCES/);
  });
});

test("dynamic.unpack refuses unarmed and fails settled without pe-sieve", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    const refusal = await UNPACK.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs: fakeJobs() });
    assert.equal(refusal.status, "refused");
  });

  await withEnv(
    { MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: "local" },
    async () => {
      const jobs = fakeJobs();
      await UNPACK.execute({ path: "sample.bin" }, { workspace: fixture.workspace, jobs });
      assert.equal(jobs.spec.kind, "unpack");
      const outcome = await jobs.spec.run().done;
      assert.equal(outcome.status, "failed", "spawning a text file cannot succeed");
      assert.match(outcome.detail, /spawn|EFTYPE|ENOENT|EACCES|not available/);
    },
  );
});

test("resolvePeSieve prefers an explicit existing path and falls back to the bundled tool", async () => {
  const { resolvePeSieve } = await import("../dist/core/dynamic.js");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sieve-"));
  try {
    const fake = path.join(root, "sieve.exe");
    await writeFile(fake, "MZ");
    await withEnv({ MINUSONE_PESIEVE_BIN: fake }, () => {
      assert.equal(resolvePeSieve(), fake);
      return Promise.resolve();
    });
    await withEnv({ MINUSONE_PESIEVE_BIN: path.join(root, "missing.exe") }, () => {
      const bundled = path.join(process.cwd(), "tools", "pe-sieve64.exe");
      assert.equal(resolvePeSieve(), bundled, "a stale explicit path falls back to the bundled tool");
      return Promise.resolve();
    });  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/** Minimal PE stub: MZ + e_lfanew + "PE\0\0" + COFF + (no optional header) + section table. */
function fakePe(sectionChars, { rawSize = 0x100 } = {}) {
  const buf = Buffer.alloc(0x80, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c); // e_lfanew -> PE sig
  buf.write("PE", 0x40, "latin1"); // "PE\0\0"
  buf.writeUInt16LE(0x14c, 0x44); // machine (i386)
  buf.writeUInt16LE(1, 0x46); // numberOfSections
  buf.writeUInt16LE(0, 0x54); // sizeOfOptionalHeader
  // section table at 0x40 + 24 + 0 = 0x58
  buf.write("UPX0", 0x58, "latin1"); // name
  buf.writeUInt32LE(0x8000, 0x58 + 8); // virtualSize
  buf.writeUInt32LE(0x1000, 0x58 + 12); // rva
  buf.writeUInt32LE(rawSize, 0x58 + 16); // rawSize
  buf.writeUInt32LE(0x200, 0x58 + 20); // rawPtr
  buf.writeUInt32LE(sectionChars, 0x58 + 36); // characteristics
  return buf;
}

test("normalizeDumpedPe rewrites UPX-style uninitialized executable sections in place", async () => {
  const { normalizeDumpedPe } = await import("../dist/core/dynamic.js");
  const SCN_CNT_CODE = 0x20;
  const SCN_CNT_UNINITIALIZED_DATA = 0x80;
  const SCN_MEM_EXECUTE = 0x2000_0000;

  const upx = fakePe(SCN_MEM_EXECUTE | SCN_CNT_UNINITIALIZED_DATA);
  const result = normalizeDumpedPe(upx);
  assert.equal(result.sections, 1);
  assert.equal(result.patched, true, "the UPX-style section is patched");
  assert.equal(upx.readUInt32LE(0x58 + 36), SCN_MEM_EXECUTE | SCN_CNT_CODE);

  const second = normalizeDumpedPe(upx);
  assert.equal(second.patched, false, "the sanitizer is idempotent");

  const clean = fakePe(SCN_MEM_EXECUTE | SCN_CNT_CODE);
  assert.equal(normalizeDumpedPe(clean).patched, false, "an already-clean section is untouched");

  const noRaw = fakePe(SCN_MEM_EXECUTE | SCN_CNT_UNINITIALIZED_DATA, { rawSize: 0 });
  assert.equal(normalizeDumpedPe(noRaw).patched, false, "a zero-rawSize section (real BSS) is left alone");

  const notPe = Buffer.alloc(0x80, 0);
  assert.equal(normalizeDumpedPe(notPe).sections, 0, "non-PE buffers are skipped");
});

test("executeSample pipes stdin to the sample (interactive crackme pattern)", { timeout: 120_000 }, async (context) => {
  const { executeSample } = await import("../dist/core/dynamic.js");
  const { execFileSync } = await import("node:child_process");
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-stdin-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const binary = path.join(root, "stdincheck.exe");
  let compiled = true;
  try {
    execFileSync("gcc", ["-O0", "-o", binary, path.join(repository, "test", "fixtures", "stdincheck.c")]);
  } catch {
    compiled = false;
  }
  if (!compiled) context.skip("needs gcc");
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

  const result = await executeSample(workspace, "stdincheck.exe", {
    stdin: "tester\nSECRET-123\n",
    timeoutSeconds: 15,
  });
  assert.equal(result.command.exitCode, 0, result.command.stderr);
  assert.match(result.command.stdout, /GOT name=tester serial=SECRET-123/);
});
