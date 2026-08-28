import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const REBUILD = operations.find((entry) => entry.id === "pe.rebuild");
assert.ok(REBUILD, "pe.rebuild operation exists");
assert.equal(REBUILD.toolName, "pe_rebuild");

const UPX = path.join(process.cwd(), "tools", "upx.exe");

function commandAvailable(command) {
  const probe = spawnSync(command, ["--version"], { encoding: "utf8" });
  return probe.error === undefined;
}

/**
 * Full unpack-and-rebuild pipeline: UPX-pack a sleeper fixture (stays alive
 * long enough for pe-sieve to catch the unpacked image), dump it with
 * dynamic_unpack, reconstruct with pe.rebuild, then verify the rebuilt
 * image is analysis-grade — strings reachable with RVA/section, original
 * import table restored.
 */
test("pe.rebuild reconstructs an analysis-grade PE from a pe-sieve dump", { timeout: 600_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  if (!commandAvailable(UPX)) context.skip("needs the bundled upx.exe");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-rebuild-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  // Trusted fixture compiled from test/fixtures/sleeper.c: sleeps 20s so the
  // unpacked image stays mapped when pe-sieve scans.
  const plain = path.join(root, "sleeper.exe");
  const packed = path.join(root, "sleeper.packed.exe");
  assert.equal(
    spawnSync("gcc", ["-O0", "-o", plain, path.join(process.cwd(), "test", "fixtures", "sleeper.c")], { encoding: "utf8" }).status,
    0,
    "gcc build failed",
  );
  assert.equal(spawnSync(UPX, ["-q", "-o", packed, plain], { encoding: "utf8" }).status, 0, "upx pack failed");

  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  context.after(() => {
    delete process.env.MINUSONE_ALLOW_DYNAMIC;
    delete process.env.MINUSONE_DYNAMIC_TARGET;
  });

  // ---- unpack: pe-sieve dump of the running packed sample -----------------
  const UNPACK = operations.find((entry) => entry.id === "dynamic.unpack");
  let dumpDir = null;
  let dumpFile = null;
  {
    let settle;
    const settled = new Promise((resolve) => {
      settle = resolve;
    });
    const jobs = {
      start(spec) {
        const handle = spec.run();
        handle.done.then((outcome) => {
          if (outcome.status === "completed") {
            const parsed = JSON.parse(outcome.output);
            dumpDir = parsed.dumpDir;
            const dumped = parsed.dumpedFiles.find((file) => /\.exe$/.test(file.path));
            if (dumped !== undefined) dumpFile = `${dumpDir}/${dumped.path}`.replace(/\\/g, "/");
          }
          settle();
        });
        return "job-1";
      },
    };
    await UNPACK.execute({ path: "sleeper.packed.exe", runSeconds: 4 }, { workspace, jobs });
    await settled;
    assert.ok(dumpFile !== null, "pe-sieve produced a module dump");
  }

  // The unpacked payload must already be visible in the dump (UPX expanded).
  const FIND = operations.find((entry) => entry.id === "binary.find");
  const dumpFind = await FIND.execute({ path: dumpFile, needle: "sleeper-started" }, { workspace });
  assert.ok(dumpFind.hitCount >= 1, "the dump carries the unpacked marker string");

  // ---- rebuild: LIEF reconstruction with the original as import donor ------
  const result = await REBUILD.execute({ path: dumpFile, originalPath: "sleeper.packed.exe" }, { workspace });
  assert.equal(result.report.status, "ok");
  assert.ok(result.bytes > 0);
  assert.match(result.sha256, /^[0-9a-f]{64}$/);
  assert.ok(result.rebuiltPath.includes(".minusone"));

  // ---- the rebuilt image is analysis-grade ---------------------------------
  const rebuiltFind = await FIND.execute({ path: result.rebuiltPath, needle: "sleeper-started" }, { workspace });
  assert.ok(rebuiltFind.hitCount >= 1, "marker reachable in the rebuilt image");
  assert.ok(rebuiltFind.hits[0].rva !== null && rebuiltFind.hits[0].rva !== undefined, "hit carries an RVA");
  assert.ok(rebuiltFind.hits[0].section !== null, "hit carries a section name");

  const TRIAGE = operations.find((entry) => entry.id === "binary.triage");
  const triage = await TRIAGE.execute({ path: result.rebuiltPath }, { workspace });
  assert.ok(triage.imports.functionCount >= 3, `import table restored (${triage.imports.functionCount} functions)`);

  // Report transparency: the repairs list documents what LIEF did.
  assert.ok(result.report.repairs.length >= 1, "repairs list is populated");
  assert.ok(result.report.dumpImports !== null || result.report.importsRestored !== null);
});

test("pe.rebuild rejects non-PE and empty dumps early", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-rebuild-rej-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "notape.bin"), "this is not a PE");

  await assert.rejects(
    () => REBUILD.execute({ path: "notape.bin" }, { workspace }),
    /MZ/,
  );
});
