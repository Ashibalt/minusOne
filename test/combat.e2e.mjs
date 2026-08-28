import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

/**
 * The combat-readiness gate: one fixture walks the full operational path an
 * analyst would run against a real packed sample —
 *   pack → binary.triage → binary.find → unpack.chain (dump + rebuild)
 *   → binary.find on the rebuilt image → report.correlate → report.findings.
 * Every step goes through the public operation surface (no internal APIs),
 * on the real backends (gcc, UPX, pe-sieve, LIEF docker, DIE, binwalk).
 * Green means: the katana cuts.
 */
const TRIAGE = operations.find((entry) => entry.id === "binary.triage");
const FIND = operations.find((entry) => entry.id === "binary.find");
const UNPACK_CHAIN = operations.find((entry) => entry.id === "unpack.chain");
const CORRELATE = operations.find((entry) => entry.id === "report.correlate");
const FINDINGS = operations.find((entry) => entry.id === "report.findings");

const UPX = path.join(process.cwd(), "tools", "upx.exe");

test("combat e2e: packed sample from first sight to a recorded finding", { timeout: 900_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc");
  if (spawnSync(UPX, ["--version"], { encoding: "utf8" }).status !== 0) context.skip("needs the bundled upx.exe");

  // ---- fixture: a trusted sleeper carrying a findable secret ----------------
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-combat-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const source = path.join(root, "combat.c");
  await writeFile(source, [
    "#include <stdio.h>",
    "#include <windows.h>",
    "int main(void) {",
    "  FILE *note = fopen(\"combat-note.txt\", \"w\");",
    "  if (note) { fputs(\"MINUSONE_COMBAT_SECRET_77\", note); fclose(note); }",
    "  puts(\"combat-started\");",
    "  Sleep(20000);",
    "  return 0;",
    "}",
    "",
  ].join("\n"));
  const plain = path.join(root, "combat.exe");
  const packed = path.join(root, "combat.packed.exe");
  assert.equal(spawnSync("gcc", ["-O0", "-o", plain, source], { encoding: "utf8" }).status, 0, "gcc build failed");
  assert.equal(spawnSync(UPX, ["-q", "-o", packed, plain], { encoding: "utf8" }).status, 0, "upx pack failed");

  // ---- 1. first sight: triage flags the sample as packed --------------------
  const triage = await TRIAGE.execute({ path: "combat.packed.exe" }, { workspace });
  assert.equal(triage.format.kind, "pe");
  assert.equal(triage.verdict.packed, true, "triage must flag the UPX sample");
  assert.ok(triage.verdict.packedWhy.length >= 1);
  assert.ok(triage.next.some((hint) => /dynamic_unpack|unpack_chain/.test(hint)), "packed verdict steers toward unpacking");
  // The plaintext secret must NOT be reachable in the packed image.
  const packedFind = await FIND.execute({ path: "combat.packed.exe", needle: "MINUSONE_COMBAT_SECRET_77" }, { workspace });
  assert.equal(packedFind.hitCount, 0, "the secret is compressed inside the packed image");

  // ---- 2. the chain: dump the unpacked image and rebuild it ------------------
  const savedAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const savedTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  let chainReport = null;
  try {
    let settleChain;
    const chainSettled = new Promise((resolve) => {
      settleChain = resolve;
    });
    const jobs = {
      start(spec) {
        const handle = spec.run();
        handle.done.then((outcome) => settleChain(outcome));
        return "combat-1";
      },
    };
    await UNPACK_CHAIN.execute({ path: "combat.packed.exe", runSeconds: 4 }, { workspace, jobs });
    const chainOutcome = await chainSettled;
    assert.equal(chainOutcome.status, "completed", `chain failed: ${chainOutcome.detail ?? ""}`);
    chainReport = JSON.parse(chainOutcome.output);

    const stages = Object.fromEntries(chainReport.stages.map((stage) => [stage.stage, stage]));
    assert.equal(stages["post-triage"].status, "ok", stages["post-triage"].detail);
    // Two valid routes: the UPX static fast-path (upx -d, no execution) or
    // the dynamic pe-sieve + LIEF rebuild. Either must produce a rebuilt
    // image whose strings/imports are statically reachable.
    if (stages["UPX static unpack"]?.status === "ok") {
      assert.ok(chainReport.rebuiltPath.includes("unpack-static"), "static route produced the unpacked image");
    } else {
      assert.equal(stages["pe-sieve unpack"].status, "ok", stages["pe-sieve unpack"].detail);
      assert.equal(stages["LIEF rebuild"].status, "ok", stages["LIEF rebuild"].detail);
    }
  } finally {
    if (savedAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = savedAllow;
    if (savedTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = savedTarget;
  }

  // ---- 3. the secret is now statically reachable in the rebuilt image --------
  const rebuiltFind = await FIND.execute(
    { path: chainReport.rebuiltPath, needle: "MINUSONE_COMBAT_SECRET_77" },
    { workspace },
  );
  assert.ok(rebuiltFind.hitCount >= 1, "the unpacked secret must be findable in the rebuilt image");
  assert.ok(rebuiltFind.hits[0].section !== null, "the hit carries a section");
  assert.ok(rebuiltFind.hits[0].rva !== null, "the hit carries an RVA");

  // ---- 4. correlate fuses static anchors with the dump evidence ---------------
  // (dynamic route only — the UPX static route produced no dump directory)
  if (chainReport.dumpDir !== null) {
    const dumpDir = chainReport.dumpDir;
    const correlation = await CORRELATE.execute(
      { dumpDirPath: dumpDir, samplePath: "combat.packed.exe" },
      { workspace },
    );
    assert.equal(correlation.schema, 2);
    assert.ok(correlation.sources.dumps, "the dump directory is a recorded source");
    assert.ok(correlation.sources.staticAnchor, "the static anchor is recorded");
    assert.ok(Array.isArray(correlation.dumps) && correlation.dumps.length >= 1, "dumped modules are listed");
  }

  // ---- 5. the conclusion lands in the durable case file ------------------------
  const recorded = await FINDINGS.execute({
    title: "Packed sample: secret recovered from the unpacked image",
    severity: "high",
    notes: `UPX-packed sample; unpack_chain dumped and rebuilt the image; binary_find located MINUSONE_COMBAT_SECRET_77 in ${rebuiltFind.hits[0].section} at RVA ${rebuiltFind.hits[0].rva}`,
    evidence: [],
  }, { workspace });
  assert.equal(recorded.findings.length, 1);
  assert.equal(recorded.findings[0].severity, "high");

  const listed = await FINDINGS.execute({}, { workspace });
  assert.equal(listed.findings[0].title, "Packed sample: secret recovered from the unpacked image");
});
