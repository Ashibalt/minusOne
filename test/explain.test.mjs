import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { explainNeedle } from "../dist/core/explain.js";
import { unpackStatic, parseUpxRatio } from "../dist/core/unpack-static.js";
import { Workspace } from "../dist/core/workspace.js";
import { operations } from "../dist/core/operations.js";
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

/** Minimal PE with one section; needle placed inside it. */
function fakePe(payload) {
  const buf = Buffer.alloc(0x600, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24);
  const st = 0x188;
  buf.write(".rdata", st, "latin1");
  buf.writeUInt32LE(0x200, st + 8);
  buf.writeUInt32LE(0x1000, st + 12);
  buf.writeUInt32LE(0x400, st + 16);
  buf.writeUInt32LE(0x400, st + 20);
  buf.write(payload, 0x400, "latin1");
  return buf;
}

test("binary.explain without IDA falls back to the Ghidra references backend (or records its absence honestly)", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-explain-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "sample.exe"), fakePe("trial_blocked_here"));

  await withEnv({ MINUSONE_IDA_DISABLED: "1" }, async () => {
    const result = await explainNeedle(workspace, "sample.exe", { needle: "trial_blocked" });
    assert.equal(result.stages[0].stage, "search");
    assert.equal(result.stages[0].status, "ok");
    assert.ok(result.search.hitCount >= 1);
    assert.ok(result.search.hits.some((hit) => hit.va === "0x140001000"), "VA computed from PE tables");
    const xrefStage = result.stages.find((stage) => stage.stage === "xrefs");
    const decompileStage = result.stages.find((stage) => stage.stage === "decompile");
    // Two valid outcomes depending on backend availability:
    //  - Ghidra present: xrefs answered by the references backend (never a
    //    dead skip); decompile ok OR skipped when nothing references the
    //    string in a stub PE (no code exists to reference it)
    //  - no backend at all: failed with the reason recorded
    if (xrefStage.status === "ok") {
      assert.ok(xrefStage.detail.includes("Ghidra"), `detail: ${xrefStage.detail}`);
      assert.ok(decompileStage.status === "ok" || decompileStage.status === "skipped");
      if (decompileStage.status === "skipped") {
        assert.ok((decompileStage.detail ?? "").includes("no referring functions") || (decompileStage.detail ?? "").includes("no decompilations"));
      }
    } else {
      assert.equal(xrefStage.status, "failed");
      assert.ok(xrefStage.detail.includes("ghidra") || xrefStage.detail.includes("IDA"), `detail: ${xrefStage.detail}`);
    }
    // Reference sites hand back addresses either way.
    assert.ok(result.referenceSites.length >= 1);
    assert.equal(result.referenceSites[0].address, "0x140001000");
  });
});

test("binary.explain with no hits stops after search and suggests FLOSS", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-explain2-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "sample.exe"), fakePe("nothing interesting"));

  const result = await explainNeedle(workspace, "sample.exe", { needle: "absent-thing" });
  assert.equal(result.search.hitCount, 0);
  assert.equal(result.stages.length, 3);
  assert.ok(result.next.some((hint) => hint.includes("strings_extract_deep")));
});

test("operations table registers binary_search, binary_explain, unpack_static", () => {
  const ids = operations.map((operation) => operation.id);
  assert.ok(ids.includes("binary.search"), "binary.search registered");
  assert.ok(ids.includes("binary.explain"), "binary.explain registered");
  assert.ok(ids.includes("unpack.static"), "unpack.static registered");

  const search = operations.find((operation) => operation.id === "binary.search");
  // No maxScanBytes parameter at all — there is no ceiling by design.
  assert.equal(search.parameters.properties.maxScanBytes, undefined);
  assert.equal(search.parameters.properties.startOffset.minimum, 0);

  const explain = operations.find((operation) => operation.id === "binary.explain");
  assert.deepEqual(explain.parameters.required, ["path", "needle"]);

  const strings = operations.find((operation) => operation.id === "strings.extract");
  assert.equal(strings.parameters.properties.limit.maximum, undefined, "strings limit uncapped");
  assert.equal(strings.parameters.properties.maxScanBytes.maximum, undefined, "strings scan uncapped");

  const find = operations.find((operation) => operation.id === "binary.find");
  assert.equal(find.parameters.properties.maxScanBytes.maximum, undefined, "find scan uncapped");
});

test("unpackStatic reports not-UPX honestly (probe semantics)", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-upx-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "plain.exe"), fakePe("not packed at all"));

  // Force docker-null via MINUSONE_PE_TOOLS_IMAGE="" and no local upx
  // — expect the disabled error (no backend), OR with docker available the
  // not-UPX refusal. Either way the operation must not throw for non-UPX.
  const result = await unpackStatic(workspace, "plain.exe");
  assert.equal(result.packed, false);
  assert.equal(result.outputPath, null);
  assert.ok(result.notes.length > 0, "upx's own refusal is surfaced");
});

test("parseUpxRatio extracts the summary line", () => {
  assert.equal(
    parseUpxRatio("                       UberBLOX  [  45.6% ]  file.exe -> file-unpacked.exe"),
    "file.exe -> file-unpacked.exe",
  );
  assert.equal(parseUpxRatio("no banner"), null);
});
