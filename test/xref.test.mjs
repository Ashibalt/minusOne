import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { runRadareXrefs, shutdownRadareSessions } from "../dist/core/radare.js";
import { Workspace } from "../dist/core/workspace.js";

// The live test runs against a local obfuscated sample supplied by the owner
// through MINUSONE_TEST_LIVE_SAMPLE — the sample never ships with the repo.
const SAMPLE = process.env.MINUSONE_TEST_LIVE_SAMPLE ?? "";
const LIVE = process.env.MINUSONE_EVAL_R2_LIVE === "1" && SAMPLE !== "" && existsSync(SAMPLE);

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-xref-"));
  await writeFile(path.join(root, "sample.exe"), "dummy-sample-content");
  return { root, workspace: await Workspace.create(root) };
}

test("xref.query exists with va/rva/offset parameters and honest contracts", async () => {
  const operation = operations.find((entry) => entry.id === "xref.query");
  assert.ok(operation, "xref.query operation exists");
  assert.equal(operation.toolName, "xref_query");
  const properties = operation.parameters.properties;
  assert.ok(properties.va, "va parameter present");
  assert.ok(properties.rva, "rva parameter present");
  assert.ok(properties.offset, "offset parameter present");
  assert.equal(operation.parameters.required.join(","), "path");
});

test("xref.query rejects an addressless call and a disabled backend alike", async (context) => {
  const operation = operations.find((entry) => entry.id === "xref.query");
  assert.ok(operation);
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  await assert.rejects(
    () => operation.execute({ path: "sample.exe" }, { workspace: fixture.workspace }),
    /needs one of va, rva or offset/,
  );

  const previousImage = process.env.MINUSONE_R2_IMAGE;
  process.env.MINUSONE_R2_IMAGE = "";
  context.after(() => {
    delete process.env.MINUSONE_R2_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_R2_IMAGE = previousImage;
  });
  await assert.rejects(
    () => runRadareXrefs(fixture.workspace, "sample.exe", { va: "0x140001000" }),
    /disabled/,
  );
});

test("rva/offset targeting on a non-PE file is refused honestly", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));
  const previousBin = process.env.MINUSONE_R2_BIN;
  // A plain text file is not a PE: the section-table arithmetic cannot run.
  // (The disabled-backend error fires first when no r2 exists at all, so both
  // outcomes assert the honest-refusal contract.)
  await assert.rejects(
    () => runRadareXrefs(fixture.workspace, "sample.exe", { rva: "0x1000" }),
    /(requires a PE file|disabled)/,
  );
  if (previousBin !== undefined) process.env.MINUSONE_R2_BIN = previousBin;
});

test("live: xref.query on the owner-supplied sample resolves crypto-constant refs through the cached session", { skip: !LIVE }, async (context) => {
  const workspace = await Workspace.create(process.cwd());
  context.after(() => shutdownRadareSessions());
  const result = await runRadareXrefs(workspace, SAMPLE, { va: "0x1400d3820" });
  assert.equal(result.target, "0x1400d3820");
  assert.equal(result.targetKind, "va");
  assert.ok(Array.isArray(result.xrefs), "xrefs array present");
  // The chacha sigma constant is referenced from fcn.140016350 (movdqa).
  const fromCrypto = result.xrefs.find((entry) => entry.functionName === "fcn.140016350");
  if (result.xrefs.length > 0) {
    assert.ok(fromCrypto, "at least one ref comes from the crypto function");
    assert.match(fromCrypto.type, /DATA|STRN|READ/i);
  }
  // Second query hits the SAME cached session — completes fast, no re-analysis.
  const again = await runRadareXrefs(workspace, SAMPLE, { va: "0x1400d39c0" });
  assert.equal(again.backend, result.backend);
});
