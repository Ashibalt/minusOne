import assert from "node:assert/strict";
import { mkdtemp, rm, cp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifySignature } from "../dist/core/signatures.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

test("signature.verify LIVE: signed system binary validates; unsigned build reports NotSigned", { timeout: 120_000 }, async (context) => {
  if (process.platform !== "win32") context.skip("win-native signature check");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sig-"));
  context.after(() => rmRoot(root));
  const notepad = path.join(root, "notepad.exe");
  try {
    await cp("C:/Windows/System32/notepad.exe", notepad);
  } catch {
    context.skip("no system notepad to copy");
  }
  await cp(path.resolve(".minusone/smoke/hello.exe"), path.join(root, "hello.exe"));
  const workspace = await Workspace.create(root);

  const signed = await verifySignature(workspace, "notepad.exe");
  assert.equal(signed.backend, "win-native");
  assert.equal(signed.signaturePresent, true);
  assert.equal(signed.status, "Valid");
  assert.equal(signed.valid, true);
  assert.equal(signed.signerCommonName, "Microsoft Windows");
  assert.match(signed.verdict, /VALID SIGNATURE/);

  const unsigned = await verifySignature(workspace, "hello.exe");
  // A gcc-built fixture has no meaningful signature: the OS verdict is the
  // source of truth (NotSigned for a table-less file, or an invalid state
  // if a stub table exists) — never "Valid".
  assert.equal(unsigned.valid, false);
  assert.equal(unsigned.status === null || unsigned.status !== "Valid", true, `status must not be Valid (got ${unsigned.status})`);
  assert.match(unsigned.verdict, /NOT SIGNED|SIGNATURE PRESENT|BROKEN|structural/);
});

test("signature.verify operation is registered with the output contract", async () => {
  const operation = operations.find((entry) => entry.id === "signature.verify");
  assert.ok(operation, "signature.verify registered");
  assert.equal(operation.toolName, "signature_verify");
  assert.deepEqual(operation.outputSchema.required, ["backend", "path", "sampleId", "signaturePresent", "valid", "verdict", "notes"]);
});

test("packed heuristic: a valid signature suppresses entropy-only packed hints", async (context) => {
  // The suppression logic lives in packedVerdict via signatureValid=true;
  // verify through the exported triage path on a signed file with DIE's
  // entropy verdict unavailable (docker down) — the signature note must
  // still appear and packed must stay false.
  if (process.platform !== "win32") context.skip("win-native signature check");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sig2-"));
  context.after(() => rmRoot(root));
  try {
    await cp("C:/Windows/System32/notepad.exe", path.join(root, "notepad.exe"));
  } catch {
    context.skip("no system notepad to copy");
  }
  const workspace = await Workspace.create(root);
  const { triageBinary } = await import("../dist/core/triage.js");
  const report = await triageBinary(workspace, "notepad.exe");
  assert.equal(report.verdict.packed, false, `a validly-signed system binary must not be called packed (why: ${report.verdict.packedWhy.join("; ")})`);
  assert.ok(
    report.verdict.evidenceNotes.some((note) => /valid Authenticode signature/i.test(note)) || report.verdict.notable.some((note) => /valid Authenticode/i.test(note)),
    "the signature finding must surface in triage",
  );
});
