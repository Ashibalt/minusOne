import assert from "node:assert/strict";
import { mkdtemp, rm, cp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifySignature, locateCertificateTable } from "../dist/core/signatures.js";
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
  // signaturePresent means an EMBEDDED certificate table (data directory 4).
  // System binaries like notepad are typically CATALOG-signed (no embedded
  // table) while Get-AuthenticodeSignature still validates them via the
  // catalog — so `valid` is the OS verdict and `signaturePresent` stays
  // false here. (The old +4*4 offset arithmetic read the RESOURCE table
  // instead and reported present=true for nearly every PE.)
  assert.equal(typeof signed.signaturePresent, "boolean");
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

test("locateCertificateTable reads data-directory index 4, not the resource table", async (context) => {
  // CERTIFICATE_TABLE is directory entry 4 (8 bytes per entry): offset
  // opt+112+4*8 (PE32+) or opt+96+4*8 (PE32). The old +4*4 arithmetic read
  // entry 2 (RESOURCE_TABLE) instead, so nearly every PE with resources
  // looked "signature present".
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-sig3-"));
  context.after(() => rmRoot(root));

  const pe64 = Buffer.alloc(0x400);
  pe64.write("MZ", 0, "ascii");
  pe64.writeUInt32LE(0x100, 0x3c);
  pe64.write("PE\0\0", 0x100, "ascii");
  const opt = 0x100 + 24;
  pe64.writeUInt16LE(0x20b, opt); // PE32+
  // Decoy in the resource entry (index 2): the buggy read returned this.
  const resourceDir = opt + 112 + 2 * 8;
  pe64.writeUInt32LE(0x9999, resourceDir);
  pe64.writeUInt32LE(0x9999, resourceDir + 4);
  const certDir = opt + 112 + 4 * 8;
  pe64.writeUInt32LE(0x2000, certDir);
  pe64.writeUInt32LE(0x300, certDir + 4);
  const file64 = path.join(root, "pe64.bin");
  await writeFile(file64, pe64);
  assert.deepEqual(await locateCertificateTable(file64), { offset: 0x2000, size: 0x300 });

  const pe32 = Buffer.alloc(0x400);
  pe32.write("MZ", 0, "ascii");
  pe32.writeUInt32LE(0x100, 0x3c);
  pe32.write("PE\0\0", 0x100, "ascii");
  pe32.writeUInt16LE(0x10b, opt); // PE32
  const certDir32 = opt + 96 + 4 * 8;
  pe32.writeUInt32LE(0x3000, certDir32);
  pe32.writeUInt32LE(0x180, certDir32 + 4);
  const file32 = path.join(root, "pe32.bin");
  await writeFile(file32, pe32);
  assert.deepEqual(await locateCertificateTable(file32), { offset: 0x3000, size: 0x180 });

  // Zero certificate entry → absent, even with the resource decoy present.
  pe64.writeUInt32LE(0, certDir);
  pe64.writeUInt32LE(0, certDir + 4);
  await writeFile(file64, pe64);
  assert.equal(await locateCertificateTable(file64), null);
});
