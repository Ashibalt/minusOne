import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { surveyBinaries } from "../dist/core/survey.js";
import { operations } from "../dist/core/operations.js";
import { readArtifactFull } from "../dist/core/artifacts.js";
import { upsertSymbols } from "../dist/core/symbols.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function fixturePe(suffix, payload) {
  const buf = Buffer.alloc(0x600, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(1, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24);
  const st = 0x188; // PE@0x80 + 24 (COFF) + sizeOfOptionalHeader(0xf0)
  buf.write(".rdata", st, "latin1");
  buf.writeUInt32LE(0x300, st + 8); // virtual size
  buf.writeUInt32LE(0x1000, st + 12); // virtual address
  buf.writeUInt32LE(0x400, st + 16); // raw size
  buf.writeUInt32LE(0x400, st + 20); // raw pointer
  buf.write(payload, 0x400, "latin1");
  if (suffix !== undefined) {
    buf.writeUInt16LE(0x2000, 0x96); // DLL flag in COFF characteristics (peOffset 0x80 + 22)
  }
  return buf;
}

test("batch.survey: one command produces the full structural table of several files", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-survey-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "a.exe"), fixturePe(undefined, "survey-payload-A"));
  await writeFile(path.join(root, "b.dll"), fixturePe("dll", "survey-payload-B"));
  const workspace = await Workspace.create(root);

  const result = await surveyBinaries(workspace, ["a.exe", "b.dll"]);
  assert.equal(result.fileCount, 2);
  assert.equal(result.files.length, 2);

  const a = result.files[0];
  assert.equal(a.format.kind, "pe");
  assert.equal(a.pe.available, true);
  assert.equal(a.pe.imageBase, "0x140000000");
  assert.equal(a.pe.isDll, false);
  assert.equal(a.pe.sections.length, 1);
  assert.equal(a.pe.sections[0].name, ".rdata");
  assert.equal(a.pe.sections[0].va, "0x140001000");
  assert.equal(a.pe.sections[0].fileOffset, "0x400");

  const b = result.files[1];
  assert.equal(b.pe.isDll, true);

  // The full untruncated table is paged into an artifact.
  assert.ok(a.fullTable.artifactId.length > 0);
  const full = JSON.parse(await readArtifactFull(workspace, a.fullTable.artifactId));
  assert.equal(full.path, "a.exe");
  assert.ok(Array.isArray(full.pe.sections));
});

test("batch.survey: annotated symbols are merged into the table", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-survey-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "a.exe"), fixturePe(undefined, "survey-payload-A"));
  const workspace = await Workspace.create(root);
  const a = await surveyBinaries(workspace, ["a.exe"]);
  const sampleId = a.files[0].sampleId;

  await upsertSymbols(workspace, sampleId, [{ va: "0x140001000", name: "payload_marker", comment: "the A payload" }]);
  const resurveyed = await surveyBinaries(workspace, ["a.exe"]);
  assert.equal(resurveyed.files[0].symbols.count, 1);
  assert.equal(resurveyed.files[0].symbols.entries[0].name, "payload_marker");
});

test("batch.survey: non-PE file degrades to empty planes with a note, never null", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-survey-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "raw.bin"), Buffer.from("not a PE at all"));
  const workspace = await Workspace.create(root);

  const result = await surveyBinaries(workspace, ["raw.bin"]);
  const file = result.files[0];
  assert.equal(file.pe.available, false);
  assert.deepEqual(file.pe.sections, []);
  assert.deepEqual(file.pe.imports.functions, []);
  assert.ok(file.pe.notes.some((note) => /not a parsable PE/.test(note)));
});

test("batch.survey: caps the batch size", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-survey-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await assert.rejects(
    surveyBinaries(workspace, Array.from({ length: 9 }, (_, index) => `f${index}.bin`)),
    /caps at 8 files/,
  );
});

test("batch.survey operation is registered with the output contract", async () => {
  const operation = operations.find((entry) => entry.id === "batch.survey");
  assert.ok(operation, "batch.survey registered");
  assert.equal(operation.toolName, "batch_survey");
  assert.deepEqual(operation.outputSchema.required, ["files", "fileCount", "notes", "next"]);
});
