import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { searchBinary } from "../dist/core/search.js";
import { parsePeTablesFromPath } from "../dist/core/peimports.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

async function fixtureWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-search-"));
  return { root, workspace: await Workspace.create(root) };
}

/** Minimal but valid PE: MZ header, PE\0\0, one section covering the whole file. */
function buildFakePe({ payloadAt = 0x400, payload = "" } = {}) {
  const size = 0x600 + payload.length;
  const buf = Buffer.alloc(size);
  buf.write("MZ", 0, "ascii");
  buf.writeUInt32LE(0x80, 0x3c); // e_lfanew
  buf.write("PE\0\0", 0x80, "ascii");
  buf.writeUInt16LE(0x8664, 0x84); // machine x86_64
  buf.writeUInt16LE(1, 0x86); // numberOfSections
  buf.writeUInt16LE(0xf0, 0x94); // sizeOfOptionalHeader
  buf.writeUInt16LE(0x20b, 0x98); // optional magic PE32+
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24); // imageBase
  // section table at 0x80 + 24 + 0xf0 = 0x188
  const sectionTable = 0x188;
  buf.write(".payload", sectionTable, "ascii");
  buf.writeUInt32LE(0x200, sectionTable + 8); // virtualSize
  buf.writeUInt32LE(0x1000, sectionTable + 12); // virtualAddress
  buf.writeUInt32LE(0x400, sectionTable + 16); // rawSize
  buf.writeUInt32LE(0x400, sectionTable + 20); // pointerToRawData
  buf.write(payload, payloadAt, "ascii");
  return buf;
}

test("binary.search scans the WHOLE file regardless of size (no byte ceiling)", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  // 20MB file with the needle at the very END — beyond any historical cap.
  const chunk = Buffer.alloc(1024 * 1024, 0x41); // 1MB of 'A'
  const file = path.join(root, "huge.bin");
  const { open } = await import("node:fs/promises");
  const handle = await open(file, "w");
  try {
    for (let round = 0; round < 20; round += 1) await handle.write(chunk);
    await handle.write(Buffer.from("needle-deep-in-the-file", "ascii"));
  } finally {
    await handle.close();
  }

  const result = await searchBinary(workspace, "huge.bin", { needle: "needle-deep-in-the-file" });
  assert.equal(result.hitCount, 1);
  assert.ok(result.hits[0].offset > 20 * 1024 * 1024 - 64, "hit offset is at the file tail");
  assert.equal(result.scanComplete, true);
  assert.equal(result.fileSize, result.scannedBytes);
  assert.ok(result.durationMs >= 0);
});

test("binary.search finds matches spanning chunk boundaries (overlap discipline)", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  // Force tiny chunks by placing a needle exactly across the 8MB boundary.
  const size = 8 * 1024 * 1024;
  const buf = Buffer.alloc(size + 16);
  buf.write("BORDER", 8 * 1024 * 1024 - 3, "ascii"); // spans the boundary
  await writeFile(path.join(root, "border.bin"), buf);

  const result = await searchBinary(workspace, "border.bin", { needle: "BORDER" });
  assert.equal(result.hitCount, 1, "boundary-spanning match found exactly once");
  assert.equal(result.hits[0].offset, 8 * 1024 * 1024 - 3);
});

test("binary.search hex bytes + case-insensitive + encodings filter", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  await writeFile(path.join(root, "mix.bin"), Buffer.concat([
    Buffer.from("Hello WORLD here", "ascii"),
    Buffer.from("h\x00e\x00l\x00l\x00o\x00", "ascii"), // utf16le "hello"
    Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
  ]));

  const hex = await searchBinary(workspace, "mix.bin", { needle: "4d5a90", kind: "bytes" });
  assert.equal(hex.hitCount, 1);
  assert.equal(hex.hits[0].encoding, "hex");

  const insensitive = await searchBinary(workspace, "mix.bin", { needle: "hello world" });
  assert.equal(insensitive.hitCount, 1, "case-insensitive ascii match");

  const utf16 = await searchBinary(workspace, "mix.bin", { needle: "hello", encodings: ["utf16le"] });
  assert.equal(utf16.hitCount, 1);
  assert.equal(utf16.hits[0].encoding, "utf16le");
});

test("binary.search regex matches, hit cap, and window semantics", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  const parts = [];
  for (let index = 0; index < 30; index += 1) parts.push(`item-${index}`);
  const blob = parts.join(" | ");
  await writeFile(path.join(root, "regex.bin"), blob);

  const all = await searchBinary(workspace, "regex.bin", { needle: "item-\\d+", kind: "regex" });
  assert.equal(all.hitCount, 30, "every regex match found");
  assert.equal(all.scanComplete, true);

  const capped = await searchBinary(workspace, "regex.bin", { needle: "item-\\d+", kind: "regex", maxHits: 5 });
  assert.equal(capped.hits.length, 5);
  assert.equal(capped.truncated, true);
  assert.ok(capped.next.some((hint) => hint.includes("raise maxHits")), "hit-cap hint present");

  // Window semantics: startOffset excludes earlier matches.
  const cutoff = blob.indexOf("item-10");
  const tail = await searchBinary(workspace, "regex.bin", { needle: "item-\\d+", kind: "regex", startOffset: cutoff });
  assert.equal(tail.hitCount, 20, "matches from item-10 onward");
  assert.equal(tail.hits[0].value, "item-10");
  assert.equal(tail.scannedFrom, cutoff);
});

test("binary.search attaches PE section/RVA/VA context to hits (random-access tables)", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  const pe = buildFakePe({ payload: "trial_blocked" });
  await writeFile(path.join(root, "sample.exe"), pe);

  const result = await searchBinary(workspace, "sample.exe", { needle: "trial_blocked" });
  assert.equal(result.hitCount, 1);
  const hit = result.hits[0];
  assert.equal(hit.section, ".payload");
  assert.equal(hit.rva, 0x1000 + (0x400 - 0x400) + 0); // payload at raw 0x400 → RVA 0x1000
  assert.equal(hit.va, "0x140001000");
});

test("binary.search: whole-file false-y scan says so honestly", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  await writeFile(path.join(root, "empty-of-it.bin"), Buffer.from("nothing to see"));
  const result = await searchBinary(workspace, "empty-of-it.bin", { needle: "absent-needle" });
  assert.equal(result.hitCount, 0);
  assert.equal(result.scanComplete, true);
  assert.ok(result.next.some((hint) => hint.includes("strings_extract_deep")), "FLOSS hint present");
});

test("parsePeTablesFromPath reads an import table located beyond 64MB (random access, no truncation)", async (context) => {
  const { root, workspace } = await fixtureWorkspace();
  context.after(() => rmRoot(root));

  // Section table maps .idata at RVA 0x100000 → file offset 100MB+0x400.
  // The import structures live FAR beyond the historical 64MB read cap;
  // random-access parsing must still walk them completely.
  const importBlockOffset = 100 * 1024 * 1024 + 0x400;
  const header = buildFakePe();
  // Rewrite the single section to cover the far-away import data.
  const sectionTable = 0x188;
  header.write(".idata", sectionTable, "ascii");
  header.writeUInt32LE(0x1000, sectionTable + 8); // virtualSize
  header.writeUInt32LE(0x100000, sectionTable + 12); // virtualAddress
  header.writeUInt32LE(0x1000, sectionTable + 16); // rawSize
  header.writeUInt32LE(importBlockOffset, sectionTable + 20); // pointerToRawData
  // Data directory #1 (imports): PE32+ directories at optionalHeader+112.
  const optionalHeader = 0x98;
  header.writeUInt32LE(0x100000, optionalHeader + 112 + 8); // import dir RVA

  const file = path.join(root, "huge-imports.exe");
  const { open } = await import("node:fs/promises");
  const handle = await open(file, "w");
  try {
    await handle.write(header, 0, header.length, 0);
    // Sparse-extend the file: writing the import block at 100MB+0x400 makes
    // everything before it a hole the reader must NOT need.
    const importBlock = Buffer.alloc(0x400);
    importBlock.write("KERNEL32.DLL", 0x40, "ascii"); // DLL name
    // Import descriptor at offset 0: OriginalFirstThunk=0x100100, Name=0x100040, FirstThunk=0x100200
    importBlock.writeUInt32LE(0x100100, 0);
    importBlock.writeUInt32LE(0x100040, 12);
    importBlock.writeUInt32LE(0x100200, 16);
    // Thunk at 0x100 (RVA 0x100100): name RVA 0x100080, then terminator
    importBlock.writeUInt32LE(0x100080, 0x100);
    importBlock.writeUInt32LE(0, 0x104);
    // Hint/name at 0x80 (RVA 0x100080): hint=0, then "CreateFileW"
    importBlock.write("CreateFileW", 0x82, "ascii");
    await handle.write(importBlock, 0, importBlock.length, importBlockOffset);
  } finally {
    await handle.close();
  }

  const tables = await parsePeTablesFromPath(file);
  assert.notEqual(tables, null, "PE recognized from the lead header");
  assert.equal(tables.importDlls.length, 1);
  assert.equal(tables.importDlls[0], "KERNEL32.DLL");
  assert.equal(tables.imports.length, 1);
  assert.equal(tables.imports[0].name, "CreateFileW");
  assert.equal(tables.imports[0].iatVa, 0x140000000 + 0x100200);
  // No truncation note: the whole table was read via positioned reads.
  assert.ok(!tables.partial.some((note) => note.includes("truncated")), `partial notes: ${tables.partial.join("; ")}`);
});
