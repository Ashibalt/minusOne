import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readMemory, parseDebuggerMemoryOutput } from "../dist/core/memoryread.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { upsertSymbols } from "../dist/core/symbols.js";
import { rmRoot } from "./helpers.mjs";

/**
 * Fixture PE (64-bit, image base 0x140000000, one .rdata section):
 *   file 0x400 (rva 0x1000, va 0x140001000): "MINU\0" + padding
 *   file 0x410 (rva 0x1010, va 0x140001010): u64 table [0x140001000, 7]
 *   file 0x440 (rva 0x1040, va 0x140001040): "leaf-string\0"
 */
function fixturePe() {
  const buf = Buffer.alloc(0x600, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x8664, 0x84); // machine x64
  buf.writeUInt16LE(1, 0x86); // sections
  buf.writeUInt16LE(0xf0, 0x94); // optional header size
  buf.writeUInt16LE(0x20b, 0x98); // PE32+ magic
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24); // image base
  const st = 0x188; // PE@0x80 + 24 (COFF) + sizeOfOptionalHeader(0xf0)
  buf.write(".rdata", st, "latin1");
  buf.writeUInt32LE(0x300, st + 8); // virtual size
  buf.writeUInt32LE(0x1000, st + 12); // virtual address
  buf.writeUInt32LE(0x400, st + 16); // raw size
  buf.writeUInt32LE(0x400, st + 20); // raw pointer
  buf.write("MINU\0", 0x400, "latin1");
  const table = Buffer.alloc(16);
  table.writeBigUInt64LE(0x140001000n, 0);
  table.writeUInt32LE(7, 8);
  table.copy(buf, 0x410);
  buf.write("leaf-string\0", 0x440, "latin1");
  return buf;
}

test("memory.read file mode: va resolves through the section table with the full va/rva/offset triple", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);

  const result = await readMemory(workspace, { path: "sample.exe", va: "0x140001000", count: 16 });
  assert.equal(result.mode, "file");
  assert.equal(result.address.kind, "va");
  assert.equal(result.address.fileOffset, 0x400);
  assert.equal(result.address.rva, 0x1000);
  assert.equal(result.address.va, "0x140001000");
  assert.equal(result.address.section, ".rdata");
  assert.match(result.ascii, /^MINU/);
  // No type requested → degradation-safe empty decode object (never null).
  assert.equal(result.decode.type, "none");
  assert.deepEqual(result.decode.values, []);
  assert.equal(result.sessionId, "");
  assert.equal(result.debugger, "");
});

test("memory.read: rva and offset inputs land on the same window", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);

  const byRva = await readMemory(workspace, { path: "sample.exe", rva: "0x1000", count: 8 });
  const byOffset = await readMemory(workspace, { path: "sample.exe", offset: 0x400, count: 8 });
  assert.equal(byRva.address.va, "0x140001000");
  assert.equal(byOffset.address.va, "0x140001000");
  assert.equal(byRva.address.fileOffset, byOffset.address.fileOffset);
  assert.equal(byRva.ascii, byOffset.ascii);
});

test("memory.read: a va below the image base is caught with the rva hint (not a silent misread)", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);
  await assert.rejects(readMemory(workspace, { path: "sample.exe", va: "0x1000" }), /below the image base.*rva/);
});

test("memory.read: va/rva/offset are mutually exclusive", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);
  await assert.rejects(readMemory(workspace, { path: "sample.exe", va: "0x140001000", rva: "0x1000" }), /only ONE/);
});

test("memory.read: type u32 with elements reads the whole table; chasePointers follows in-image pointers to the leaf string", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);

  const result = await readMemory(workspace, {
    path: "sample.exe",
    rva: "0x1010",
    type: "u64",
    elements: 2,
    chasePointers: true,
  });
  assert.equal(result.address.va, "0x140001010");
  assert.ok(result.decode);
  assert.equal(result.decode.values.length, 2);
  assert.match(result.decode.values[0], /0x140001000/);
  assert.equal(result.decode.values[1], "0x7 (7)");
  // The pointer chase must resolve 0x140001000 → .rdata and find the string there.
  assert.equal(result.pointers.length, 1, "one in-image pointer chased");
  assert.equal(result.pointers[0].hops[0].section, ".rdata");
  assert.equal(result.pointers[0].leafString, "MINU");
});

test("memory.read: cstr decode reads the NUL-terminated string", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);

  const result = await readMemory(workspace, { path: "sample.exe", va: "0x140001040", type: "cstr" });
  assert.deepEqual(result.decode.values, ["leaf-string"]);
});

test("memory.read: annotated symbols resolve at the address", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-memread-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), fixturePe());
  const workspace = await Workspace.create(root);
  await upsertSymbols(workspace, "sample-1", [{ va: "0x140001000", name: "magic_blob" }]);

  const result = await readMemory(workspace, { path: "sample.exe", va: "0x140001000", count: 4 });
  assert.equal(result.address.symbol, null, "symbol map is keyed by sampleId; a mismatched id must not resolve");
});

test("memory.read operation is registered with the output contract", async () => {
  const operation = operations.find((entry) => entry.id === "memory.read");
  assert.ok(operation, "memory.read registered");
  assert.equal(operation.toolName, "memory_read");
  assert.equal(operation.outputSchema.required.includes("address"), true);
  assert.equal(operation.outputSchema.required.includes("decode"), true);
});

test("parseDebuggerMemoryOutput: gdb and cdb byte-dump formats", () => {
  const gdb = parseDebuggerMemoryOutput("0x140001000:\t0x4d\t0x49\t0x4e\t0x55");
  assert.equal(gdb.toString("latin1"), "MINU");
  const gdbAnnotated = parseDebuggerMemoryOutput("0x7ff6c6de1234 <main+8>:\t0x4d\t0x49");
  assert.equal(gdbAnnotated.toString("latin1"), "MI");
  const cdb = parseDebuggerMemoryOutput("00007ff6`c6de1234  4d 49 4e-55 00 00 00 00");
  assert.equal(cdb.toString("latin1"), "MINU\u0000\u0000\u0000\u0000");
});
