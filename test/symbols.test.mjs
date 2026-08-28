import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadSymbolIndex, lookupSymbol, lookupSymbolString, parseVa, readSymbolMap, removeSymbols, upsertSymbols, formatVa } from "../dist/core/symbols.js";
import { operations } from "../dist/core/operations.js";
import { searchBinary } from "../dist/core/search.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

/** Minimal PE: string payload inside .rdata at RVA 0x1000 (file offset 0x400). */
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

test("parseVa accepts 0x-prefixed, bare hex, and rejects junk", () => {
  assert.equal(parseVa("0x140001000"), 0x140001000);
  assert.equal(parseVa("140001000"), 0x140001000);
  assert.equal(parseVa("  0x10 "), 0x10);
  assert.equal(parseVa("0"), null);
  assert.equal(parseVa("-5"), null);
  assert.equal(parseVa("hello"), null);
  assert.equal(parseVa(""), null);
  assert.equal(formatVa(0x140001000), "0x140001000");
});

test("annotate.symbol op: upsert, list, remove, and name resolution in binary_search", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-symbols-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "sample.exe"), fakePe("c2-endpoint-here"));

  const ANNOTATE = operations.find((entry) => entry.id === "annotate.symbol");

  // Upsert: name the VA where the string lives (0x140001000).
  const upserted = await ANNOTATE.execute(
    { path: "sample.exe", entries: [{ va: "0x140001000", name: "g_c2_endpoint", comment: "the C2 host constant" }] },
    { workspace },
  );
  assert.equal(upserted.entryCount, 1);
  assert.equal(upserted.entries[0].name, "g_c2_endpoint");
  assert.equal(upserted.entries[0].comment, "the C2 host constant");

  // The persisted map round-trips.
  const stored = await readSymbolMap(workspace, upserted.sampleId);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].va, "0x140001000");

  // Update: same VA, new name — one entry, not two.
  const updated = await ANNOTATE.execute(
    { path: "sample.exe", entries: [{ va: "0x140001000", name: "kC2Host" }] },
    { workspace },
  );
  assert.equal(updated.entryCount, 1);
  assert.equal(updated.entries[0].name, "kC2Host");

  // binary_search resolves the hit through the symbol map.
  const search = await searchBinary(workspace, "sample.exe", { needle: "c2-endpoint" });
  assert.equal(search.hitCount, 1);
  assert.equal(search.hits[0].symbol, "kC2Host");
  assert.equal(search.hits[0].va, "0x140001000");

  // Remove: map empties, file deleted, search shows no symbol.
  const removed = await ANNOTATE.execute({ path: "sample.exe", vas: ["0x140001000"] }, { workspace });
  assert.equal(removed.entryCount, 0);
  const after = await searchBinary(workspace, "sample.exe", { needle: "c2-endpoint" });
  assert.equal(after.hits[0].symbol, undefined);
});

test("symbol index lookup helpers", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-symbols2-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), fakePe("x"));

  const binary = { sampleId: "abc123" };
  await upsertSymbols(workspace, binary.sampleId, [
    { va: "0x401000", name: "main" },
    { va: "0x402000", name: "decrypt_config", comment: "xor loop" },
  ]);
  const index = await loadSymbolIndex(workspace, binary.sampleId);
  assert.equal(lookupSymbol(index, 0x401000)?.name, "main");
  assert.equal(lookupSymbol(index, 0x999999), null);
  assert.equal(lookupSymbolString(index, "0x402000")?.comment, "xor loop");
  assert.equal(lookupSymbolString(index, null), null);
  assert.equal(lookupSymbolString(index, "garbage"), null);

  await removeSymbols(workspace, binary.sampleId, ["0x401000"]);
  const remaining = await readSymbolMap(workspace, binary.sampleId);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].name, "decrypt_config");
});

test("annotate.symbol validates input", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-symbols3-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "s.exe"), fakePe("x"));

  const ANNOTATE = operations.find((entry) => entry.id === "annotate.symbol");
  await assert.rejects(
    () => ANNOTATE.execute({ path: "s.exe", entries: [{ va: "not-a-va", name: "x" }] }, { workspace }),
    /invalid VA/,
  );
  await assert.rejects(
    () => ANNOTATE.execute({ path: "s.exe", entries: [{ va: "0x401000", name: "  " }] }, { workspace }),
    /empty symbol name/,
  );
});
