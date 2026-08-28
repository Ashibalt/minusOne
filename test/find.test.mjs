import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cacheKeyDigest, storeArtifact } from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { fileOffsetToRva, parsePeTablesFromBuffer, rvaToFileOffset } from "../dist/core/peimports.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const FIND = operations.find((entry) => entry.id === "binary.find");
assert.ok(FIND, "binary.find operation exists");
assert.equal(FIND.toolName, "binary_find");

async function fakeWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-find-"));
  await writeFile(path.join(root, "sample.bin"), "dummy-sample-content with NEEDLE inside");
  return { root, workspace: await Workspace.create(root) };
}

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

/** Minimal PE with one section and an embedded ASCII string in it. */
function fakePeWithString(text) {
  const rawSize = 0x200;
  const buf = Buffer.alloc(0x400, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c);
  buf.write("PE", 0x40, "latin1");
  buf.writeUInt16LE(0x14c, 0x44);
  buf.writeUInt16LE(1, 0x46);
  buf.writeUInt16LE(0xe0, 0x54); // sizeOfOptionalHeader (PE32)
  buf.writeUInt16LE(0x10b, 0x58); // PE32 magic
  buf.writeUInt32LE(0x14000000, 0x58 + 28); // imageBase
  buf.write(".text", 0x40 + 24 + 0xe0, "latin1");
  const sectionTable = 0x40 + 24 + 0xe0;
  buf.writeUInt32LE(0x180, sectionTable + 8); // virtualSize
  buf.writeUInt32LE(0x1000, sectionTable + 12); // rva
  buf.writeUInt32LE(rawSize, sectionTable + 16); // rawSize
  buf.writeUInt32LE(0x200, sectionTable + 20); // pointerToRawData
  buf.write(text, 0x200, "latin1");
  return buf;
}

test("binary.find finds a string on a non-PE file across bytes and strings planes", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  const result = await FIND.execute({ path: "sample.bin", needle: "NEEDLE" }, { workspace: fixture.workspace });
  assert.equal(result.hitCount >= 1, true);
  assert.equal(result.kind, "string");
  assert.ok(result.planes.consulted.includes("strings"));
  assert.ok(result.planes.consulted.includes("bytes"));
  // The PE-only planes degrade to skips, not failures.
  assert.ok(result.planes.skipped.some((skip) => skip.plane === "imports" && /requires a PE file/.test(skip.reason)));

  const caseHit = await FIND.execute({ path: "sample.bin", needle: "needle" }, { workspace: fixture.workspace });
  assert.ok(caseHit.hitCount >= 1, "default matching is case-insensitive, so lowercase finds NEEDLE");
  const sensitive = await FIND.execute({ path: "sample.bin", needle: "needle", caseSensitive: true }, { workspace: fixture.workspace });
  assert.equal(sensitive.hitCount, 0, "caseSensitive restricts to exact-case matches");
});

test("binary.find rejects malformed needles with a clear error", async (context) => {
  const fixture = await fakeWorkspace();
  context.after(() => rmRoot(fixture.root));

  await assert.rejects(
    () => FIND.execute({ path: "sample.bin", needle: "xyz", kind: "bytes" }, { workspace: fixture.workspace }),
    /even-length hex/,
  );
  await assert.rejects(
    () => FIND.execute({ path: "sample.bin", needle: "(" , kind: "regex" }, { workspace: fixture.workspace }),
    /invalid regular expression/,
  );
});

test("rva mapping round-trips through a parsed section table", async () => {
  const buf = fakePeWithString("minusone");
  const tables = await parsePeTablesFromBuffer(buf);
  assert.ok(tables, "fixture parses as PE");
  assert.equal(tables.bits, 32);
  assert.equal(tables.machine, "x86");
  assert.equal(tables.sections.length, 1);
  assert.equal(tables.sections[0].name, ".text");

  const offset = rvaToFileOffset(tables.sections, 0x1000);
  assert.equal(offset, 0x200);
  assert.equal(fileOffsetToRva(tables.sections, 0x200), 0x1000);
  assert.equal(rvaToFileOffset(tables.sections, 0x2000), null, "outside every section");
});

test("binary.find enriches PE hits with section, RVA and VA", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-findpe-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "mini.exe"), fakePeWithString("minusone-marker"));

  const result = await FIND.execute({ path: "mini.exe", needle: "minusone-marker" }, { workspace });
  const hit = result.hits.find((entry) => entry.plane !== "imports");
  assert.ok(hit, "string hit exists");
  assert.equal(hit.section, ".text");
  assert.equal(hit.rva, 0x1000);
  assert.equal(hit.va, "0x14001000");
});

test("binary.find lights up the symbols plane from the cached radare2 listing", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-findsym-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "mini.exe"), fakePeWithString("minusone-marker"));

  const before = await FIND.execute({ path: "mini.exe", needle: "decode", kind: "symbol" }, { workspace });
  assert.equal(before.hitCount, 0);
  assert.ok(before.planes.skipped.some((skip) => skip.plane === "symbols" && /disassembly_functions/.test(skip.reason)));

  const previousImage = process.env.MINUSONE_R2_IMAGE;
  const previousBin = process.env.MINUSONE_R2_BIN;
  process.env.MINUSONE_R2_IMAGE = "registry.invalid/minusone/r2:test";
  delete process.env.MINUSONE_R2_BIN;
  try {
    const sha256 = createHash("sha256").update(fakePeWithString("minusone-marker")).digest("hex");
    const cacheKey = cacheKeyDigest({
      sample: sha256,
      operation: "disassembly.functions",
      image: process.env.MINUSONE_R2_IMAGE,
      local: null,
      schema: 1,
    });
    await storeArtifact(workspace, JSON.stringify([
      // sym.decode spans 0x14000fc0..0x14001088 — covers the string's VA 0x14001000.
      { offset: 0x14000fc0, name: "sym.decode", realsz: 0xc8, nbbs: 2, signature: "void sym.decode(char *dst, int len);" },
      { offset: 0x14001088, name: "main", realsz: 140, nbbs: 5 },
    ]), {
      mediaType: "application/json",
      sourceOperation: "disassembly.functions",
      description: "pre-seeded function cache",
      cacheKey,
    });

    const after = await FIND.execute({ path: "mini.exe", needle: "decode", kind: "symbol" }, { workspace });
    assert.equal(after.hitCount, 1);
    assert.equal(after.hits[0].plane, "symbols");
    assert.equal(after.hits[0].value, "sym.decode");
    assert.equal(after.planes.consulted.includes("symbols"), true);

    // Enrichment: a string hit inside sym.decode's range carries the function name.
    const enriched = await FIND.execute({ path: "mini.exe", needle: "minusone-marker" }, { workspace });
    const hit = enriched.hits.find((entry) => entry.plane === "strings" || entry.plane === "bytes");
    assert.ok(hit, "string/buffer hit exists");
    assert.equal(hit.function, "sym.decode");
  } finally {
    delete process.env.MINUSONE_R2_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_R2_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_R2_BIN = previousBin;
  }
});

test("binary.find live: a real PE yields cross-plane hits for a known string and API", { timeout: 120_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the live fixture");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-findlive-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const source = path.join(root, "findtarget.c");
  await writeFile(source, [
    "#include <stdio.h>",
    "#include <string.h>",
    "int main(int argc, char **argv) {",
    "  const char *marker = \"MINUSONE_FIND_MARKER_42\";",
    "  if (argc == 2 && strcmp(argv[1], marker) == 0) { puts(marker); return 0; }",
    "  puts(\"no match\"); return 1;",
    "}",
    "",
  ].join("\n"));

  const exe = path.join(root, "findtarget.exe");
  const cc = spawnSync("gcc", ["-O0", "-o", exe, source], { encoding: "utf8" });
  assert.equal(cc.status, 0, `gcc failed: ${cc.stderr}`);

  const byString = await FIND.execute({ path: "findtarget.exe", needle: "MINUSONE_FIND_MARKER_42" }, { workspace });
  assert.ok(byString.hitCount >= 1, `expected strings-plane hits, got ${JSON.stringify(byString.planeCounts)}`);
  assert.ok(byString.planeCounts.strings >= 1, "strings plane matched");
  // The bytes plane deduplicates against strings-plane offsets by design: an
  // ASCII string already reported once is not re-reported as a raw byte hit.
  const withSection = byString.hits.find((hit) => hit.section !== null && hit.section !== undefined);
  assert.ok(withSection, "at least one hit carries a section name");
  assert.ok(withSection.rva !== null && withSection.rva !== undefined, "hit carries an RVA");
  assert.match(withSection.va, /^0x[0-9a-f]+$/, "hit carries a VA");
  assert.ok(byString.next.length >= 1, "next-step guidance is present");

  const byApi = await FIND.execute({ path: "findtarget.exe", needle: "strcmp", kind: "api" }, { workspace });
  assert.ok(byApi.planeCounts.imports >= 1, "imports plane matched strcmp");
  const importHit = byApi.hits.find((hit) => hit.plane === "imports");
  assert.ok(importHit);
  assert.match(importHit.value, /strcmp/);
  assert.match(importHit.iatVa, /^0x[0-9a-f]+$/, "import hit carries its IAT slot VA");

  const byBytes = await FIND.execute({ path: "findtarget.exe", needle: "4d5a", kind: "bytes" }, { workspace });
  assert.equal(byBytes.kind, "bytes");
  assert.ok(byBytes.hitCount >= 1, "MZ header found at offset 0 by hex needle");
  assert.equal(byBytes.hits[0].offset, 0);

  const byRegex = await FIND.execute({ path: "findtarget.exe", needle: "MINUSONE_[A-Z_]+", kind: "regex" }, { workspace });
  assert.ok(byRegex.hitCount >= 1, "regex matches the marker");
});
