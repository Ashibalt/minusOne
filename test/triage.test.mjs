import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { classifyImportRisk, mineIocs, packedVerdict, sectionEntropy } from "../dist/core/triage.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const TRIAGE = operations.find((entry) => entry.id === "binary.triage");
assert.ok(TRIAGE, "binary.triage operation exists");
assert.equal(TRIAGE.toolName, "binary_triage");

test("classifyImportRisk maps imports to classic triage categories", () => {
  const high = classifyImportRisk([
    { dll: "kernel32.dll", name: "VirtualAllocEx" },
    { dll: "kernel32.dll", name: "WriteProcessMemory" },
    { dll: "kernel32.dll", name: "CreateRemoteThread" },
    { dll: "ws2_32.dll", name: "connect" },
    { dll: "user32.dll", name: "GetAsyncKeyState" },
  ]);
  assert.equal(high.level, "high");
  const categories = high.categories.map((category) => category.category);
  assert.ok(categories.includes("process-injection"));
  assert.ok(categories.includes("credential-theft"));
  assert.ok(categories.includes("network"));
  const injection = high.categories.find((category) => category.category === "process-injection");
  assert.equal(injection.apis.length, 3);

  const medium = classifyImportRisk([{ dll: "ws2_32.dll", name: "send" }]);
  assert.equal(medium.level, "medium");

  const clean = classifyImportRisk([{ dll: "msvcrt.dll", name: "printf" }]);
  assert.equal(clean.level, "low");
  assert.equal(clean.categories.length, 0);
});

test("mineIocs extracts bounded IOC classes from strings", () => {
  const iocs = mineIocs([
    "hxxp placeholder https://malware.example/payload.exe",
    "connect to 185.220.101.4:443",
    "registry key HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "D:\\build\\malware\\release\\implant.pdb",
    "backup at \\\\fileshare\\dropzone\\stage",
    "127.0.0.1 local only",
    "0.0.0.0 nothing",
  ]);
  assert.deepEqual(iocs.urls, ["https://malware.example/payload.exe"]);
  assert.deepEqual(iocs.ips, ["185.220.101.4"]);
  assert.deepEqual(iocs.registry, ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]);
  assert.deepEqual(iocs.pdbPaths, ["D:\\build\\malware\\release\\implant.pdb"]);
  assert.deepEqual(iocs.uncPaths, ["\\\\fileshare\\dropzone\\stage"]);
});

/** Minimal PE with one .text section; imports are faked by callers when needed. */
function fakePe() {
  const buf = Buffer.alloc(0x400, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c);
  buf.write("PE", 0x40, "latin1");
  buf.writeUInt16LE(0x14c, 0x44);
  buf.writeUInt16LE(1, 0x46);
  buf.writeUInt16LE(0xe0, 0x54);
  buf.writeUInt16LE(0x10b, 0x58);
  buf.writeUInt32LE(0x400000, 0x58 + 28);
  const st = 0x40 + 24 + 0xe0;
  buf.write(".text", st, "latin1");
  buf.writeUInt32LE(0x180, st + 8);
  buf.writeUInt32LE(0x1000, st + 12);
  buf.writeUInt32LE(0x200, st + 16);
  buf.writeUInt32LE(0x200, st + 20);
  buf.writeUInt32LE(0x60000020, st + 36); // code|execute|read
  buf.write("https://fake.example/c2", 0x200, "latin1");
  return buf;
}

async function disableBackends() {
  const saved = {
    die: process.env.MINUSONE_DIE_IMAGE,
    binwalk: process.env.MINUSONE_BINWALK_IMAGE,
    capa: process.env.MINUSONE_CAPA_IMAGE,
    dieBin: process.env.MINUSONE_DIE_BIN,
    binwalkBin: process.env.MINUSONE_BINWALK_BIN,
    capaBin: process.env.MINUSONE_CAPA_BIN,
  };
  process.env.MINUSONE_DIE_IMAGE = "";
  process.env.MINUSONE_BINWALK_IMAGE = "";
  process.env.MINUSONE_CAPA_IMAGE = "";
  delete process.env.MINUSONE_DIE_BIN;
  delete process.env.MINUSONE_BINWALK_BIN;
  delete process.env.MINUSONE_CAPA_BIN;
  return () => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}

test("binary.triage fuses native planes and degrades gracefully without backends", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-triage-"));
  context.after(() => rmRoot(root));
  const restore = await disableBackends();
  context.after(restore);
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "mini.exe"), fakePe());

  const result = await TRIAGE.execute({ path: "mini.exe" }, { workspace });
  assert.equal(result.format.kind, "pe");
  assert.equal(result.format.architecture, "x86");
  assert.equal(result.sections.length, 1);
  assert.equal(result.sections[0].name, ".text");
  assert.equal(result.sections[0].executable, true);
  assert.equal(result.sections[0].writable, false);
  assert.deepEqual(result.imports, { dllCount: 0, functionCount: 0, dlls: [], risk: { level: "low", categories: [] } }, "a stub PE without an import directory reports empty imports, not null");
  assert.equal(result.verdict.dotnet, false);
  assert.equal(result.verdict.packed, false, "plain low-entropy fixture is not packed");
  assert.deepEqual(result.strings.iocs.urls, ["https://fake.example/c2"]);
  assert.ok(result.next.length >= 1, "contextual next steps present");
  assert.match(result.fullReport.artifactId, /^sha256:[0-9a-f]{64}$/);

  // Graceful degradation: backends disabled, but the report is still complete.
  const degradedPlanes = result.planes.degraded.map((entry) => entry.plane);
  assert.ok(degradedPlanes.includes("packer"), `packer plane degrades, got ${JSON.stringify(result.planes)}`);
  assert.ok(degradedPlanes.includes("embedded"));
  assert.ok(degradedPlanes.includes("capabilities"));
  assert.ok(result.planes.consulted.includes("binary"));
  assert.ok(result.planes.consulted.includes("strings"));

  // Output-schema contract (hosts like dsh VALIDATE outputs): the degraded
  // planes are empty objects with available:false — never null, which the
  // binary_triage outputSchema forbids and which broke the dsh plugin.
  assert.equal(typeof result.packer, "object");
  assert.equal(result.packer.available, false);
  assert.deepEqual(result.packer.filetypes, []);
  assert.equal(typeof result.embedded, "object");
  assert.equal(result.embedded.available, false);
  assert.equal(result.embedded.signatureCount, 0);
  assert.equal(typeof result.capabilities, "object");
  assert.equal(result.capabilities.available, false);
  assert.equal(result.capabilities.ruleCount, 0);
});

test("binary.triage flags a UPX-style layout as packed", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-triageupx-"));
  context.after(() => rmRoot(root));
  const restore = await disableBackends();
  context.after(restore);
  const workspace = await Workspace.create(root);

  const buf = Buffer.alloc(0x400, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c);
  buf.write("PE", 0x40, "latin1");
  buf.writeUInt16LE(0x14c, 0x44);
  buf.writeUInt16LE(2, 0x46);
  buf.writeUInt16LE(0xe0, 0x54);
  buf.writeUInt16LE(0x10b, 0x58);
  const st = 0x40 + 24 + 0xe0;
  buf.write("UPX0", st, "latin1");
  buf.writeUInt32LE(0x8000, st + 8); // virtualSize
  buf.writeUInt32LE(0x1000, st + 12); // rva
  buf.writeUInt32LE(0, st + 16); // rawSize 0 — uninitialized
  buf.writeUInt32LE(0x200, st + 20);
  buf.writeUInt32LE(0xe0000060, st + 36); // uninit|execute|read|write
  buf.write("UPX1", st + 40, "latin1");
  buf.writeUInt32LE(0x4000, st + 40 + 8);
  buf.writeUInt32LE(0x9000, st + 40 + 12);
  buf.writeUInt32LE(0x200, st + 40 + 16);
  buf.writeUInt32LE(0x200, st + 40 + 20);
  buf.writeUInt32LE(0xe0000060, st + 40 + 36);
  await writeFile(path.join(root, "packed.exe"), buf);

  const result = await TRIAGE.execute({ path: "packed.exe" }, { workspace });
  assert.equal(result.verdict.packed, true);
  assert.ok(result.verdict.packedWhy.some((why) => /packer layout \(UPX0\)/.test(why)), JSON.stringify(result.verdict.packedWhy));
  assert.ok(result.verdict.packedWhy.some((why) => /raw size 0/.test(why)));
  assert.ok(result.next.some((hint) => /dynamic_unpack/.test(hint)), "packed verdict drives the unpack next-step");
});

test("binary.triage live: real PE with imports, risk categories and IOCs", { timeout: 300_000 }, async (context) => {
  const gccProbe = spawnSync("gcc", ["--version"], { encoding: "utf8" });
  if (gccProbe.status !== 0) context.skip("needs gcc to build the live fixture");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-triagelive-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const source = path.join(root, "triagetarget.c");
  await writeFile(source, [
    "#include <stdio.h>",
    "#include <windows.h>",
    "#include <wininet.h>",
    "int main(void) {",
    "  HINTERNET h = InternetOpenA(\"agent\", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);",
    "  InternetCloseHandle(h);",
    "  puts(\"beacon https://triage.example/report\");",
    "  return 0;",
    "}",
    "",
  ].join("\n"));
  const exe = path.join(root, "triagetarget.exe");
  const cc = spawnSync("gcc", ["-O0", "-o", exe, source, "-lwininet"], { encoding: "utf8" });
  assert.equal(cc.status, 0, `gcc failed: ${cc.stderr}`);

  const result = await TRIAGE.execute({ path: "triagetarget.exe" }, { workspace });
  assert.equal(result.format.kind, "pe");
  assert.ok(result.imports.functionCount >= 3, "real PE has imports");
  assert.ok(result.imports.dlls.some((dll) => /wininet/i.test(dll)), `wininet imported, got ${JSON.stringify(result.imports.dlls)}`);
  assert.equal(result.imports.risk.level, "medium", "InternetOpenA is a network-category API");
  assert.ok(result.imports.risk.categories.some((category) => category.category === "network"));
  assert.ok(result.strings.iocs.urls.includes("https://triage.example/report"), JSON.stringify(result.strings.iocs));
  assert.ok(result.sections.length >= 3, "real PE has multiple sections");
  assert.ok(result.verdict.packed === false, "plain gcc build is not packed");
  assert.ok(result.next.some((hint) => /capabilities_detect/.test(hint)));
});

test("packedVerdict: standard-layout sections suppress DIE entropy misfires (Unity.dll lesson)", () => {
  const tables = {
    sections: [
      { name: ".text", virtualSize: 0x100000, rawSize: 0x100000, characteristics: 0x60000020 },
      { name: ".rdata", virtualSize: 0x1000, rawSize: 0x1000, characteristics: 0x40000040 },
    ],
  };
  const sectionEntropies = [
    { name: ".text", virtualSize: 0x100000, rawSize: 0x100000, entropy: 6.5, executable: true, writable: false },
  ];
  const verdict = packedVerdict({ entropy: 6.4 }, tables, true, sectionEntropies, null);
  assert.equal(verdict.packed, false, "suppressed weak evidence must not flag an optimized build as packed");
  assert.ok(verdict.why.some((why) => /SUPPRESSED/.test(why)), "the suppression must stay visible in packedWhy");
});

test("packedVerdict: strong packer-layout evidence always wins", () => {
  const tables = {
    sections: [{ name: "UPX0", virtualSize: 0x10000, rawSize: 0, characteristics: 0xe0000020 }],
  };
  const verdict = packedVerdict({ entropy: 4.0 }, tables, false, [], null);
  assert.equal(verdict.packed, true);
  assert.ok(verdict.why.some((why) => /packer layout \(UPX0\)/.test(why)));
  assert.ok(verdict.why.some((why) => /raw size 0/.test(why)));
});

test("packedVerdict: hard-threshold entropy on a standard layout is NOT suppressed", () => {
  const tables = {
    sections: [{ name: ".text", virtualSize: 0x10000, rawSize: 0x10000, characteristics: 0x60000020 }],
  };
  const sectionEntropies = [
    { name: ".text", virtualSize: 0x10000, rawSize: 0x10000, entropy: 7.9, executable: true, writable: false },
  ];
  const verdict = packedVerdict({ entropy: 7.8 }, tables, true, sectionEntropies, null);
  assert.equal(verdict.packed, true, "7.5+ entropy in an executable section is not compiler output");
  assert.ok(!verdict.why.some((why) => /SUPPRESSED/.test(why)), "hard-threshold evidence is never suppressed");
});

test("packedVerdict: a valid Authenticode signature downgrades entropy-only hints", () => {
  const verdict = packedVerdict({ entropy: 7.9 }, null, null, [], true);
  assert.equal(verdict.packed, false);
  assert.ok(verdict.why.some((why) => /VALID Authenticode/.test(why)));
});

test("sectionEntropy matches DIE's wrapped record names", () => {
  // diec names section records like `Section (1) [".text"]`; exact-only
  // matching never hit, so triage section entropy was always null.
  const records = [
    { name: "Header", entropy: 2.61 },
    { name: 'Section (1) [".text"]', entropy: 6.14 },
    { name: ".rdata", entropy: 4.2 },
  ];
  assert.equal(sectionEntropy(records, ".text"), 6.14);
  assert.equal(sectionEntropy(records, ".rdata"), 4.2);
  assert.equal(sectionEntropy(records, ".data"), null);
  assert.equal(sectionEntropy(undefined, ".text"), null);
});
