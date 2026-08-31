// Phase 2 (v2): dossier extractors — golden tests per operation family
// (fixture result → expected assembled form), the generic fallback,
// tolerance to broken shapes, and the writeDossierEntry assembled+raw
// split (assembled inline, raw in the CAS by pointer).

import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { listDossierIndex, dossierDir, writeDossierEntry } from "../dist/core/campaign.js";
import { readArtifactFull } from "../dist/core/artifacts.js";
import { extractDossierResult } from "../dist/core/dossier.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

test("extractor: binary_triage keeps the verdict, risk categories, IOCs, sections", () => {
  const assembled = extractDossierResult("binary_triage", {
    path: "sample.exe", sha256: "ab".repeat(32), size: 12345, entropy: 7.9,
    format: { kind: "PE", architecture: "x86-64", bits: 64 },
    verdict: { packed: true, packedWhy: ["high entropy"], dotnet: false, riskLevel: "high", notable: ["vmprotect sections"], analysisIncomplete: true, incompleteWhy: ["packed"], evidenceNotes: [] },
    sections: [{ name: ".text", virtualSize: 4096, rawSize: 4096, entropy: 6.1, executable: true }, { name: ".vmp0", virtualSize: 8192, rawSize: 0, entropy: 7.9, executable: true }],
    imports: { dllCount: 2, functionCount: 5, risk: { level: "high", categories: [{ category: "process-injection", level: "high", apis: [{ name: "VirtualAllocEx", dll: "kernel32" }] }] } },
    strings: { count: 100, iocs: { urls: ["http://c2.example/panel"], ips: ["1.2.3.4"], registry: [], pdbPaths: [], uncPaths: [] } },
    next: ["unpack it", "read strings"],
    fullReport: { artifactId: "sha256:ff", bytes: 1000, pageWith: "artifact_read" },
  });
  assert.equal(assembled.verdict.packed, true);
  assert.equal(assembled.verdict.riskLevel, "high");
  assert.equal(assembled.sections.length, 2);
  assert.equal(assembled.sections[1].name, ".vmp0");
  assert.equal(assembled.imports.risk.level, "high");
  assert.equal(assembled.imports.risk.categories[0].category, "process-injection");
  assert.equal(assembled.imports.risk.categories[0].apiCount, 1);
  assert.deepEqual(assembled.strings.iocs.urls, ["http://c2.example/panel"]);
  assert.equal(assembled.fullReport.artifactId, "sha256:ff");
});

test("extractor: strings_find bounds hits and keeps offsets/RVA/VA", () => {
  const hits = Array.from({ length: 200 }, (_, index) => ({ plane: "strings", offset: index * 16, section: ".rdata", rva: `0x${(index * 16).toString(16)}`, va: `0x1400${(index * 16).toString(16)}`, text: `string-${index}` }));
  const assembled = extractDossierResult("strings_find", { mode: "whole-file", needle: "secret", hits, truncated: true });
  assert.equal(assembled.mode, "whole-file");
  assert.equal(assembled.hitsCount, 200);
  assert.equal(assembled.hits.length, 50, "hits bounded at 50");
  assert.equal(assembled.hits[0].va, "0x14000");
  assert.equal(assembled.truncated, true);
});

test("extractor: decompile keeps per-function pseudocode and callers", () => {
  const assembled = extractDossierResult("ida_decompile", {
    backend: "idat",
    decompiled: [
      { target: "0x140001000", name: "validate_key", start: "0x140001000", pseudocodePreview: "__int64 validate_key() { return check(); }", truncated: false, callers: [{ fromAddress: "0x140002000" }] },
    ],
    fullReport: { artifactId: "sha256:aa", bytes: 500, pageWith: "artifact_read" },
  });
  assert.equal(assembled.functions.length, 1);
  assert.equal(assembled.functions[0].name, "validate_key");
  assert.equal(assembled.functions[0].va, "0x140001000");
  assert.match(assembled.functions[0].pseudocode, /check\(\)/);
  assert.equal(assembled.functions[0].callers.length, 1);
  // Ghidra shape (functions array with decompiledCode) extracts identically.
  const ghidra = extractDossierResult("function_decompile", {
    functions: [{ name: "main", entryPoint: "0x401000", decompiledCode: "int main() { return 0; }", callers: [] }],
  });
  assert.equal(ghidra.functions[0].name, "main");
  assert.equal(ghidra.functions[0].va, "0x401000");
  assert.match(ghidra.functions[0].pseudocode, /return 0/);
});

test("extractor: unpack/config/signature/emu families", () => {
  const unpack = extractDossierResult("unpack_static", { backend: "upx", packed: true, outputPath: "sample-unpacked.exe", outputSha256: "cd".repeat(32), outputBytes: 999, ratio: "62.5%", notes: ["upx -d"] });
  assert.equal(unpack.packed, true);
  assert.equal(unpack.outputPath, "sample-unpacked.exe");
  assert.equal(unpack.outputBytes, 999);

  const config = extractDossierResult("config_extract", {
    extractionDepth: "floss-decoded", family: "AsyncRAT",
    fields: [{ key: "c2", value: "evil.example:443", confidence: "high", evidence: "decoded string @ 0x1400d1234 (FLOSS)" }],
  });
  assert.equal(config.extractionDepth, "floss-decoded");
  assert.equal(config.fields[0].key, "c2");
  assert.match(config.fields[0].evidence, /FLOSS/);

  const signature = extractDossierResult("signature_verify", { signaturePresent: true, valid: true, status: "Valid", signer: "CN=Example Corp", signerCommonName: "Example Corp", verdict: "VALID" });
  assert.equal(signature.valid, true);
  assert.equal(signature.signerCommonName, "Example Corp");

  const emu = extractDossierResult("emu_diff", { status: "ok", match: false, comparedBytes: 16, divergenceCount: 1, firstDivergence: { offset: 3, referenceHex: "0f", candidateHex: "0e" }, divergenceOffsets: [3] });
  assert.equal(emu.match, false);
  assert.equal(emu.firstDivergence.offset, 3);
});

test("extractor: generic form for unlisted operations; tolerance to garbage", () => {
  const generic = extractDossierResult("some_other_op", { a: 1, b: { nested: true }, big: "x".repeat(10000) });
  assert.deepEqual(generic.keys, ["a", "b", "big"]);
  assert.ok(generic.preview.length <= 4000, "preview bounded");

  assert.doesNotThrow(() => extractDossierResult("binary_triage", null));
  assert.doesNotThrow(() => extractDossierResult("strings_find", "a string, not an object"));
  assert.doesNotThrow(() => extractDossierResult("ida_decompile", 42));
  const nullTriage = extractDossierResult("binary_triage", null);
  assert.ok(nullTriage.preview !== undefined, "garbage degrades to the generic form");
});

test("writeDossierEntry stores ASSEMBLED inline and RAW in the CAS", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dossier-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const name = await writeDossierEntry(workspace, {
    task: "verify",
    operation: "signature_verify",
    status: "ok",
    completedAt: new Date().toISOString(),
    attempts: [{ operation: "signature_verify", status: "ok", durationMs: 12 }],
    result: { signaturePresent: true, valid: false, status: "HashMismatch", signer: "CN=Someone", verdict: "SIGNATURE BROKEN", extraField: "kept-in-raw-only" },
  });
  const stored = JSON.parse(await readFile(path.join(dossierDir(workspace), name), "utf8"));
  assert.equal(stored.task, "verify");
  assert.equal(stored.assembled.valid, false, "assembled form inline");
  assert.equal(stored.assembled.extraField, undefined, "assembled form is the extracted subset, not the whole blob");
  assert.ok(stored.rawArtifact, "raw result stored in the CAS");
  const raw = JSON.parse(await readArtifactFull(workspace, stored.rawArtifact));
  assert.equal(raw.extraField, "kept-in-raw-only", "raw preserves everything");
  const index = await listDossierIndex(workspace);
  assert.equal(index[0].task, "verify");
  assert.equal(index[0].status, "ok");

  // Failure entries: no assembled, no raw artifact, error stays in attempts.
  const failedName = await writeDossierEntry(workspace, {
    task: "broken",
    operation: "unpack_static",
    status: "error",
    completedAt: new Date().toISOString(),
    attempts: [{ operation: "unpack_static", status: "error", error: "upx exploded", durationMs: 5 }],
    result: null,
  });
  const failedStored = JSON.parse(await readFile(path.join(dossierDir(workspace), failedName), "utf8"));
  assert.equal(failedStored.assembled, null);
  assert.equal(failedStored.rawArtifact, null);
  assert.equal(failedStored.attempts[0].error, "upx exploded");
});
