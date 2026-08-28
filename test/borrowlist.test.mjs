import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { extractConfig, decodeBase64Candidate } from "../dist/core/configextract.js";
import { runEmulation, runEmulationChain, runEmulationDiff } from "../dist/core/emu.js";
import { diffBinaries } from "../dist/core/bindiff.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function fakePe(payload) {
  const buf = Buffer.alloc(0x800, 0);
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
  buf.writeUInt32LE(0x400, st + 8);
  buf.writeUInt32LE(0x1000, st + 12);
  buf.writeUInt32LE(0x400, st + 16);
  buf.writeUInt32LE(0x400, st + 20);
  buf.write(payload, 0x400, "latin1");
  return buf;
}

// ---- config.extract -----------------------------------------------------------

test("config.extract: C2/mutex/registry/campaign harvest with evidence labels", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-config-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const payload = [
    "C2: 185.220.101.4:443",
    "backup c2 evil.example.com:8080",
    "Global\\MTX_evil_loader_mutex",
    "HKCU\\Software\\Evil\\Run",
    "CampaignID=SPRING2024",
    "https://panel.evil.example/update?id=7",
    "C:\\Users\\dev\\projects\\evil\\Release\\evil.pdb",
    "key: s3cr3tK3y",
  ].join("\n");
  await writeFile(path.join(root, "rat.exe"), fakePe(payload));

  // FLOSS unavailable in this env → static fallback (recorded honestly).
  const result = await extractConfig(workspace, "rat.exe", { useFloss: false });
  assert.equal(result.extractionDepth, "static-strings");
  const keys = result.fields.map((field) => field.key);
  assert.ok(keys.includes("c2"), `keys: ${keys.join(",")}`);
  assert.ok(result.fields.filter((field) => field.key === "c2").length >= 2, "both C2 endpoints harvested");
  assert.ok(keys.includes("mutex"));
  assert.ok(keys.includes("persistence.registry"));
  assert.ok(keys.includes("url"));
  assert.ok(keys.includes("pdbPath"));
  // Evidence discipline: every field carries its source.
  for (const field of result.fields) {
    assert.ok(field.evidence.length > 0, `field ${field.key} lacks evidence`);
    assert.ok(["high", "medium", "low"].includes(field.confidence));
  }
  // The static-only limitation is stated, not hidden.
  assert.ok(result.notes.some((note) => note.includes("PLAIN strings")));
});

test("config.extract: base64 blobs decode only when printable", () => {
  // 'SGVsbG8gZnJvbSBtaW51c09uZQ==' = "Hello from minusOne"
  assert.equal(decodeBase64Candidate("SGVsbG8gZnJvbSBtaW51c09uZQ=="), "Hello from minusOne");
  // Random bytes that happen to be base64-alphabet decode to junk — rejected.
  assert.equal(decodeBase64Candidate("AAAAAAAAAAAAAAAAáriibb"), null);
  assert.equal(decodeBase64Candidate(""), null);
});

// ---- emu.run ------------------------------------------------------------------

test("emu.run LIVE: XOR decryptor emulation — encrypted blob in, plaintext out", { timeout: 120_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }

  // mov ecx,4; mov esi,0x200000; mov edi,0x201000; lodsb; xor al,0x42; stosb; loop; ret
  const code = Buffer.from([
    0xB9, 0x04, 0x00, 0x00, 0x00,
    0xBE, 0x00, 0x00, 0x20, 0x00,
    0xBF, 0x00, 0x10, 0x20, 0x00,
    0xAC, 0x34, 0x42, 0xAA,
    0xE2, 0xFA,
    0xC3,
  ]);
  const encrypted = Buffer.from("MINU").map((byte) => byte ^ 0x42);
  const workspace = await Workspace.create(await mkdtemp(path.join(os.tmpdir(), "minusone-emu-")));
  context.after(() => rmRoot(workspace.root));
  const result = await runEmulation({
    arch: "x86",
    codeHex: code.toString("hex"),
    until: "0x1000ff",
    data: [
      { address: "0x200000", bytesHex: encrypted.toString("hex"), size: 4096 },
      { address: "0x201000", size: 4096 },
    ],
  }, workspace);
  assert.equal(result.status, "ok", result.error ?? "emulation failed");
  assert.equal(result.registers.ecx, "0x0", "loop ran to completion");
  const output = result.memory.find((region) => region.address === "0x201000");
  assert.ok(output, "output mapping exported");
  assert.equal(Buffer.from(output.bytesHex, "hex").toString("latin1"), "MINU", "decrypted payload");
  assert.ok(result.traceHead.length >= 9, "per-instruction trace captured");
  // The full trace is paged into an artifact, never inline output.
  assert.ok(result.traceArtifact, "trace artifact stored");
  assert.equal(result.traceArtifact.steps, result.traceHead.length);
  assert.deepEqual(result.notes, [], "aligned inputs produce no alignment notes");
});

test("emu.run: misaligned base and data sizes are auto-aligned to 4KB with notes", { timeout: 120_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  const workspace = await Workspace.create(await mkdtemp(path.join(os.tmpdir(), "minusone-emu2-")));
  context.after(() => rmRoot(workspace.root));
  // ret only; base misaligned by 0x800, data size 0x1ff (not page-multiple).
  const result = await runEmulation({
    arch: "x86",
    codeHex: "c3",
    base: "0x100800",
    data: [{ address: "0x200000", bytesHex: "90", size: 0x1ff }],
  }, workspace);
  assert.equal(result.status, "ok", result.error ?? "emulation failed");
  assert.ok(result.notes.some((note) => /base 0x100800 auto-aligned to 0x100000/.test(note)), `base note missing: ${JSON.stringify(result.notes)}`);
  assert.ok(result.notes.some((note) => /size 511 auto-grown to 4096/.test(note)), `size note missing: ${JSON.stringify(result.notes)}`);
});

test("emu.run LIVE: misaligned DATA ADDRESS reaches the runner as-is and must not crash it (R3-1 regression)", { timeout: 120_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  const workspace = await Workspace.create(await mkdtemp(path.join(os.tmpdir(), "minusone-emu3-")));
  context.after(() => rmRoot(workspace.root));
  // The wrapper aligns base and data SIZES, but a data ADDRESS passes through
  // untouched — it used to hit the runner's mem_map as UC_ERR_ARG, then the
  // `except Exception as error` on read-back deleted the run-status binding
  // and the runner died with UnboundLocalError instead of answering JSON.
  // mov esi,0x200080; mov edi,0x202080; mov ecx,2; rep movsw; ret (32-bit)
  // — copy 4 bytes between two MISALIGNED data windows (kept 0x2000 apart so
  // their page-rounded mappings never overlap after alignment).
  const code = Buffer.from([
    0xBE, 0x80, 0x00, 0x20, 0x00,
    0xBF, 0x80, 0x20, 0x20, 0x00,
    0xB9, 0x02, 0x00, 0x00, 0x00,
    0xF3, 0xA5,
    0xC3,
  ]);
  const result = await runEmulation({
    arch: "x86",
    codeHex: code.toString("hex"),
    until: "0x1000ff",
    data: [
      { address: "0x200080", bytesHex: "deadbeef", size: 0x800 },
      { address: "0x202080", size: 0x800 },
    ],
  }, workspace);
  assert.equal(result.status, "ok", `runner crashed instead of answering: ${result.error}`);
  const output = result.memory.find((region) => region.address === "0x202080");
  assert.ok(output, `output window exported at the ORIGINAL address: ${JSON.stringify(result.memory.map((r) => r.address))}`);
  assert.ok(!output.error, `read-back at the misaligned address must work: ${output.error}`);
  assert.equal(output.bytesHex, "deadbeef", "payload copied to the misaligned output window");
});

test("emu.run LIVE: x64 r8–r15 registers settable and readable (R3-2 regression)", { timeout: 120_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  const workspace = await Workspace.create(await mkdtemp(path.join(os.tmpdir(), "minusone-emu4-")));
  context.after(() => rmRoot(workspace.root));
  // r12-loop, the register compiled x64 code lives in: dec r12d; jnz back-5;
  // mov rax, r12; ret. r12 and r14 arrive via the registers input — before
  // R3-2 the runner silently ignored every r8–r15 name.
  const code = Buffer.from([
    0x49, 0xFF, 0xCC,             // dec r12d
    0x75, 0xFB,                   // jnz -5 (back to the dec)
    0x4C, 0x89, 0xE0,             // mov rax, r12
    0xC3,                         // ret
  ]);
  const result = await runEmulation({
    arch: "x64",
    codeHex: code.toString("hex"),
    until: "0x1000ff",
    registers: { r12: "0x5", r14: "0xdeadbeefcafe0000" },
  }, workspace);
  assert.equal(result.status, "ok", result.error ?? "emulation failed");
  assert.equal(result.registers.r12, "0x0", "r12 looped down to 0 — the initial r12 value was HONORED");
  assert.equal(result.registers.rax, "0x0", "mov rax, r12 saw the decremented value");
  assert.equal(result.registers.r14, "0xdeadbeefcafe0000", "r14 transited untouched");
  assert.ok(result.registers.r15 !== undefined, "final register snapshot includes r15");
});

test("emu.chain LIVE: stateful steps — transform carries memory across steps, failure stops the chain", { timeout: 180_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  const workspace = await Workspace.create(await mkdtemp(path.join(os.tmpdir(), "minusone-emuchain-")));
  context.after(() => rmRoot(workspace.root));
  // Three steps over one shared window at 0x200000 (init → xor → inc):
  //   0: mov dword [0x200000], 0x4d494e55 ("MINU")   — writer seeds the state
  //   1: esi=0x200000, ecx=4: xor byte [esi], 0x42    — transform A
  //   2: esi=0x200000, ecx=4: inc byte [esi]          — transform B
  // State MUST carry: step 2 must see step 1's output, not the seed.
  const stepWrite = Buffer.from([
    0xC7, 0x05, 0x00, 0x00, 0x20, 0x00, 0x55, 0x4E, 0x49, 0x4D, // mov dword [0x200000], 0x4d494e55
    0xC3,
  ]);
  const stepXor = Buffer.from([
    0xBE, 0x00, 0x00, 0x20, 0x00,
    0xB9, 0x04, 0x00, 0x00, 0x00,
    0x8A, 0x06, 0x34, 0x42, 0x88, 0x06,
    0x46,
    0xE2, 0xF7,
    0xC3,
  ]);
  const stepInc = Buffer.from([
    0xBE, 0x00, 0x00, 0x20, 0x00,
    0xB9, 0x04, 0x00, 0x00, 0x00,
    0x8A, 0x06, 0xFE, 0xC0, 0x88, 0x06,
    0x46,
    0xE2, 0xF7,
    0xC3,
  ]);
  const result = await runEmulationChain({
    arch: "x86",
    base: "0x100000",
    until: "0x1000ff",
    data: [{ address: "0x200000", size: 4096 }],
    steps: [
      { codeHex: stepWrite.toString("hex") },
      { codeHex: stepXor.toString("hex"), registers: { esi: "0x200000", ecx: "0x4" } },
      { codeHex: stepInc.toString("hex"), registers: { esi: "0x200000", ecx: "0x4" } },
    ],
  }, workspace);
  assert.equal(result.status, "ok", result.error ?? "chain failed");
  assert.equal(result.stepsCompleted, 3, "all three steps ran");
  assert.equal(result.steps.length, 3);
  // Step 0 writes the immediate 0x4d494e55 little-endian → 55 4e 49 4d;
  // xor 0x42 per byte → 17 0c 0b 0f; inc per byte → 18 0d 0c 10.
  const final = Buffer.from(result.steps[2].memory[0].bytesHex, "hex");
  assert.equal(final.toString("hex"), "180d0c10", `state must carry: step 2 saw step 1's output, got ${final.toString("hex")}`);
  assert.ok(result.stepsArtifact, "full steps artifact stored");

  // Failure mid-chain: an unmapped dereference in step 1 stops the chain —
  // stepsCompleted reflects how far it got, no garbage past the failure.
  const badStep = Buffer.from([
    0xBE, 0x00, 0x00, 0x90, 0x00, // mov esi, 0x900000 (unmapped)
    0x8A, 0x06,                   // mov al, [esi] → UC_ERR_READ_UNMAPPED
    0xC3,
  ]);
  const failed = await runEmulationChain({
    arch: "x86",
    base: "0x100000",
    until: "0x1000ff",
    data: [{ address: "0x200000", size: 4096 }],
    steps: [
      { codeHex: stepWrite.toString("hex") },
      { codeHex: badStep.toString("hex") },
      { codeHex: stepInc.toString("hex"), registers: { esi: "0x200000", ecx: "0x4" } },
    ],
  }, workspace);
  assert.equal(failed.status, "error", "chain with a failing step reports error");
  assert.equal(failed.stepsCompleted, 1, "chain stopped at the failure");
  assert.equal(failed.steps.length, 2, "step 3 never ran — no garbage past the failure");
  assert.match(failed.error ?? "", /step 1 failed/);
});

test("emu.chain: validation rejects empty steps and junk hex", async () => {
  await assert.rejects(() => runEmulationChain({ steps: [] }), /steps is empty/);
  await assert.rejects(() => runEmulationChain({ steps: [{ codeHex: "zz" }] }), /invalid hex/);
  await assert.rejects(() => runEmulationChain({ steps: [{ codeHex: "" }] }), /empty/);
});

test("emu.diff LIVE: reconstruction oracle — correct candidate matches, wrong byte is localized", { timeout: 180_000 }, async (context) => {
  const probe = spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" });
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  // THEIR function: esi=0x200000, edi=0x201000, ecx=4: lodsb; xor al,0x42; stosb; loop
  const their = Buffer.from([
    0xBE, 0x00, 0x00, 0x20, 0x00,
    0xBF, 0x00, 0x10, 0x20, 0x00,
    0xB9, 0x04, 0x00, 0x00, 0x00,
    0xAC, 0x34, 0x42, 0xAA,
    0xE2, 0xFA,
    0xC3,
  ]);
  const base = {
    arch: "x86",
    codeHex: their.toString("hex"),
    until: "0x1000ff",
    data: [
      { address: "0x200000", bytesHex: "4d494e55", size: 4096 },
      { address: "0x201000", size: 4096 },
    ],
    outputAddress: "0x201000",
  };

  // Correct reconstruction: match=true, zero divergence.
  const ok = await runEmulationDiff({ ...base, candidatePython: "out = bytes(b ^ 0x42 for b in mem[0x200000][:4])" });
  assert.equal(ok.status, "ok", ok.error ?? "oracle failed");
  assert.equal(ok.match, true, `correct candidate must match: div=${ok.divergenceCount} first=${JSON.stringify(ok.firstDivergence)}`);
  assert.equal(ok.divergenceCount, 0);
  assert.equal(ok.comparedBytes, 4);

  // Wrong key: every byte diverges, first divergence at offset 0 with the
  // exact pair of values (reference 0x0f = 'M'^0x42, candidate 0x0e).
  const wrongKey = await runEmulationDiff({ ...base, candidatePython: "out = bytes(b ^ 0x43 for b in mem[0x200000][:4])" });
  assert.equal(wrongKey.status, "ok");
  assert.equal(wrongKey.match, false);
  assert.equal(wrongKey.divergenceCount, 4);
  assert.deepEqual(wrongKey.firstDivergence, { offset: 0, referenceHex: "0f", candidateHex: "0e" }, "the oracle names the exact wrong byte");

  // A candidate that uses regs + struct (the full environment contract).
  const withRegs = await runEmulationDiff({
    ...base,
    registers: { ecx: "4" },
    candidatePython: "out = bytes(struct.pack('<I', int.from_bytes(mem[0x200000][:4], 'little') ^ 0x42424242))",
  });
  assert.equal(withRegs.status, "ok");
  assert.equal(withRegs.match, true, "struct/regs environment works");

  // Candidate crash = structured error, not a lost answer.
  const crashed = await runEmulationDiff({ ...base, candidatePython: "out = mem[0xdeadbeef][:4]" });
  assert.equal(crashed.status, "error");
  assert.match(crashed.error ?? "", /candidate python failed/);
});

test("emu.diff: validation rejects empty candidate and junk codeHex", async () => {
  await assert.rejects(() => runEmulationDiff({ codeHex: "c3", candidatePython: "", outputAddress: "0x201000" }), /candidatePython is empty/);
  await assert.rejects(() => runEmulationDiff({ codeHex: "zz", candidatePython: "out = b''", outputAddress: "0x201000" }), /invalid hex/);
});

test("emu.run: validation rejects junk input", async () => {
  await assert.rejects(() => runEmulation({ codeHex: "zz" }), /invalid hex/);
  await assert.rejects(() => runEmulation({ codeHex: "" }), /empty/);
  await assert.rejects(
    () => runEmulation({ codeHex: "90", data: [{ address: "0x200000", bytesHex: "nothex" }] }),
    /bytesHex must be hex/,
  );
});

// ---- binary.diff ----------------------------------------------------------------

test("binary.diff: same-size patch diff finds the changed region with PE context", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-diff-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  const original = fakePe("license-check-payload-GOOD");
  await writeFile(path.join(root, "original.exe"), original);
  // Patch the GOOD marker (file offset 0x416 inside .rdata → RVA 0x1016).
  const goodOffset = 0x400 + "license-check-payload-GOOD".indexOf("GOOD");
  const patched = Buffer.from(original);
  patched.write("CRCK", goodOffset, "latin1");
  await writeFile(path.join(root, "patched.exe"), patched);

  const result = await diffBinaries(workspace, {
    oldPath: "original.exe",
    newPath: "patched.exe",
    decompile: false,
  });
  assert.equal(result.identical, false);
  assert.equal(result.aligned, true);
  assert.equal(result.looksLikeRebuild, false);
  assert.ok(result.changedByteCount >= 4);
  assert.ok(result.regions.length >= 1);
  const region = result.regions.find((entry) => entry.offset <= goodOffset && entry.offset + entry.length > goodOffset);
  assert.ok(region, `changed region covering 0x${goodOffset.toString(16)}: ${JSON.stringify(result.regions.map((r) => r.offset))}`);
  assert.equal(region.section, ".rdata");
  assert.equal(region.rva, 0x1016);
  assert.equal(region.va, "0x140001016");
  assert.ok(region.oldPreview.includes("GOOD"));
  assert.ok(region.newPreview.includes("CRCK"));
});

test("binary.diff: identical files and rebuild detection", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-diff2-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  const base = fakePe("same content");
  await writeFile(path.join(root, "a.exe"), base);
  await writeFile(path.join(root, "b.exe"), base);
  const identical = await diffBinaries(workspace, { oldPath: "a.exe", newPath: "b.exe", decompile: false });
  assert.equal(identical.identical, true);
  assert.equal(identical.regions.length, 0);

  // A much larger second file = rebuild, flagged honestly.
  const grown = Buffer.concat([base, Buffer.alloc(base.length, 0x41)]);
  await writeFile(path.join(root, "grown.exe"), grown);
  const rebuild = await diffBinaries(workspace, { oldPath: "a.exe", newPath: "grown.exe", decompile: false });
  assert.equal(rebuild.looksLikeRebuild, true);
  assert.ok(rebuild.notes.some((note) => note.includes("REBUILD")));
  assert.ok(rebuild.next.some((hint) => hint.includes("binary_triage")));
});

test("operations table registers config_extract, emu_run, binary_diff", () => {
  const ids = operations.map((operation) => operation.id);
  assert.ok(ids.includes("config.extract"));
  assert.ok(ids.includes("emu.run"));
  assert.ok(ids.includes("binary.diff"));
  const emu = operations.find((operation) => operation.id === "emu.run");
  assert.deepEqual(emu.parameters.required, ["codeHex"]);
  const diff = operations.find((operation) => operation.id === "binary.diff");
  assert.deepEqual(diff.parameters.required, ["oldPath", "newPath"]);
});

test("no operation schema uses JSON type arrays (dsh tool validator rejects them)", () => {
  const violations = [];
  const walk = (schema, path) => {
    if (schema === null || typeof schema !== "object") return;
    if (Array.isArray(schema.type)) violations.push(`${path}: type array ${JSON.stringify(schema.type)}`);
    for (const [key, value] of Object.entries(schema)) {
      if (key === "items" || key === "properties") walk(value, `${path}.${key}`);
      else if (Array.isArray(value)) {
        value.forEach((entry, index) => {
          if (entry !== null && typeof entry === "object") walk(entry, `${path}.${key}[${index}]`);
        });
      }
    }
  };
  for (const operation of operations) {
    walk(operation.parameters, `${operation.id}.parameters`);
    walk(operation.outputSchema, `${operation.id}.outputSchema`);
  }
  assert.deepEqual(violations, [], `dsh rejects type arrays: ${violations.join("; ")}`);
});
