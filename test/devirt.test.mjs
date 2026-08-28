import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { classifyHandler, surveyVm } from "../dist/core/devirt.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function peWithSections(sections) {
  const buf = Buffer.alloc(0x2000, 0);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write("PE\0\0", 0x80, "latin1");
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(sections.length, 0x86);
  buf.writeUInt16LE(0xf0, 0x94);
  buf.writeUInt16LE(0x20b, 0x98);
  buf.writeBigUInt64LE(0x140000000n, 0x98 + 24);
  let entry = 0x188;
  let rawCursor = 0x400;
  for (const section of sections) {
    buf.write(section.name, entry, "latin1");
    buf.writeUInt32LE(section.virtualSize ?? 0x1000, entry + 8);
    buf.writeUInt32LE(section.virtualAddress, entry + 12);
    buf.writeUInt32LE(section.rawSize ?? 0x400, entry + 16);
    buf.writeUInt32LE(section.rawSize === 0 ? 0 : rawCursor, entry + 20);
    buf.writeUInt32LE(section.characteristics, entry + 36);
    if (section.rawSize !== 0 && section.rawSize !== undefined) {
      if (section.payload !== undefined) buf.write(section.payload, rawCursor, "latin1");
      rawCursor += section.rawSize;
    }
    entry += 40;
  }
  return buf;
}

const SCN_EXECUTE = 0x60000020; // CODE|EXECUTE|READ

test("devirt.survey: clean compiled PE reports no VM with reasons", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-devirt-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "clean.exe"), peWithSections([
    { name: ".text", virtualAddress: 0x1000, rawSize: 0x400, characteristics: SCN_EXECUTE, payload: "\x90\x90\xc3" },
    { name: ".rdata", virtualAddress: 0x2000, rawSize: 0x400, characteristics: 0x40000040 },
  ]));
  const workspace = await Workspace.create(root);

  const result = await surveyVm(workspace, "clean.exe");
  assert.equal(result.vmDetected, false);
  assert.equal(result.confidence, "none");
  assert.match(result.verdict, /no VM indicators|weak single indicator/);
});

test("devirt.survey: VMProtect-style layout is detected with high confidence", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-devirt-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "vmp.exe"), peWithSections([
    { name: ".vmp0", virtualAddress: 0x1000, rawSize: 0, virtualSize: 0x8000, characteristics: SCN_EXECUTE },
    { name: ".vmp1", virtualAddress: 0x9000, rawSize: 0x800, characteristics: SCN_EXECUTE, payload: "\xff\xe0" },
    { name: ".rdata", virtualAddress: 0xb000, rawSize: 0x400, characteristics: 0x40000040 },
  ]));
  const workspace = await Workspace.create(root);

  const result = await surveyVm(workspace, "vmp.exe");
  assert.equal(result.vmDetected, true);
  assert.equal(result.confidence, "high");
  assert.ok(result.vmSections.some((section) => section.name === ".vmp0"));
  assert.ok(result.indicators.some((indicator) => /\.vmp0/.test(indicator)));
  assert.ok(result.dispatchers.some((finding) => /jmp reg/.test(finding.idiom)), "the jmp reg site in .vmp1 must be reported");
});

test("devirt.survey: dispatcher idioms are found with VA and section", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-devirt-"));
  context.after(() => rmRoot(root));
  // 0xff 0x24 0xc5 = jmp qword ptr [rax*8 + disp32]
  await writeFile(path.join(root, "disp.exe"), peWithSections([
    { name: ".text", virtualAddress: 0x1000, rawSize: 0x400, characteristics: SCN_EXECUTE, payload: "\x48\x31\xc0\xff\x24\xc5\x00\x00\x00" },
  ]));
  const workspace = await Workspace.create(root);
  const result = await surveyVm(workspace, "disp.exe");
  const computed = result.dispatchers.find((finding) => /computed handler jump/.test(finding.idiom));
  assert.ok(computed, "computed jump idiom must be reported");
  assert.equal(computed.rva, "0x1003");
  assert.equal(computed.section, ".text");
});

test("devirt.classify LIVE: XOR handler classified as COMPUTE, NOP junk as NO-EFFECT", { timeout: 120_000 }, async (context) => {
  const probe = await import("node:child_process").then((cp) => cp.spawnSync("docker", ["images", "--format", "{{.Repository}}", "minusone/unicorn"], { encoding: "utf8" }));
  if (probe.status !== 0 || !probe.stdout.includes("minusone/unicorn")) {
    context.skip("needs the minusone/unicorn docker image");
  }
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-devirt-classify-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);

  // xor rax, rbx; ret — input-dependent register transform, no memory writes.
  const xorHandler = "4831d8c3";
  const xor = await classifyHandler(workspace, { codeHex: xorHandler });
  assert.equal(xor.status, "ok", xor.error ?? "emulation failed");
  assert.match(xor.classification, /COMPUTE/, `XOR handler must classify as COMPUTE (got ${xor.classification})`);
  assert.ok(xor.effects.some((effect) => /rax/.test(effect)));

  // nop; ret — identical state across different inputs = junk handler.
  const junk = "90c3";
  const noEffect = await classifyHandler(workspace, { codeHex: junk });
  assert.equal(noEffect.status, "ok", noEffect.error ?? "emulation failed");
  assert.match(noEffect.classification, /NO-EFFECT/, `NOP handler must classify as NO-EFFECT (got ${noEffect.classification})`);

  // mov [rdi], rax; ret — memory write = STORE.
  const store = "488907c3";
  const storeResult = await classifyHandler(workspace, { codeHex: store });
  assert.equal(storeResult.status, "ok", storeResult.error ?? "emulation failed");
  assert.match(storeResult.classification, /STORE/, `store handler must classify as STORE (got ${storeResult.classification})`);
});

test("devirt operations registered with output contracts", () => {
  const survey = operations.find((entry) => entry.id === "devirt.survey");
  assert.ok(survey, "devirt.survey registered");
  assert.equal(survey.toolName, "devirt_survey");
  const classify = operations.find((entry) => entry.id === "devirt.classify");
  assert.ok(classify, "devirt.classify registered");
  assert.equal(classify.toolName, "devirt_classify");
  assert.ok(classify.outputSchema.required.includes("classification"));
});
