import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

/**
 * Output-schema contract test: hosts (the dsh native plugin) VALIDATE tool
 * outputs against the declared outputSchema. Any operation that returns
 * null where the schema says object/array — or an actual type mismatch —
 * crashes the whole tool call on such hosts, even though the MCP facade
 * (no output validation) never notices. This test runs every sync static
 * operation against stub samples with all docker backends disabled (the
 * worst-case degradation) and validates the shape.
 */

function validate(value, schema, pathName, violations) {
  if (schema === undefined || schema === null) return;
  if (typeof schema !== "object") return;
  if (schema.type !== undefined) {
    const actual = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
    if (schema.type === "integer" && actual === "number" && Number.isInteger(value)) return;
    if (actual !== schema.type) {
      violations.push(`${pathName}: expected ${schema.type}, got ${actual}`);
      return;
    }
  }
  if (schema.type === "object" && typeof value === "object" && value !== null && !Array.isArray(value)) {
    if (schema.required !== undefined && Array.isArray(schema.required)) {
      for (const key of schema.required) {
        if (!(key in value)) violations.push(`${pathName}: required field "${key}" missing`);
      }
    }
    const properties = schema.properties ?? {};
    for (const [key, child] of Object.entries(properties)) {
      if (key in value) validate(value[key], child, `${pathName}.${key}`, violations);
    }
  }
  if (schema.type === "array" && Array.isArray(value)) {
    if (schema.items !== undefined && typeof schema.items === "object" && !Array.isArray(schema.items)) {
      for (let index = 0; index < Math.min(value.length, 20); index += 1) {
        validate(value[index], schema.items, `${pathName}[${index}]`, violations);
      }
    }
  }
}

function withDisabledBackends() {
  const saved = {};
  const names = [
    "MINUSONE_GHIDRA_IMAGE", "MINUSONE_CAPA_IMAGE", "MINUSONE_YARA_IMAGE", "MINUSONE_FLOSS_IMAGE",
    "MINUSONE_DIE_IMAGE", "MINUSONE_R2_IMAGE", "MINUSONE_BINWALK_IMAGE", "MINUSONE_VOLATILITY_IMAGE",
    "MINUSONE_PE_TOOLS_IMAGE", "MINUSONE_EMU_IMAGE", "MINUSONE_IDA_DISABLED", "MINUSONE_R2_BIN",
    "MINUSONE_GDB_BIN", "MINUSONE_PESIEVE_BIN", "MINUSONE_CDB_PATH", "MINUSONE_X64DBG_HOME",
    "MINUSONE_UPX_BIN", "MINUSONE_BINWALK_BIN", "MINUSONE_DIE_BIN", "MINUSONE_CAPA_BIN",
  ];
  for (const name of names) {
    saved[name] = process.env[name];
    if (name === "MINUSONE_IDA_DISABLED") process.env[name] = "1";
    else process.env[name] = "";
  }
  return () => {
    for (const name of names) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  };
}

/** Minimal PE with a string payload. */
function stubPe() {
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
  buf.write("schema-contract-payload http://schema.example/c2", 0x400, "latin1");
  return buf;
}

test("every sync static operation's output matches its outputSchema under full backend degradation", { timeout: 300_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-schema-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await writeFile(path.join(root, "sample.exe"), stubPe());
  await writeFile(path.join(root, "plain.bin"), Buffer.from("plain text with a string or two"));
  await writeFile(path.join(root, "sample2.exe"), stubPe());

  const restore = withDisabledBackends();
  context.after(restore);

  const jobs = { start: () => "job-1" };
  const cases = [
    ["binary.inspect", { path: "sample.exe" }],
    ["binary.find", { path: "sample.exe", needle: "schema" }],
    ["binary.search", { path: "sample.exe", needle: "schema" }],
    ["binary.explain", { path: "sample.exe", needle: "schema", maxDecompiles: 0 }],
    ["binary.triage", { path: "sample.exe" }],
    ["binary.diff", { oldPath: "sample.exe", newPath: "sample2.exe", decompile: false }],
    ["strings.extract", { path: "sample.exe" }],
    ["strings.extract.deep", { path: "sample.exe" }],
    ["analysis.baseline", { path: "plain.bin" }],
    ["capabilities.detect", { path: "sample.exe" }],
    ["rules.scan", { path: "sample.exe", rules: 'rule a { strings: $x = "schema" condition: $x }' }],
    ["packer.detect", { path: "sample.exe" }],
    ["embedded.scan", { path: "sample.exe" }],
    ["pe.resources", { path: "sample.exe" }],
    ["unpack.static", { path: "sample.exe" }],
    ["config.extract", { path: "sample.exe", useFloss: false }],
    ["emu.run", { codeHex: "90" }],
    ["annotate.symbol", { path: "sample.exe" }],
    ["memory.read", { path: "sample.exe", offset: 0, count: 8 }],
    ["batch.survey", { paths: ["sample.exe"] }],
    ["devirt.survey", { path: "sample.exe" }],
    ["signature.verify", { path: "sample.exe" }],
    ["artifact.list", {}],
    ["provider.report", {}],
    ["report.findings", {}],
  ];

  const violations = [];
  const skipped = [];
  for (const [id, args] of cases) {
    const operation = operations.find((entry) => entry.id === id);
    assert.ok(operation, `${id} registered`);
    let result;
    try {
      result = await operation.execute(args, { workspace, jobs });
    } catch (error) {
      // A thrown error is a legitimate outcome (backend refused); the
      // contract under test is SHAPE of successful outputs.
      skipped.push(`${id} (threw: ${error instanceof Error ? error.message.slice(0, 60) : String(error)})`);
      continue;
    }
    if (result === null || result === undefined) {
      violations.push(`${id}: returned null/undefined`);
      continue;
    }
    const local = [];
    validate(result, operation.outputSchema, id, local);
    if (local.length > 0) violations.push(...local);
  }
  assert.deepEqual(violations, [], `output-schema violations (dsh would reject these):\n${violations.join("\n")}`);
  // Note: refusal-shaped results (dynamic ops unarmed) are allowed to
  // deviate — they declare status: refused schemas themselves.
  console.log("checked:", cases.length - skipped.length, "| threw (allowed):", skipped.length);
});
