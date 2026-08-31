// Phase 4 (v2): campaign knowledge index — chunk cutting per family,
// unavailable-when-models-off, the full index→query flow over a FAKE
// sidecar (deterministic keyword embeddings, no torch), incremental
// rebuilds, and the empty-index honest error.

import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { writeDossierEntry } from "../dist/core/campaign.js";
import { buildKnowledgeIndex, chunksFromEntry, queryKnowledge } from "../dist/core/knowledge.js";
import { shutdownModels } from "../dist/core/models.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const FAKE_SIDECAR = path.resolve("test/fixtures/fake-sidecar.py");

function armFakeModels(context) {
  const previous = {
    models: process.env.MINUSONE_MODELS,
    sidecar: process.env.MINUSONE_MODELS_SIDECAR,
    python: process.env.MINUSONE_MODELS_PYTHON,
  };
  process.env.MINUSONE_MODELS = "1";
  process.env.MINUSONE_MODELS_SIDECAR = FAKE_SIDECAR;
  process.env.MINUSONE_MODELS_PYTHON = "python";
  context.after(async () => {
    await shutdownModels().catch(() => {});
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

async function freshWorkspace(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-knowledge-"));
  context.after(() => rmRoot(root));
  return Workspace.create(root);
}

test("knowledge: chunksFromEntry cuts per-function, per-field, per-section, digest", () => {
  const functions = chunksFromEntry("f1.json", "decomp", "ida_decompile", {
    functions: [
      { name: "validate_key", va: "0x140001000", pseudocode: "__int64 validate_key() { return check(); }" },
      { name: "main", va: "0x140002000", pseudocode: "int main() { return validate_key(); }" },
    ],
  });
  assert.equal(functions.length, 2);
  assert.equal(functions[0].kind, "function");
  assert.equal(functions[0].ref, "0x140001000");
  assert.match(functions[0].text, /validate_key/);

  const fields = chunksFromEntry("f2.json", "cfg", "config_extract", {
    fields: [{ key: "c2", value: "evil.example:443", confidence: "high", evidence: "decoded string" }],
  });
  assert.equal(fields.length, 1);
  assert.equal(fields[0].kind, "config");
  assert.match(fields[0].text, /evil\.example:443/);

  const strings = chunksFromEntry("f3.json", "strings", "strings_find", {
    needle: "license",
    hits: [
      { section: ".rdata", text: "license key invalid" },
      { section: ".rdata", text: "enter your serial" },
      { section: ".text", text: "some code string" },
    ],
  });
  assert.equal(strings.length, 2, "grouped by section");
  assert.equal(strings[0].kind, "strings");
  assert.match(strings[0].text, /license key invalid/);

  const digest = chunksFromEntry("f4.json", "triage", "binary_triage", { verdict: { packed: true }, entropy: 7.9 });
  assert.equal(digest.length, 1);
  assert.equal(digest[0].kind, "entry");

  assert.deepEqual(chunksFromEntry("f5.json", "t", "op", null), [], "garbage → no chunks");
});

test("knowledge: index build is unavailable when the models plane is off", async (context) => {
  const workspace = await freshWorkspace(context);
  delete process.env.MINUSONE_MODELS;
  await writeDossierEntry(workspace, {
    task: "decomp", operation: "ida_decompile", status: "ok",
    completedAt: new Date().toISOString(),
    attempts: [{ operation: "ida_decompile", status: "ok", durationMs: 1 }],
    result: { decompiled: [{ name: "validate_key", start: "0x140001000", pseudocodePreview: "validate the license" }] },
  });
  const report = await buildKnowledgeIndex(workspace);
  assert.equal(report.status, "unavailable", "off plane → unavailable, no silent spend");
});

test("knowledge: full index→query flow over the fake sidecar, incremental rebuild", async (context) => {
  armFakeModels(context);
  const workspace = await freshWorkspace(context);
  await writeDossierEntry(workspace, {
    task: "decomp", operation: "ida_decompile", status: "ok",
    completedAt: new Date().toISOString(),
    attempts: [{ operation: "ida_decompile", status: "ok", durationMs: 1 }],
    result: { decompiled: [
      { name: "validate_key", start: "0x140001000", pseudocodePreview: "validate the serial key against the expected hash" },
      { name: "render_ui", start: "0x140002000", pseudocodePreview: "draw the menu and print colors" },
    ] },
  });

  const built = await buildKnowledgeIndex(workspace);
  assert.equal(built.status, "ok", built.error ?? "");
  assert.equal(built.addedChunks, 2, "two function chunks indexed");

  const answer = await queryKnowledge(workspace, "where is the validator");
  assert.equal(answer.status, "ok", answer.error ?? "");
  assert.equal(answer.ranked.length, 2);
  assert.equal(answer.ranked[0].ref, "0x140001000", "the validator function outranks the UI function");
  assert.ok(answer.ranked[0].score > answer.ranked[1].score);
  assert.match(answer.note, /not a verdict/, "ranker-not-oracle contract in the note");
  assert.equal(answer.ranked[0].task, "decomp", "hits carry the source task");

  // Incremental: a second build with one NEW dossier entry adds only its chunks.
  await writeDossierEntry(workspace, {
    task: "cfg", operation: "config_extract", status: "ok",
    completedAt: new Date().toISOString(),
    attempts: [{ operation: "config_extract", status: "ok", durationMs: 1 }],
    result: { fields: [{ key: "license_server", value: "license.example:443", confidence: "high", evidence: "decoded" }] },
  });
  const rebuilt = await buildKnowledgeIndex(workspace);
  assert.equal(rebuilt.addedChunks, 1, "only the new entry's chunk got embedded");
  assert.equal(rebuilt.indexedChunks, 3);

  const licenseAnswer = await queryKnowledge(workspace, "where does the license check talk to");
  assert.equal(licenseAnswer.ranked[0].kind, "config", "the new config chunk is queryable");
});

test("knowledge: query on an empty index says to build it first", async (context) => {
  armFakeModels(context);
  const workspace = await freshWorkspace(context);
  const answer = await queryKnowledge(workspace, "anything");
  assert.equal(answer.status, "error");
  assert.match(answer.error, /knowledge_index/);
  await assert.rejects(async () => {
    const bad = await queryKnowledge(workspace, "  ");
    if (bad.status === "error") throw new Error(bad.error);
  }, /empty/);
});
