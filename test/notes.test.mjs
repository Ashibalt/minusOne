// Phase 3 (v2): investigation notes — parse/render round-trip, every
// update action, hypothesis status evolution, question resolution, and
// the notes_read/notes_update operations end to end.

import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseNotes, readNotes, renderNotes, updateNotes } from "../dist/core/notes.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

async function freshWorkspace(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-notes-"));
  context.after(() => rmRoot(root));
  return Workspace.create(root);
}

test("notes: parse/render round-trips every section", () => {
  const data = {
    goal: "recover sources",
    updated: "2026-08-28T10:00:00.000Z",
    hypotheses: [
      { status: "open", text: "config is AES-128", stamp: "2026-08-28T10:01:00.000Z" },
      { status: "killed", text: "strings are plaintext", stamp: "2026-08-28T10:02:00.000Z" },
    ],
    addresses: [{ address: "0x140001000", name: "validate_key" }],
    deadEnds: [{ text: "dynamic without the format gate", stamp: "2026-08-28T10:03:00.000Z" }],
    openQuestions: ["where does the salt come from?"],
    log: [{ stamp: "2026-08-28T10:00:00.000Z", text: "campaign started" }],
  };
  const parsed = parseNotes(renderNotes(data));
  assert.equal(parsed.goal, "recover sources");
  assert.equal(parsed.hypotheses.length, 2);
  assert.equal(parsed.hypotheses[1].status, "killed");
  assert.deepEqual(parsed.addresses, [{ address: "0x140001000", name: "validate_key" }]);
  assert.equal(parsed.deadEnds[0].text, "dynamic without the format gate");
  assert.deepEqual(parsed.openQuestions, ["where does the salt come from?"]);
  assert.equal(parsed.log[0].text, "campaign started");
});

test("notes: updates apply every action; hypothesis status evolves in place", async (context) => {
  const workspace = await freshWorkspace(context);
  assert.equal((await readNotes(workspace)).exists, false, "no notes before the first update");

  await updateNotes(workspace, { action: "goal", text: "recover sources from example.dll" });
  await updateNotes(workspace, { action: "hypothesis", text: "config is AES-128", status: "open" });
  await updateNotes(workspace, { action: "hypothesis", text: "strings are plaintext", status: "open" });
  await updateNotes(workspace, { action: "hypothesis", text: "strings are plaintext", status: "killed" });
  await updateNotes(workspace, { action: "address", address: "0x140001000", name: "validate_key" });
  await updateNotes(workspace, { action: "dead_end", text: "dynamic run without the gate — hooks silent" });
  await updateNotes(workspace, { action: "question", text: "where is the salt?" });
  await updateNotes(workspace, { action: "log", text: "emu.diff confirmed the XOR candidate" });

  const notes = await readNotes(workspace);
  assert.equal(notes.exists, true);
  assert.equal(notes.data.goal, "recover sources from example.dll");
  assert.equal(notes.data.hypotheses.length, 2, "status evolution replaces, not appends");
  assert.equal(notes.data.hypotheses[1].status, "killed");
  assert.equal(notes.data.addresses.length, 1);
  assert.equal(notes.data.deadEnds.length, 1);
  assert.deepEqual(notes.data.openQuestions, ["where is the salt?"]);
  assert.ok(notes.data.log.length >= 2);

  // Address dedupe + question resolution.
  await updateNotes(workspace, { action: "address", address: "0x140001000", name: "validate_key" });
  assert.equal((await readNotes(workspace)).data.addresses.length, 1, "address dedupes");
  const resolved = await updateNotes(workspace, { action: "resolve_question", text: "salt" });
  assert.equal(resolved.summary.openQuestions, 0, "substring match resolves the question");

  // The summary reports section counts.
  const summary = resolved.summary;
  assert.equal(summary.hypotheses.killed, 1);
  assert.equal(summary.hypotheses.open, 1);
  assert.equal(summary.deadEnds, 1);
});

test("notes: operations notes_read/notes_update end to end, with validation", async (context) => {
  const workspace = await freshWorkspace(context);
  const read = operations.find((operation) => operation.toolName === "notes_read");
  const update = operations.find((operation) => operation.toolName === "notes_update");
  assert.ok(read && update, "notes operations registered");

  const empty = await read.execute({}, { workspace });
  assert.equal(empty.exists, false);
  assert.equal(empty.markdown, "");

  await update.execute({ action: "hypothesis", text: "blob is XOR 0x42", status: "open" }, { workspace });
  await update.execute({ action: "log", text: "carved the decryptor stub at 0x140005170" }, { workspace });
  const full = await read.execute({}, { workspace });
  assert.equal(full.exists, true);
  assert.match(full.markdown, /blob is XOR 0x42/);
  assert.match(full.markdown, /carved the decryptor stub/);
  assert.equal(full.summary.hypotheses.open, 1);
  assert.equal(full.summary.logLines, 1);

  // Validation: missing text / status / address parts fail fast.
  await assert.rejects(() => update.execute({ action: "log" }, { workspace }), /text/);
  await assert.rejects(() => update.execute({ action: "hypothesis", text: "x" }, { workspace }), /status/);
  await assert.rejects(() => update.execute({ action: "address", address: "0x1000" }, { workspace }), /name/);

  // campaign_status sees the notes now.
  const status = await operations.find((operation) => operation.toolName === "campaign_status").execute({}, { workspace });
  assert.equal(status.notesPresent, true);
});
