/**
 * Campaign knowledge index — the query layer over the dossier. Chunks are
 * cut per-function / per-region / per-class (NEVER raw bytes), embedded
 * through the models-plane sidecar (BinSeek-Embedding, opt-in), and stored
 * under .minusone/campaign/index/:
 *
 *   chunks.jsonl   — chunk manifest: id, source file, task, operation, kind, ref, text
 *   vectors.json   — chunk id → normalized embedding
 *
 * knowledge_index is INCREMENTAL (only new dossier entries get embedded).
 * knowledge_query encodes the query and scores it against the stored
 * vectors — a ranked candidate list with source pointers, never a verdict
 * (ranker-not-oracle, the models-plane contract).
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, writeFile, appendFile } from "node:fs/promises";
import path from "node:path";
import { campaignIndexDir, dossierDir, ensureCampaignDir, listDossierIndex } from "./campaign.js";
import { embedTexts } from "./models.js";
import type { Workspace } from "./workspace.js";

const CHUNK_TEXT_CAP = 2000;
const EMBED_BATCH = 32;

export interface KnowledgeChunk {
  id: string;
  file: string;
  task: string;
  operation: string;
  kind: string;
  ref: string;
  text: string;
}

type AnyRecord = Record<string, unknown>;

function asRecord(value: unknown): AnyRecord | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as AnyRecord) : null;
}

function chunkId(source: string): string {
  return createHash("sha1").update(source).digest("hex").slice(0, 16);
}

function bound(text: unknown): string {
  return typeof text === "string" ? text.slice(0, CHUNK_TEXT_CAP) : "";
}

/** Cut one dossier entry into knowledge chunks. */
export function chunksFromEntry(file: string, task: string, operation: string, assembled: unknown): KnowledgeChunk[] {
  const record = asRecord(assembled);
  if (record === null) return [];
  const base = { file, task, operation };
  const chunks: KnowledgeChunk[] = [];
  const push = (kind: string, ref: string, text: string) => {
    if (text.trim() === "") return;
    chunks.push({ ...base, kind, ref, text: bound(text), id: chunkId(`${file}|${kind}|${ref}|${chunks.length}`) });
  };

  const functions = Array.isArray(record.functions) ? record.functions : null;
  if (functions !== null) {
    // Decompile family: one chunk PER FUNCTION — the pseudocode is the payload.
    for (const fn of functions) {
      const record2 = asRecord(fn);
      if (record2 === null) continue;
      const name = typeof record2.name === "string" ? record2.name : "";
      const va = typeof record2.va === "string" ? record2.va : "";
      const pseudocode = typeof record2.pseudocode === "string" ? record2.pseudocode : "";
      push("function", va || name, `${name} ${va}\n${pseudocode}`);
    }
    return chunks;
  }

  const fields = Array.isArray(record.fields) ? record.fields : null;
  if (fields !== null) {
    // config_extract: one chunk per harvested field (evidence included).
    for (const field of fields) {
      const record2 = asRecord(field);
      if (record2 === null) continue;
      push("config", String(record2.key ?? ""), `${record2.key ?? ""}: ${record2.value ?? ""} (${record2.confidence ?? ""}) — ${record2.evidence ?? ""}`);
    }
    return chunks;
  }

  const hits = Array.isArray(record.hits) ? record.hits : null;
  if (hits !== null) {
    // strings_find: one chunk per SECTION CLASS with its previews.
    const bySection = new Map<string, string[]>();
    for (const hit of hits) {
      const record2 = asRecord(hit);
      if (record2 === null) continue;
      const section = typeof record2.section === "string" ? record2.section : "?";
      const text = typeof record2.text === "string" ? record2.text : typeof record2.symbol === "string" ? record2.symbol : "";
      if (text !== "") bySection.set(section, [...(bySection.get(section) ?? []), text].slice(0, 20));
    }
    for (const [section, texts] of bySection) {
      push("strings", section, `strings in ${section} (needle ${String(record.needle ?? "")}):\n${texts.join("\n")}`);
    }
    if (chunks.length > 0) return chunks;
  }

  // Everything else (triage, unpack, signature, emu, generic previews):
  // one digest chunk for the entry.
  push("entry", "", JSON.stringify(record).slice(0, CHUNK_TEXT_CAP));
  return chunks;
}

async function readIndexChunks(workspace: Workspace): Promise<KnowledgeChunk[]> {
  try {
    const raw = await readFile(path.join(campaignIndexDir(workspace), "chunks.jsonl"), "utf8");
    return raw.split(/\r?\n/).filter((line) => line.trim() !== "").map((line) => JSON.parse(line) as KnowledgeChunk);
  } catch {
    return [];
  }
}

async function readVectors(workspace: Workspace): Promise<Record<string, number[]>> {
  try {
    return JSON.parse(await readFile(path.join(campaignIndexDir(workspace), "vectors.json"), "utf8")) as Record<string, number[]>;
  } catch {
    return {};
  }
}

export interface IndexReport {
  status: "ok" | "error" | "unavailable";
  indexedChunks: number;
  addedChunks: number;
  skippedExisting: number;
  entriesScanned: number;
  byKind: Record<string, number>;
  error?: string;
}

/** Build/refresh the campaign knowledge index from the dossier (incremental). */
export async function buildKnowledgeIndex(workspace: Workspace): Promise<IndexReport> {
  const entries = await listDossierIndex(workspace);
  const okEntries = entries.filter((line) => line.status === "ok");
  const existingChunks = await readIndexChunks(workspace);
  const existingIds = new Set(existingChunks.map((chunk) => chunk.id));
  const vectors = await readVectors(workspace);

  const fresh: KnowledgeChunk[] = [];
  let scanned = 0;
  for (const line of okEntries) {
    let assembled: unknown;
    try {
      const entry = JSON.parse(await readFile(path.join(dossierDir(workspace), line.file), "utf8")) as AnyRecord;
      assembled = entry.assembled;
    } catch {
      continue; // a torn entry is skipped, never fatal
    }
    scanned += 1;
    for (const chunk of chunksFromEntry(line.file, line.task, line.operation, assembled)) {
      if (!existingIds.has(chunk.id) && !(chunk.id in vectors)) fresh.push(chunk);
    }
  }

  const report: IndexReport = {
    status: "ok",
    indexedChunks: existingChunks.length,
    addedChunks: 0,
    skippedExisting: existingChunks.length,
    entriesScanned: scanned,
    byKind: {},
  };
  if (fresh.length === 0) return report;

  await ensureCampaignDir(workspace);
  for (let start = 0; start < fresh.length; start += EMBED_BATCH) {
    const batch = fresh.slice(start, start + EMBED_BATCH);
    const embedded = await embedTexts(workspace, batch.map((chunk) => chunk.text));
    if (embedded.status !== "ok" || embedded.embeddings === undefined) {
      return { ...report, status: embedded.status, error: embedded.error ?? "embedding failed" };
    }
    for (let index = 0; index < batch.length; index += 1) {
      const chunk = batch[index];
      const vector = embedded.embeddings[index];
      if (chunk === undefined || vector === undefined) continue;
      vectors[chunk.id] = vector;
      await appendFile(path.join(campaignIndexDir(workspace), "chunks.jsonl"), `${JSON.stringify(chunk)}\n`, "utf8");
      report.addedChunks += 1;
      report.byKind[chunk.kind] = (report.byKind[chunk.kind] ?? 0) + 1;
    }
  }
  await writeFile(path.join(campaignIndexDir(workspace), "vectors.json"), JSON.stringify(vectors), "utf8");
  report.indexedChunks += report.addedChunks;
  return report;
}

export interface KnowledgeHit {
  score: number;
  task: string;
  operation: string;
  kind: string;
  ref: string;
  file: string;
  text: string;
}

export interface QueryReport {
  status: "ok" | "error" | "unavailable";
  ranked?: KnowledgeHit[];
  indexedChunks?: number;
  note?: string;
  error?: string;
}

const QUERY_PREVIEW_CHARS = 600;

/** Rank the campaign's indexed knowledge against a plain-language query. */
export async function queryKnowledge(workspace: Workspace, query: string, topN = 8): Promise<QueryReport> {
  if (query.trim() === "") return { status: "error", error: "query is empty" };
  const chunks = await readIndexChunks(workspace);
  if (chunks.length === 0) {
    return { status: "error", error: "the knowledge index is empty — run knowledge_index first (and the dossier must hold completed tasks)" };
  }
  const vectors = await readVectors(workspace);
  const embedded = await embedTexts(workspace, [query]);
  if (embedded.status !== "ok" || embedded.embeddings?.[0] === undefined) {
    return { status: embedded.status, error: embedded.error ?? "query embedding failed" };
  }
  const queryVector = embedded.embeddings[0];

  const scored: KnowledgeHit[] = [];
  for (const chunk of chunks) {
    const vector = vectors[chunk.id];
    if (vector === undefined || vector.length !== queryVector.length) continue;
    let dot = 0;
    for (let index = 0; index < vector.length; index += 1) {
      dot += (vector[index] ?? 0) * (queryVector[index] ?? 0);
    }
    scored.push({
      score: dot,
      task: chunk.task,
      operation: chunk.operation,
      kind: chunk.kind,
      ref: chunk.ref,
      file: chunk.file,
      text: chunk.text.slice(0, QUERY_PREVIEW_CHARS),
    });
  }
  scored.sort((a, b) => b.score - a.score);
  return {
    status: "ok",
    ranked: scored.slice(0, Math.max(1, Math.min(32, topN))),
    indexedChunks: chunks.length,
    note: "ranked candidates with cosine scores — a retrieval list, not a verdict; open the source file for the full chunk before acting",
  };
}
