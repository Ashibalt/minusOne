/**
 * Per-sample symbol map — the "write-back lite" plane. The agent renames
 * what it understands (a function at 0x140001450 becomes
 * check_license_expiry) and every subsequent operation — binary_find,
 * binary_search, binary_explain, trace_source — resolves those addresses
 * through the map, so the agent's knowledge compounds across the session
 * without any disassembler-side state. Stored as JSON under
 * .minusone/symbols/<sampleId>.json; entries are keyed by VA (hex string
 * in reports, number internally) and carry an optional comment plus
 * provenance.
 */
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Workspace } from "./workspace.js";

export const SYMBOLS_MAX_ENTRIES = 4096;
export const SYMBOLS_MAX_NAME_CHARS = 256;
export const SYMBOLS_MAX_COMMENT_CHARS = 1024;

export interface SymbolEntry {
  /** Virtual address as a "0x..." hex string (stable across reports). */
  va: string;
  name: string;
  comment?: string;
  updatedAt: number;
  /** Where the rename came from: "agent" (annotate op) or an operation id. */
  source: string;
}

export interface SymbolUpsert {
  va: string;
  name: string;
  comment?: string;
  source?: string;
}

function symbolsDir(workspace: Workspace): string {
  return path.join(workspace.root, ".minusone", "symbols");
}

function symbolsFile(workspace: Workspace, sampleId: string): string {
  return path.join(symbolsDir(workspace), `${sampleId}.json`);
}

/** Parse "0x140001450" / "140001450" (hex) into a number; null when invalid. */
export function parseVa(value: string): number | null {
  const trimmed = value.trim().toLowerCase();
  if (!/^(0x)?[0-9a-f]+$/.test(trimmed)) return null;
  const numeric = Number.parseInt(trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed, 16);
  return Number.isSafeInteger(numeric) && numeric > 0 ? numeric : null;
}

export function formatVa(va: number): string {
  return `0x${va.toString(16)}`;
}

export async function readSymbolMap(workspace: Workspace, sampleId: string): Promise<SymbolEntry[]> {
  try {
    const parsed = JSON.parse(await readFile(symbolsFile(workspace, sampleId), "utf8")) as unknown;
    if (!Array.isArray(parsed)) return [];
    const entries: SymbolEntry[] = [];
    for (const raw of parsed) {
      if (raw === null || typeof raw !== "object") continue;
      const entry = raw as Partial<SymbolEntry>;
      const va = typeof entry.va === "string" ? parseVa(entry.va) : null;
      if (va === null || typeof entry.name !== "string" || entry.name === "") continue;
      entries.push({
        va: formatVa(va),
        name: entry.name.slice(0, SYMBOLS_MAX_NAME_CHARS),
        ...(typeof entry.comment === "string" && entry.comment !== "" ? { comment: entry.comment.slice(0, SYMBOLS_MAX_COMMENT_CHARS) } : {}),
        updatedAt: typeof entry.updatedAt === "number" ? entry.updatedAt : 0,
        source: typeof entry.source === "string" ? entry.source : "unknown",
      });
    }
    return entries;
  } catch {
    return [];
  }
}

/** VA → entry lookup table; hex VA strings are the canonical key format. */
export async function loadSymbolIndex(workspace: Workspace, sampleId: string): Promise<Map<number, SymbolEntry>> {
  const index = new Map<number, SymbolEntry>();
  for (const entry of await readSymbolMap(workspace, sampleId)) {
    const va = parseVa(entry.va);
    if (va !== null) index.set(va, entry);
  }
  return index;
}

export async function upsertSymbols(workspace: Workspace, sampleId: string, upserts: SymbolUpsert[]): Promise<SymbolEntry[]> {
  const existing = new Map<number, SymbolEntry>();
  for (const entry of await readSymbolMap(workspace, sampleId)) {
    const va = parseVa(entry.va);
    if (va !== null) existing.set(va, entry);
  }
  const now = Date.now();
  for (const upsert of upserts) {
    const va = parseVa(upsert.va);
    if (va === null) throw new Error(`invalid VA: ${JSON.stringify(upsert.va)}`);
    const name = upsert.name.trim();
    if (name === "") throw new Error(`empty symbol name for VA ${upsert.va}`);
    if (existing.size >= SYMBOLS_MAX_ENTRIES && !existing.has(va)) {
      throw new Error(`symbol map is full (${SYMBOLS_MAX_ENTRIES} entries)`);
    }
    const comment = upsert.comment?.trim();
    const previous = existing.get(va);
    existing.set(va, {
      va: formatVa(va),
      name: name.slice(0, SYMBOLS_MAX_NAME_CHARS),
      ...(comment !== undefined && comment !== "" ? { comment: comment.slice(0, SYMBOLS_MAX_COMMENT_CHARS) } : {}),
      updatedAt: now,
      source: upsert.source ?? "agent",
    });
  }
  const entries = [...existing.values()].sort((left, right) => (parseVa(left.va) ?? 0) - (parseVa(right.va) ?? 0));
  await mkdir(symbolsDir(workspace), { recursive: true });
  await writeFile(symbolsFile(workspace, sampleId), JSON.stringify(entries, null, 2), "utf8");
  return entries;
}

export async function removeSymbols(workspace: Workspace, sampleId: string, vas: string[]): Promise<SymbolEntry[]> {
  const existing = new Map<number, SymbolEntry>();
  for (const entry of await readSymbolMap(workspace, sampleId)) {
    const va = parseVa(entry.va);
    if (va !== null) existing.set(va, entry);
  }
  for (const candidate of vas) {
    const va = parseVa(candidate);
    if (va !== null) existing.delete(va);
  }
  const entries = [...existing.values()].sort((left, right) => (parseVa(left.va) ?? 0) - (parseVa(right.va) ?? 0));
  if (entries.length === 0) {
    await rm(symbolsFile(workspace, sampleId), { force: true });
  } else {
    await mkdir(symbolsDir(workspace), { recursive: true });
    await writeFile(symbolsFile(workspace, sampleId), JSON.stringify(entries, null, 2), "utf8");
  }
  return entries;
}

/** Resolve a VA through the index; null when unmapped. */
export function lookupSymbol(index: Map<number, SymbolEntry>, va: number): SymbolEntry | null {
  return index.get(va) ?? null;
}

/** Resolve a "0x..." VA string through the index (parse tolerant). */
export function lookupSymbolString(index: Map<number, SymbolEntry>, va: string | null | undefined): SymbolEntry | null {
  if (va === null || va === undefined) return null;
  const parsed = parseVa(va);
  return parsed === null ? null : lookupSymbol(index, parsed);
}
