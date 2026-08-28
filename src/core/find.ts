/**
 * binary.find — the first intent-level operation: one call answers "where
 * does X live in this binary" across every static plane we can read
 * natively. Fan-out: raw bytes (file offsets, ASCII/UTF-16/hex/regex),
 * extracted strings, PE import/export tables, PE resource strings, and the
 * cached radare2 function listing (the disassembly.functions artifact).
 * Cross-plane correlation is the point: a hit carries its file offset,
 * section, RVA/VA and — when a cached function list exists — the function
 * it sits inside, so the agent never hand-glues this together again.
 * Deliberately spawn-free: every plane is either an in-process parse or a
 * cache read, so a find returns in well under a second on typical samples.
 */
import { open, stat } from "node:fs/promises";
import { cacheKeyDigest, findArtifactByCacheKey, readArtifactFull } from "./artifacts.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { inspectBinary } from "./binary.js";
import { fileOffsetToRva, parsePeTablesFromBuffer, sectionForFileOffset } from "./peimports.js";
import type { PeTables } from "./peimports.js";
import { parsePeResources } from "./peresources.js";
import { extractStrings } from "./strings.js";
import { loadSymbolIndex, lookupSymbol } from "./symbols.js";
import type { SymbolEntry } from "./symbols.js";
import type { RadareFunction } from "./radare.js";
import type { Workspace } from "./workspace.js";

export const FIND_DEFAULT_MAX_HITS = 50;
export const FIND_MAX_HITS_CAP = 500;
export const FIND_DEFAULT_SCAN_BYTES = 128 * 1024 * 1024;
const FIND_MAX_NEEDLE_CHARS = 512;
const FIND_MAX_HEX_CHARS = 1024;
const PLANE_HIT_CAP = 2000;
const VALUE_PREVIEW_CHARS = 256;
const BYTES_WINDOW = 32;
const STRINGS_PLANE_LIMIT = 2000;

export type FindKind = "string" | "bytes" | "regex" | "api" | "symbol";

export interface FindOptions {
  needle: string;
  kind?: FindKind;
  caseSensitive?: boolean;
  maxHits?: number;
  maxScanBytes?: number;
}

export interface FindHit {
  plane: "bytes" | "strings" | "imports" | "exports" | "resources" | "symbols";
  offset: number | null;
  value: string;
  preview: string;
  section?: string | null;
  rva?: number | null;
  va?: string | null;
  encoding?: "ascii" | "utf16le";
  function?: string | null;
  /** Agent-assigned name from annotate.symbol for this hit's VA. */
  symbol?: string | null;
  symbolComment?: string | null;
  matchOn?: "name" | "dll";
  dll?: string;
  iatVa?: string | null;
  ordinal?: number | null;
  key?: string;
}

export interface FindResult {
  path: string;
  sampleId: string;
  sha256: string;
  format: { kind: string; architecture: string; bits: number | null };
  needle: string;
  kind: FindKind;
  caseSensitive: boolean;
  hits: FindHit[];
  hitCount: number;
  truncated: boolean;
  planeCounts: Record<string, number>;
  planes: { consulted: string[]; skipped: Array<{ plane: string; reason: string }> };
  scan: { scannedBytes: number; fileSize: number; truncated: boolean };
  notes: string[];
  next: string[];
}

/** ASCII-only case folding so byte offsets survive the lowercase pass. */
function foldAscii(text: string): string {
  return text.replace(/[A-Z]/g, (char) => String.fromCharCode(char.charCodeAt(0) + 32));
}

function parseHexNeedle(needle: string): Buffer {
  if (!/^[0-9a-fA-F]+$/.test(needle) || needle.length % 2 !== 0) {
    throw new Error(`bytes needle must be non-empty even-length hex (e.g. "4d5a"), got ${JSON.stringify(needle.slice(0, 64))}`);
  }
  if (needle.length > FIND_MAX_HEX_CHARS) {
    throw new Error(`bytes needle is too long (${needle.length / 2} bytes; cap ${FIND_MAX_HEX_CHARS / 2})`);
  }
  return Buffer.from(needle, "hex");
}

function printableWindow(buffer: Buffer, offset: number, length: number): string {
  const start = Math.max(0, offset - BYTES_WINDOW);
  const end = Math.min(buffer.length, offset + length + BYTES_WINDOW);
  let out = "";
  for (let index = start; index < end; index += 1) {
    const byte = buffer[index] ?? 0;
    out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
  }
  return out;
}

function capText(value: string, limit: number): string {
  return value.length <= limit ? value : `${value.slice(0, limit)}...`;
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

/** Match strategy shared by every text plane: substring or regex. */
function createTextMatcher(needle: string, kind: FindKind, caseSensitive: boolean): (value: string) => boolean {
  if (kind === "regex") {
    if (needle.length < 1 || needle.length > FIND_MAX_NEEDLE_CHARS) {
      throw new Error(`regex needle must be 1-${FIND_MAX_NEEDLE_CHARS} characters`);
    }
    let regex: RegExp;
    try {
      regex = new RegExp(needle, caseSensitive ? "" : "i");
    } catch (error) {
      throw new Error(`invalid regular expression: ${error instanceof Error ? error.message : String(error)}`);
    }
    return (value) => regex.test(value);
  }
  if (needle.length < 1 || needle.length > FIND_MAX_NEEDLE_CHARS) {
    throw new Error(`needle must be 1-${FIND_MAX_NEEDLE_CHARS} characters`);
  }
  if (caseSensitive) return (value) => value.includes(needle);
  const folded = needle.toLowerCase();
  return (value) => value.toLowerCase().includes(folded);
}

function planesForKind(kind: FindKind): string[] {
  switch (kind) {
    case "bytes":
      return ["bytes"];
    case "api":
      return ["imports", "exports", "strings"];
    case "symbol":
      return ["symbols", "exports"];
    case "regex":
      return ["strings", "imports", "exports", "resources", "symbols"];
    case "string":
    default:
      return ["strings", "bytes", "imports", "exports", "resources"];
  }
}

/** True when any plane in this find's fan-out produces hits with file offsets. */
function hitsMayCarryVa(wanted: string[]): boolean {
  return wanted.includes("strings") || wanted.includes("bytes") || wanted.includes("resources");
}

/**
 * Reuse the disassembly.functions cache key so a prior function listing
 * (same sample, same backend identity) lights up the symbols plane and
 * function-level enrichment for free.
 */
async function loadCachedFunctions(workspace: Workspace, sha256: string): Promise<RadareFunction[] | null> {
  const cacheKey = cacheKeyDigest({
    sample: sha256,
    operation: "disassembly.functions",
    image: resolveDockerImage(process.env.MINUSONE_R2_IMAGE, DEFAULT_IMAGES.radare2),
    local: process.env.MINUSONE_R2_BIN ?? null,
    schema: 1,
  });
  const cached = await findArtifactByCacheKey(workspace, cacheKey);
  if (cached === null) return null;
  try {
    const parsed = JSON.parse(await readArtifactFull(workspace, cached.id)) as unknown;
    return Array.isArray(parsed) ? (parsed as RadareFunction[]) : null;
  } catch {
    return null;
  }
}

function functionForVa(functions: RadareFunction[] | null, va: number): string | null {
  if (functions === null) return null;
  for (const fn of functions) {
    if (typeof fn.offset !== "number" || typeof fn.name !== "string") continue;
    const size = typeof fn.realsz === "number" ? fn.realsz : typeof fn.size === "number" ? fn.size : 0;
    if (va >= fn.offset && va < fn.offset + Math.max(size, 1)) return fn.name;
  }
  return null;
}

export async function findInBinary(workspace: Workspace, userPath: string, options: FindOptions): Promise<FindResult> {
  const kind: FindKind = options.kind ?? "string";
  const caseSensitive = options.caseSensitive === true;
  const maxHits = Math.min(FIND_MAX_HITS_CAP, Math.max(1, Math.floor(options.maxHits ?? FIND_DEFAULT_MAX_HITS)));
  const hexNeedle = kind === "bytes" ? parseHexNeedle(options.needle) : null;
  const match = createTextMatcher(options.needle, kind, caseSensitive);

  const binary = await inspectBinary(workspace, userPath);
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const scanCap = Math.max(1024, Math.floor(options.maxScanBytes ?? FIND_DEFAULT_SCAN_BYTES));
  const scannedBytes = Math.min(fileStats.size, scanCap);
  const handle = await open(absolutePath, "r");
  const buffer = Buffer.alloc(scannedBytes);
  try {
    if (scannedBytes > 0) await handle.read(buffer, 0, scannedBytes, 0);
  } finally {
    await handle.close();
  }

  const wanted = planesForKind(kind);
  const consulted: string[] = [];
  const skipped: Array<{ plane: string; reason: string }> = [];
  const notes: string[] = [];
  const hits: FindHit[] = [];
  const planeCounts: Record<string, number> = {};
  const count = (plane: string) => {
    planeCounts[plane] = (planeCounts[plane] ?? 0) + 1;
  };

  const tables: PeTables | null = binary.format.kind === "pe" ? await parsePeTablesFromBuffer(buffer) : null;
  if (tables !== null && tables.partial.length > 0) notes.push(...tables.partial);

  // PE-only planes degrade to a skip note on other formats.
  for (const plane of ["imports", "exports", "resources"] as const) {
    if (wanted.includes(plane) && tables === null) {
      skipped.push({ plane, reason: `requires a PE file (detected format: ${binary.format.kind})` });
    }
  }

  let functions: RadareFunction[] | null = null;
  // Function context enriches hits on every kind: load the cached radare2
  // listing whenever the sample is a PE, even when the symbols plane itself
  // is not part of this find's fan-out.
  if (tables !== null && (wanted.includes("symbols") || hitsMayCarryVa(wanted))) {
    functions = await loadCachedFunctions(workspace, binary.sha256);
    if (functions === null && wanted.includes("symbols")) {
      skipped.push({
        plane: "symbols",
        reason: "no cached radare2 function listing for this sample; run disassembly_functions first to populate it",
      });
    }
  }

  // ---- strings plane -------------------------------------------------------
  if (wanted.includes("strings")) {
    consulted.push("strings");
    const extraction = await extractStrings(workspace, userPath, { limit: STRINGS_PLANE_LIMIT, maxScanBytes: scanCap });
    if (extraction.resultTruncated) {
      notes.push(
        `strings plane stopped at its ${STRINGS_PLANE_LIMIT}-string extraction cap BEFORE the end of the scan window — matches beyond that point were NOT seen: use binary_search (streams the whole file, resumable) for exhaustive coverage`,
      );
      skipped.push({ plane: "strings(exhaustive)", reason: `extraction capped at ${STRINGS_PLANE_LIMIT} strings within the scan window; binary_search covers the whole file` });
    }
    for (const entry of extraction.strings) {
      if (!match(entry.value)) continue;
      count("strings");
      if (hits.length >= PLANE_HIT_CAP) break;
      hits.push({
        plane: "strings",
        offset: entry.offset,
        value: capText(entry.value, VALUE_PREVIEW_CHARS),
        preview: capText(entry.value, VALUE_PREVIEW_CHARS),
        encoding: entry.encoding,
      });
    }
  }

  // ---- bytes plane (raw file offsets) --------------------------------------
  if (wanted.includes("bytes")) {
    consulted.push("bytes");
    const haystack = buffer.toString("latin1");
    const searchIn = caseSensitive ? haystack : foldAscii(haystack);
    const patterns: Array<{ label: "ascii" | "utf16le" | "hex"; text: string; length: number }> = [];
    if (hexNeedle !== null) {
      patterns.push({ label: "hex", text: hexNeedle.toString("latin1"), length: hexNeedle.length });
    } else {
      const ascii = options.needle;
      const utf16 = Buffer.from(options.needle, "utf16le").toString("latin1");
      patterns.push({ label: "ascii", text: ascii, length: ascii.length });
      if (utf16 !== ascii) patterns.push({ label: "utf16le", text: utf16, length: utf16.length });
    }
    const stringOffsets = new Set(hits.filter((hit) => hit.plane === "strings").map((hit) => hit.offset));
    for (const pattern of patterns) {
      const needle = caseSensitive ? pattern.text : foldAscii(pattern.text);
      let index = searchIn.indexOf(needle);
      while (index !== -1) {
        if (!stringOffsets.has(index)) {
          count("bytes");
          if (hits.length < PLANE_HIT_CAP) {
            hits.push({
              plane: "bytes",
              offset: index,
              value: pattern.label === "hex" ? `hex:${options.needle}` : options.needle,
              preview: printableWindow(buffer, index, pattern.length),
              encoding: pattern.label === "utf16le" ? "utf16le" : "ascii",
            });
          }
        }
        index = searchIn.indexOf(needle, index + 1);
      }
      if (hits.length >= PLANE_HIT_CAP) {
        notes.push(`bytes plane hit its ${PLANE_HIT_CAP}-hit cap; narrow the needle or lower maxScanBytes`);
        break;
      }
    }
  }

  // ---- imports / exports planes ---------------------------------------------
  if (tables !== null) {
    if (wanted.includes("imports")) {
      consulted.push("imports");
      const matchedDlls = new Set<string>();
      for (const entry of tables.imports) {
        if (match(entry.name)) {
          count("imports");
          hits.push({
            plane: "imports",
            offset: entry.nameOffset,
            value: `${entry.dll}!${entry.name}`,
            preview: `${entry.dll}!${entry.name}`,
            matchOn: "name",
            dll: entry.dll,
            iatVa: hex(entry.iatVa),
          });
        } else if (match(entry.dll) && !matchedDlls.has(entry.dll)) {
          matchedDlls.add(entry.dll);
          count("imports");
          hits.push({ plane: "imports", offset: null, value: entry.dll, preview: entry.dll, matchOn: "dll", dll: entry.dll });
        }
      }
    }
    if (wanted.includes("exports")) {
      consulted.push("exports");
      for (const entry of tables.exports) {
        if (!match(entry.name)) continue;
        count("exports");
        hits.push({
          plane: "exports",
          offset: entry.nameOffset,
          value: entry.name,
          preview: entry.name,
          ordinal: entry.ordinal,
          va: entry.va === null ? null : hex(entry.va),
        });
      }
    }
  }

  // ---- resources plane -------------------------------------------------------
  if (wanted.includes("resources") && tables !== null) {
    consulted.push("resources");
    try {
      const resources = await parsePeResources(workspace, userPath);
      if (resources.versionInfo !== null) {
        for (const [key, value] of Object.entries(resources.versionInfo.strings)) {
          if (!match(key) && !match(value)) continue;
          count("resources");
          hits.push({ plane: "resources", offset: null, key, value: capText(value, VALUE_PREVIEW_CHARS), preview: capText(value, VALUE_PREVIEW_CHARS) });
        }
      }
      if (resources.manifestPreview !== null) {
        for (const line of resources.manifestPreview.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (trimmed === "" || !match(trimmed)) continue;
          count("resources");
          hits.push({ plane: "resources", offset: null, key: "manifest", value: capText(trimmed, 200), preview: capText(trimmed, 200) });
        }
      }
    } catch (error) {
      skipped.push({ plane: "resources", reason: `resource parse failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }

  // ---- symbols plane ----------------------------------------------------------
  if (wanted.includes("symbols") && functions !== null) {
    consulted.push("symbols");
    for (const fn of functions) {
      const name = typeof fn.name === "string" ? fn.name : "";
      if (name === "" || !match(name)) continue;
      count("symbols");
      hits.push({
        plane: "symbols",
        offset: null,
        value: name,
        preview: typeof fn.signature === "string" && fn.signature !== "" ? capText(fn.signature, 200) : name,
        va: typeof fn.offset === "number" ? hex(fn.offset) : null,
      });
    }
  }

  // ---- cross-plane enrichment: section, RVA/VA, containing function ----------
  // The agent's symbol map (annotate.symbol) resolves VAs the agent already
  // understands, so renames compound across every subsequent find.
  let symbolIndex: Map<number, SymbolEntry> | null = null;
  if (tables !== null && hits.some((hit) => hit.offset !== null)) {
    symbolIndex = await loadSymbolIndex(workspace, binary.sampleId);
  }
  for (const hit of hits) {
    if (hit.offset === null || tables === null || hit.plane === "symbols") continue;
    const section = sectionForFileOffset(tables.sections, hit.offset);
    const rva = fileOffsetToRva(tables.sections, hit.offset);
    hit.section = section === null ? null : section.name;
    hit.rva = rva;
    if (rva !== null) {
      const va = tables.imageBase + rva;
      hit.va = hex(va);
      hit.function = functionForVa(functions, va);
      const symbol = symbolIndex === null ? null : lookupSymbol(symbolIndex, va);
      if (symbol !== null) {
        hit.symbol = symbol.name;
        hit.symbolComment = symbol.comment ?? null;
      }
    }
  }

  hits.sort((left, right) => {
    const leftOffset = left.offset ?? Number.MAX_SAFE_INTEGER;
    const rightOffset = right.offset ?? Number.MAX_SAFE_INTEGER;
    return leftOffset - rightOffset;
  });

  const totalMatched = Object.values(planeCounts).reduce((sum, value) => sum + value, 0);
  const bounded = hits.slice(0, maxHits);

  const next: string[] = [];
  if (scannedBytes < fileStats.size) {
    next.push(`scan covered the first ${scannedBytes} of ${fileStats.size} bytes; raise maxScanBytes (default ${FIND_DEFAULT_SCAN_BYTES}, no ceiling) to scan further, or use binary_search which streams the whole file regardless of size`);
  }
  if (totalMatched > maxHits) {
    next.push(`${totalMatched} matches found; showing the first ${maxHits} — raise maxHits (cap ${FIND_MAX_HITS_CAP}) for more`);
  }
  const withVa = bounded.find((hit) => hit.va !== null && hit.va !== undefined);
  if (withVa !== undefined && withVa.va !== undefined && withVa.va !== null) {
    next.push(`inspect code around the first hit with disassembly_dump (address ${withVa.va})`);
  }
  if (functions === null && tables !== null && wanted.includes("symbols")) {
    next.push("run disassembly_functions once to populate the symbols plane and attach containing-function context to every hit");
  }
  if (bounded.length === 0) {
    if (kind === "string" || kind === "regex") {
      next.push("no static hits: try strings_extract_deep (FLOSS emulates decoders to recover obfuscated strings), or dumps.floss over an unpacked dump");
    }
    if (kind === "api") {
      next.push("no static API hits: imports may be resolved dynamically at runtime — probe with dynamic.frida or inspect an unpacked dump");
    }
  }

  return {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    format: { kind: binary.format.kind, architecture: binary.format.architecture, bits: binary.format.bits },
    needle: options.needle,
    kind,
    caseSensitive,
    hits: bounded,
    hitCount: bounded.length,
    truncated: totalMatched > maxHits,
    planeCounts,
    planes: { consulted, skipped },
    scan: { scannedBytes, fileSize: fileStats.size, truncated: scannedBytes < fileStats.size },
    notes,
    next,
  };
}
