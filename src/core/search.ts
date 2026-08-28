/**
 * binary.search — streaming whole-file search. binary.find is the fast
 * bounded fan-out over multiple planes; this is the exhaustive pass that
 * NEVER stops at a byte ceiling: the file is streamed in chunks with a
 * needle-length overlap so matches spanning chunk boundaries are caught.
 * ASCII + UTF-16LE (string), raw hex bytes, or regex. Every hit carries
 * its file offset plus PE section/RVA/VA context from random-access table
 * parsing — so a hit deep in a 437MB image still says ".rdata @ VA
 * 0x1408abcde". Resumable: startOffset/endOffset bound the window and a
 * truncated run tells the agent exactly where to resume.
 *
 * Chunk discipline: every chunk is searched in full; matches are deduped
 * by absolute start offset (the previous chunk's tail is re-read, so a
 * boundary-spanning match is found twice and reported once). Regex matches
 * that reach the chunk edge are deferred to the next chunk, which sees
 * them complete — matches longer than the 64KB regex overlap may be cut
 * or missed (documented; fixed-length needles never are).
 */
import { open, stat } from "node:fs/promises";
import { inspectBinary } from "./binary.js";
import { fileOffsetToRva, parsePeTablesFromPath, sectionForFileOffset } from "./peimports.js";
import type { PeTables } from "./peimports.js";
import { loadSymbolIndex, lookupSymbol } from "./symbols.js";
import type { SymbolEntry } from "./symbols.js";
import type { Workspace } from "./workspace.js";

export const SEARCH_CHUNK_BYTES = 8 * 1024 * 1024;
export const SEARCH_DEFAULT_MAX_HITS = 100;
export const SEARCH_MAX_HITS_CAP = 5000;
export const SEARCH_MAX_NEEDLE_CHARS = 1024;
export const SEARCH_MAX_HEX_CHARS = 2048;
export const SEARCH_DEFAULT_CONTEXT_BYTES = 32;
export const SEARCH_MAX_CONTEXT_BYTES = 4096;
/** Regex matches longer than the overlap can be cut at a chunk edge. */
export const SEARCH_REGEX_OVERLAP_BYTES = 64 * 1024;
const PREVIEW_CHARS = 256;

export type SearchKind = "string" | "bytes" | "regex";

export interface SearchOptions {
  needle: string;
  kind?: SearchKind;
  caseSensitive?: boolean;
  maxHits?: number;
  /** Encodings to try for kind "string" (default: both). */
  encodings?: Array<"ascii" | "utf16le">;
  startOffset?: number;
  endOffset?: number;
  contextBytes?: number;
  signal?: AbortSignal;
}

export interface SearchHit {
  offset: number;
  encoding: "ascii" | "utf16le" | "hex" | "regex";
  value: string;
  preview: string;
  section?: string | null;
  rva?: number | null;
  va?: string | null;
  /** Agent-assigned name from annotate.symbol for this hit's VA. */
  symbol?: string | null;
  symbolComment?: string | null;
  /** True when a regex match reached the scan-window edge (may extend further). */
  boundary?: boolean;
}

export interface SearchResult {
  path: string;
  sampleId: string;
  sha256: string;
  format: { kind: string; architecture: string; bits: number | null };
  needle: string;
  kind: SearchKind;
  caseSensitive: boolean;
  hits: SearchHit[];
  hitCount: number;
  truncated: boolean;
  scannedFrom: number;
  scannedBytes: number;
  fileSize: number;
  scanComplete: boolean;
  durationMs: number;
  notes: string[];
  next: string[];
}

/** ASCII-only case folding so byte offsets survive the lowercase pass. */
function foldAscii(text: string): string {
  return text.replace(/[A-Z]/g, (char) => String.fromCharCode(char.charCodeAt(0) + 32));
}

function printableWindow(buffer: Buffer, offset: number, length: number, contextBytes: number): string {
  const start = Math.max(0, offset - contextBytes);
  const end = Math.min(buffer.length, offset + length + contextBytes);
  let out = "";
  for (let index = start; index < end; index += 1) {
    const byte = buffer[index] ?? 0;
    out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
  }
  return out.length <= PREVIEW_CHARS ? out : `${out.slice(0, PREVIEW_CHARS)}...`;
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

export async function searchBinary(workspace: Workspace, userPath: string, options: SearchOptions): Promise<SearchResult> {
  const startedAt = Date.now();
  const kind: SearchKind = options.kind ?? "string";
  const caseSensitive = options.caseSensitive === true;
  const maxHits = Math.min(SEARCH_MAX_HITS_CAP, Math.max(1, Math.floor(options.maxHits ?? SEARCH_DEFAULT_MAX_HITS)));
  const contextBytes = Math.min(SEARCH_MAX_CONTEXT_BYTES, Math.max(0, Math.floor(options.contextBytes ?? SEARCH_DEFAULT_CONTEXT_BYTES)));
  const encodings: Array<"ascii" | "utf16le"> = kind === "string"
    ? (options.encodings !== undefined && options.encodings.length > 0 ? options.encodings : ["ascii", "utf16le"])
    : [];

  let regex: RegExp | null = null;
  let hexNeedle: Buffer | null = null;
  if (kind === "regex") {
    if (options.needle.length < 1 || options.needle.length > SEARCH_MAX_NEEDLE_CHARS) {
      throw new Error(`regex needle must be 1-${SEARCH_MAX_NEEDLE_CHARS} characters`);
    }
    try {
      regex = new RegExp(options.needle, caseSensitive ? "g" : "gi");
    } catch (error) {
      throw new Error(`invalid regular expression: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else if (kind === "bytes") {
    if (!/^[0-9a-fA-F]+$/.test(options.needle) || options.needle.length % 2 !== 0) {
      throw new Error(`bytes needle must be non-empty even-length hex (e.g. "4d5a"), got ${JSON.stringify(options.needle.slice(0, 64))}`);
    }
    if (options.needle.length > SEARCH_MAX_HEX_CHARS) {
      throw new Error(`bytes needle is too long (${options.needle.length / 2} bytes; cap ${SEARCH_MAX_HEX_CHARS / 2})`);
    }
    hexNeedle = Buffer.from(options.needle, "hex");
  } else {
    if (options.needle.length < 1 || options.needle.length > SEARCH_MAX_NEEDLE_CHARS) {
      throw new Error(`needle must be 1-${SEARCH_MAX_NEEDLE_CHARS} characters`);
    }
  }

  const binary = await inspectBinary(workspace, userPath);
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const fileSize = fileStats.size;

  const startOffset = Math.max(0, Math.floor(options.startOffset ?? 0));
  const endOffset = Math.min(fileSize, Math.floor(options.endOffset ?? fileSize));
  if (startOffset >= endOffset) {
    throw new Error(`search window is empty: startOffset ${startOffset} >= endOffset ${endOffset} (file is ${fileSize} bytes)`);
  }

  // Fixed-length needles: overlap = longest needle - 1 guarantees every
  // boundary-spanning match starts inside some chunk's buffer.
  const patterns: Array<{ label: "ascii" | "utf16le" | "hex"; text: string; length: number }> = [];
  if (hexNeedle !== null) {
    patterns.push({ label: "hex", text: hexNeedle.toString("latin1"), length: hexNeedle.length });
  } else if (kind === "string") {
    if (encodings.includes("ascii")) {
      patterns.push({ label: "ascii", text: options.needle, length: Buffer.byteLength(options.needle, "ascii") });
    }
    if (encodings.includes("utf16le")) {
      const utf16 = Buffer.from(options.needle, "utf16le").toString("latin1");
      if (!patterns.some((entry) => entry.text === utf16)) {
        patterns.push({ label: "utf16le", text: utf16, length: utf16.length });
      }
    }
  }
  const longestPattern = patterns.reduce((max, entry) => Math.max(max, entry.length), 0);
  const overlap = kind === "regex" ? SEARCH_REGEX_OVERLAP_BYTES : Math.max(longestPattern - 1, 0);

  // PE context comes from random-access table parsing: complete even when
  // the hit lies far beyond any read-ahead window.
  const tables: PeTables | null = binary.format.kind === "pe" ? await parsePeTablesFromPath(absolutePath) : null;

  const hits: SearchHit[] = [];
  const notes: string[] = [];
  const reportedOffsets = new Set<number>();
  let truncated = false;
  let lastScanned = startOffset;

  const handle = await open(absolutePath, "r");
  try {
    let position = startOffset;
    while (position < endOffset) {
      if (options.signal?.aborted) throw new Error("search aborted");
      // Fixed chunk budget (never the whole remaining file): latin1 strings
      // beyond ~256MB crash V8, and Buffer.indexOf is faster anyway for
      // fixed needles. The overlap tail guarantees boundary-spanning finds.
      const want = Math.min(SEARCH_CHUNK_BYTES + overlap, endOffset - position);
      const isLast = want < SEARCH_CHUNK_BYTES + overlap || position + want >= endOffset;
      const buffer = Buffer.alloc(SEARCH_CHUNK_BYTES + overlap);
      const { bytesRead } = await handle.read(buffer, 0, want, position);
      const chunk = bytesRead === want ? buffer.subarray(0, want) : buffer.subarray(0, bytesRead);
      if (chunk.length === 0) break;

      const report = (index: number, length: number, encoding: SearchHit["encoding"], value: string, boundary: boolean): void => {
        const absolute = position + index;
        if (reportedOffsets.has(absolute)) return;
        reportedOffsets.add(absolute);
        if (hits.length >= maxHits) {
          truncated = true;
          return;
        }
        hits.push({
          offset: absolute,
          encoding,
          value,
          preview: printableWindow(chunk, index, length, contextBytes),
          ...(boundary ? { boundary: true } : {}),
        });
      };

      if (regex !== null) {
        // Regex needs a string; the chunk is bounded (8MB + overlap), far
        // below the V8 one-byte-string limit that killed whole-file reads.
        const text = chunk.toString("latin1");
        const haystack = caseSensitive ? text : foldAscii(text);
        regex.lastIndex = 0;
        for (let match = regex.exec(haystack); match !== null; match = regex.exec(haystack)) {
          const index = match.index;
          const matched = match[0];
          if (matched.length === 0) {
            regex.lastIndex += 1;
            continue;
          }
          const atEdge = index + matched.length >= chunk.length;
          // Edge-reaching matches are deferred: the next chunk re-reads the
          // overlap and sees them complete. Only the final chunk reports
          // them (marked boundary).
          if (atEdge && !isLast) continue;
          report(index, matched.length, "regex", matched.length <= PREVIEW_CHARS ? matched : `${matched.slice(0, PREVIEW_CHARS)}...`, atEdge);
          if (truncated) break;
        }
      } else {
        // Fixed needles search the Buffer directly — byte-exact, no string
        // conversion, no case-folding pass over the haystack. Case folding
        // is applied to a needle-sized copy; the haystack is folded through
        // a bounded window only when insensitive.
        for (const pattern of patterns) {
          const needleBuffer = Buffer.from(pattern.text, "latin1");
          if (caseSensitive || pattern.label === "hex") {
            let index = chunk.indexOf(needleBuffer);
            while (index !== -1) {
              report(index, pattern.length, pattern.label, pattern.label === "hex" ? `hex:${options.needle}` : options.needle, false);
              if (truncated) break;
              index = chunk.indexOf(needleBuffer, index + 1);
            }
          } else {
            // Insensitive: fold the chunk once per chunk (bounded size).
            const foldedChunk = Buffer.from(chunk);
            for (let index = 0; index < foldedChunk.length; index += 1) {
              const byte = foldedChunk[index] ?? 0;
              if (byte >= 0x41 && byte <= 0x5a) foldedChunk[index] = byte + 32;
            }
            const foldedNeedle = Buffer.from(foldAscii(pattern.text), "latin1");
            let index = foldedChunk.indexOf(foldedNeedle);
            while (index !== -1) {
              report(index, pattern.length, pattern.label, options.needle, false);
              if (truncated) break;
              index = foldedChunk.indexOf(foldedNeedle, index + 1);
            }
          }
          if (truncated) break;
        }
      }

      lastScanned = position + chunk.length;
      if (truncated || isLast) break;
      // Advance by the fresh window; the overlap tail is re-read next round.
      position += Math.min(SEARCH_CHUNK_BYTES, Math.max(1, chunk.length - overlap));
    }
  } finally {
    await handle.close();
  }

  // PE enrichment: section, RVA, VA for every hit; the agent's symbol map
  // (annotate.symbol) resolves VAs it already named.
  if (tables !== null) {
    const symbolIndex = hits.length > 0 ? await loadSymbolIndex(workspace, binary.sampleId) : null;
    for (const hit of hits) {
      const section = sectionForFileOffset(tables.sections, hit.offset);
      const rva = fileOffsetToRva(tables.sections, hit.offset);
      hit.section = section === null ? null : section.name;
      hit.rva = rva;
      if (rva !== null) {
        const va = tables.imageBase + rva;
        hit.va = hex(va);
        const symbol = symbolIndex === null ? null : lookupSymbol(symbolIndex, va);
        if (symbol !== null) {
          hit.symbol = symbol.name;
          hit.symbolComment = symbol.comment ?? null;
        }
      }
    }
    if (tables.partial.length > 0) notes.push(...tables.partial);
  }

  const scannedBytes = lastScanned - startOffset;
  const scanComplete = lastScanned >= endOffset && !truncated;
  const next: string[] = [];
  if (truncated) {
    if (lastScanned >= endOffset) {
      next.push(`hit cap (${maxHits}) reached and the whole window was already scanned; raise maxHits (cap ${SEARCH_MAX_HITS_CAP}) or narrow the needle`);
    } else {
      next.push(`hit cap (${maxHits}) reached after ${scannedBytes} bytes; resume with startOffset: ${lastScanned} or raise maxHits (cap ${SEARCH_MAX_HITS_CAP})`);
    }
  }
  if (!scanComplete && !truncated) {
    next.push(`scan stopped at ${lastScanned} of ${endOffset} bytes; resume with startOffset: ${lastScanned}`);
  }
  if (hits.length > 0) {
    const withVa = hits.find((hit) => hit.va !== null && hit.va !== undefined);
    if (withVa !== undefined && withVa.va !== undefined && withVa.va !== null) {
      next.push("binary_explain (same needle) traces who references these hits: xrefs + decompiled functions");
    }
  } else if (scanComplete) {
    next.push("whole file scanned, no matches — try strings_extract_deep (FLOSS recovers obfuscated strings) or a wider regex");
  }

  return {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    format: { kind: binary.format.kind, architecture: binary.format.architecture, bits: binary.format.bits },
    needle: options.needle,
    kind,
    caseSensitive,
    hits,
    hitCount: hits.length,
    truncated,
    scannedFrom: startOffset,
    scannedBytes,
    fileSize,
    scanComplete,
    durationMs: Date.now() - startedAt,
    notes,
    next,
  };
}
