/**
 * binary.diff — patch analysis between two versions of a binary ("what
 * changed in the update" / "where does the cracked build differ"). Two
 * layers: byte-level (run-length diff of differing regions, sha256 per
 * region, cheap) and function-level (align PE sections, compare each
 * section's changed regions against the section table so the report says
 * ".text changed at RVA 0x140001234" instead of a raw file offset). The
 * optional deep pass hands the changed regions to the decompiler (Ghidra
 * references-free targeted decompile) so the agent sees the code that
 * actually differs. Same-size binaries with few regions = classic patch
 * diff; wildly different sizes = rebuild, reported honestly as such.
 */
import { createHash } from "node:crypto";
import { open, stat } from "node:fs/promises";
import { inspectBinary } from "./binary.js";
import { fileOffsetToRva, parsePeTables } from "./peimports.js";
import { runGhidraAnalysis } from "./ghidra.js";
import { loadSymbolIndex, lookupSymbol } from "./symbols.js";
import type { Workspace } from "./workspace.js";

export const DIFF_MAX_REGIONS = 512;
export const DIFF_REGION_CONTEXT_BYTES = 0;
export const DIFF_MAX_DECOMPILES = 4;
/** Regions smaller than this are merged with neighbors (patch noise). */
const DIFF_MERGE_GAP_BYTES = 8;

export interface DiffOptions {
  /** Old/original version (the baseline). */
  oldPath: string;
  /** New/modified version. */
  newPath: string;
  /** Decompile the top changed regions with Ghidra (default true). */
  decompile?: boolean;
  maxDecompiles?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface DiffRegion {
  /** File offset where the region starts (in BOTH files when aligned). */
  offset: number;
  /** Region length in bytes. */
  length: number;
  /** File offset of the same region in the new file (equal when aligned). */
  newOffset: number;
  /** True when the region exists only in one file (size mismatch). */
  unaligned: boolean;
  oldSha256: string;
  newSha256: string;
  /** PE context from the OLD file (section, RVA, VA) when available. */
  section: string | null;
  rva: number | null;
  va: string | null;
  symbol: string | null;
  oldPreview: string;
  newPreview: string;
}

export interface DiffResult {
  oldPath: string;
  newPath: string;
  oldSha256: string;
  newSha256: string;
  oldSize: number;
  newSize: number;
  identical: boolean;
  /** Same-size PE images compared in place (clean patch diff semantics). */
  aligned: boolean;
  changedByteCount: number;
  changedRatio: number;
  regions: DiffRegion[];
  regionCount: number;
  /** True when the sizes differ so much this is a rebuild, not a patch. */
  looksLikeRebuild: boolean;
  /** Changed functions decompiled (deep pass), bounded. */
  decompilations: Array<{ va: string; name: string | null; pseudocodePreview: string | null; error?: string }>;
  notes: string[];
  next: string[];
}

async function sha256Range(handle: Awaited<ReturnType<typeof open>>, offset: number, length: number): Promise<string> {
  const buffer = Buffer.alloc(length);
  await handle.read(buffer, 0, length, offset);
  return createHash("sha256").update(buffer).digest("hex");
}

function preview(buffer: Buffer): string {
  let out = "";
  const end = Math.min(buffer.length, 32);
  for (let index = 0; index < end; index += 1) {
    const byte = buffer[index] ?? 0;
    out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
  }
  return out;
}

async function readRange(handle: Awaited<ReturnType<typeof open>>, offset: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  await handle.read(buffer, 0, length, offset);
  return buffer;
}

export async function diffBinaries(
  workspace: Workspace,
  options: DiffOptions,
): Promise<DiffResult> {
  const oldAbsolute = await workspace.resolveFile(options.oldPath);
  const newAbsolute = await workspace.resolveFile(options.newPath);
  const oldBinary = await inspectBinary(workspace, options.oldPath);
  const newBinary = await inspectBinary(workspace, options.newPath);
  const oldStats = await stat(oldAbsolute);
  const newStats = await stat(newAbsolute);
  const notes: string[] = [];
  const next: string[] = [];

  const identical = oldBinary.sha256 === newBinary.sha256;
  const aligned = oldStats.size === newStats.size;
  const changedByteCount = identical ? 0 : -1;

  const result: DiffResult = {
    oldPath: oldBinary.path,
    newPath: newBinary.path,
    oldSha256: oldBinary.sha256,
    newSha256: newBinary.sha256,
    oldSize: oldStats.size,
    newSize: newStats.size,
    identical,
    aligned,
    changedByteCount,
    changedRatio: 0,
    regions: [],
    regionCount: 0,
    looksLikeRebuild: !aligned && Math.abs(oldStats.size - newStats.size) / Math.max(oldStats.size, 1) > 0.1,
    decompilations: [],
    notes,
    next,
  };
  if (identical) {
    notes.push("the files are byte-identical");
    return result;
  }
  if (!aligned) {
    notes.push(`size mismatch (${oldStats.size} vs ${newStats.size} bytes): regions are computed over the common prefix; the tail of the longer file is one region`);
  }
  if (result.looksLikeRebuild) {
    notes.push("sizes differ by more than 10% — this looks like a REBUILD, not a patch; per-function comparison is unreliable, consider analyzing each version separately");
    next.push("for rebuilds: run binary_triage on both versions and compare the verdicts/imports instead of byte diffing");
  }

  // ---- byte-level diff over the common prefix --------------------------------
  const oldHandle = await open(oldAbsolute, "r");
  const newHandle = await open(newAbsolute, "r");
  try {
    const common = Math.min(oldStats.size, newStats.size);
    const chunkSize = 8 * 1024 * 1024;
    let position = 0;
    let changed = 0;
    const rawRegions: Array<{ start: number; length: number }> = [];
    let openRegion: { start: number; length: number } | null = null;

    while (position < common) {
      const want = Math.min(chunkSize, common - position);
      const oldChunk = await readRange(oldHandle, position, want);
      const newChunk = await readRange(newHandle, position, want);
      for (let index = 0; index < want; index += 1) {
        const differs = oldChunk[index] !== newChunk[index];
        if (differs) {
          changed += 1;
          if (openRegion === null) {
            openRegion = { start: position + index, length: 1 };
          } else {
            openRegion.length += 1;
          }
        } else if (openRegion !== null && position + index - (openRegion.start + openRegion.length) >= DIFF_MERGE_GAP_BYTES) {
          rawRegions.push(openRegion);
          openRegion = null;
        }
      }
      position += want;
    }
    if (openRegion !== null) rawRegions.push(openRegion);
    // The tail of the longer file (if any) is one final region.
    if (common < Math.max(oldStats.size, newStats.size)) {
      rawRegions.push({ start: common, length: Math.max(oldStats.size, newStats.size) - common });
    }

    result.changedByteCount = changed + Math.abs(oldStats.size - newStats.size);
    result.changedRatio = result.changedByteCount / Math.max(oldStats.size, newStats.size);

    // ---- PE context from the OLD file's tables -------------------------------
    const oldTables = oldBinary.format.kind === "pe" ? await parsePeTables(workspace, options.oldPath) : null;
    const symbolIndex = oldTables !== null ? await loadSymbolIndex(workspace, oldBinary.sampleId) : null;

    const bounded = rawRegions.slice(0, DIFF_MAX_REGIONS);
    for (const region of bounded) {
      const oldBuffer = await readRange(oldHandle, region.start, region.length).catch(() => Buffer.alloc(0));
      const newBuffer = await readRange(newHandle, region.start, region.length).catch(() => Buffer.alloc(0));
      const section = oldTables !== null ? oldTables.sections.find((entry) => region.start >= entry.pointerToRawData && region.start < entry.pointerToRawData + entry.rawSize) ?? null : null;
      const rva = oldTables !== null ? fileOffsetToRva(oldTables.sections, region.start) : null;
      const va = oldTables !== null && rva !== null ? `0x${(oldTables.imageBase + rva).toString(16)}` : null;
      const symbol = oldTables !== null && rva !== null && va !== null && symbolIndex !== null
        ? lookupSymbol(symbolIndex, oldTables.imageBase + rva)?.name ?? null
        : null;
      result.regions.push({
        offset: region.start,
        length: region.length,
        newOffset: region.start,
        unaligned: false,
        oldSha256: createHash("sha256").update(oldBuffer).digest("hex"),
        newSha256: createHash("sha256").update(newBuffer).digest("hex"),
        section: section === null ? null : section.name,
        rva,
        va,
        symbol,
        oldPreview: preview(oldBuffer),
        newPreview: preview(newBuffer),
      });
    }
    result.regionCount = rawRegions.length;
    if (rawRegions.length > DIFF_MAX_REGIONS) {
      notes.push(`${rawRegions.length} changed regions found; showing the first ${DIFF_MAX_REGIONS}`);
    }
  } finally {
    await oldHandle.close();
    await newHandle.close();
  }

  // ---- deep pass: decompile around the top changed regions -------------------
  const maxDecompiles = Math.min(DIFF_MAX_DECOMPILES, Math.max(0, options.maxDecompiles ?? 3));
  const codeRegions = result.regions.filter((region) => region.va !== null && region.section !== null && /\.(?:text|code)/i.test(region.section ?? ""));
  if (options.decompile !== false && codeRegions.length > 0 && maxDecompiles > 0) {
    try {
      const run = await runGhidraAnalysis(workspace, options.oldPath, {
        addresses: codeRegions.slice(0, maxDecompiles).map((region) => region.va as string),
        maxFunctions: maxDecompiles,
        maxDecompiledChars: 10_000,
        ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: Math.min(options.timeoutSeconds, 900) }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      const functions = (run.report as { functions?: Array<{ name?: string; entryPoint?: string; decompiledCode?: string | null; decompilationError?: string | null }> } | null | undefined)?.functions ?? [];
      for (const fn of functions) {
        result.decompilations.push({
          va: fn.entryPoint ?? "?",
          name: fn.name ?? null,
          pseudocodePreview: typeof fn.decompiledCode === "string" ? fn.decompiledCode.slice(0, 8000) : null,
          ...(fn.decompilationError !== null && fn.decompilationError !== undefined ? { error: fn.decompilationError } : {}),
        });
      }
      if (run.command.exitCode !== 0) {
        notes.push(`Ghidra decompile pass failed (exit ${run.command.exitCode ?? -1}) — byte regions are still valid`);
      }
    } catch (error) {
      notes.push(`Ghidra decompile pass unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (result.regions.length > 0) {
    next.push("annotate_symbol the changed functions (va + name), then binary_explain (old version, needle) to see who calls the changed code");
  }
  if (result.changedRatio > 0.5) {
    notes.push("more than 50% of bytes differ — likely repacked/rewritten; compare triage verdicts instead");
  }

  return result;
}
