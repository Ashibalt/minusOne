/**
 * batch.survey — the object-map plane. ONE command produces the complete
 * structural table of a binary (or several, batched) as JSON: sections,
 * imports, exports, entrypoint, resource/version summary, annotated symbols,
 * and — when a cached r2 function listing exists — the function table with
 * annotated names. This is the pain-file item verbatim: "было бы великолепно
 * через одну команду получить json одного или нескольких файлов всю таблицу,
 * не тратя часы на ручной просмотр всего."
 *
 * All planes degrade to empty-with-note, never null (dsh validates outputs).
 * The full JSON is always stored as an artifact for paging; the inline
 * summary is bounded so the model's context survives.
 */
import { cacheKeyDigest, findArtifactByCacheKey, readArtifactFull, storeArtifact } from "./artifacts.js";
import { inspectBinary } from "./binary.js";
import { parsePeTablesFromPath, type PeTables } from "./peimports.js";
import { parsePeResources } from "./peresources.js";
import { readSymbolMap } from "./symbols.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export const SURVEY_INLINE_FUNCTIONS = 120;
export const SURVEY_INLINE_IMPORTS = 200;
export const SURVEY_INLINE_EXPORTS = 200;
export const SURVEY_INLINE_SYMBOLS = 120;
export const SURVEY_MAX_PATHS = 8;

interface RadareFunction {
  offset?: number;
  name?: string;
  size?: number;
  realsz?: number;
  nbbs?: number;
}

export interface SurveySectionRow {
  name: string;
  virtualSize: number;
  rawSize: number;
  va: string;
  rva: string;
  fileOffset: string;
  entropyHint: string;
  executable: boolean;
  writable: boolean;
}

export interface SurveyFileReport {
  path: string;
  sampleId: string;
  sha256: string;
  size: number;
  format: { kind: string; architecture: string; bits: number | null };
  pe: {
    available: boolean;
    imageBase: string | null;
    entrypointRva: string | null;
    entrypointVa: string | null;
    isDll: boolean;
    sections: SurveySectionRow[];
    imports: { dllCount: number; functions: Array<{ dll: string; name: string; iatVa: string }>; functionCount: number; truncated: boolean };
    exports: { count: number; names: Array<{ name: string; ordinal: number; va: string | null }>; truncated: boolean };
    notes: string[];
  };
  resources: { available: boolean; types: Array<{ typeName: string | null; entryCount: number }>; versionInfo: Record<string, string> | null; note: string | null };
  symbols: { count: number; entries: Array<{ va: string; name: string; comment: string | null }>; truncated: boolean };
  functions: {
    available: boolean;
    backend: string | null;
    count: number;
    entries: Array<{ name: string; va: string; size: number | null; blocks: number | null }>;
    truncated: boolean;
    note: string | null;
  };
  fullTable: { artifactId: string; bytes: number; pageWith: string };
}

export interface SurveyResult {
  files: SurveyFileReport[];
  fileCount: number;
  notes: string[];
  next: string[];
  command: CommandResult | null;
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

async function loadCachedFunctions(workspace: Workspace, sampleId: string): Promise<{ functions: RadareFunction[] | null; note: string | null }> {
  try {
    const cacheKey = cacheKeyDigest({
      sample: sampleId,
      operation: "disassembly.functions",
      image: process.env.MINUSONE_R2_IMAGE ?? "radare2-default",
      local: process.env.MINUSONE_R2_BIN ?? null,
      schema: 1,
    });
    const artifact = await findArtifactByCacheKey(workspace, cacheKey);
    if (artifact === null) return { functions: null, note: null };
    const parsed = JSON.parse(await readArtifactFull(workspace, artifact.id)) as RadareFunction[];
    if (!Array.isArray(parsed)) return { functions: null, note: null };
    return { functions: parsed, note: null };
  } catch {
    return { functions: null, note: null };
  }
}

function entropyHint(name: string, rawSize: number, virtualSize: number): string {
  // Name-based hints only: real per-section entropy requires a full read,
  // which survey avoids on principle (fast structural pass).
  const packed = /^(upx\d?|\.aspack|\.adata|themida|vmp\d?|petite|\.nsp\d|pebundle)$/i;
  if (packed.test(name)) return "packer-named section";
  if (rawSize === 0 && virtualSize > 0) return "virtual-only (BSS-like)";
  return "normal";
}

export async function surveyBinaries(workspace: Workspace, paths: string[]): Promise<SurveyResult> {
  if (paths.length === 0) throw new Error("pass at least one path");
  if (paths.length > SURVEY_MAX_PATHS) throw new Error(`batch survey caps at ${SURVEY_MAX_PATHS} files per call (got ${paths.length}) — split the batch`);

  const notes: string[] = [];
  const files: SurveyFileReport[] = [];

  for (const userPath of paths) {
    const absolutePath = await workspace.resolveFile(userPath);
    const binary = await inspectBinary(workspace, userPath);
    const tables: PeTables | null = await parsePeTablesFromPath(absolutePath);

    const peSections: SurveySectionRow[] = [];
    const imports: Array<{ dll: string; name: string; iatVa: string }> = [];
    const exportsList: Array<{ name: string; ordinal: number; va: string | null }> = [];
    const peNotes: string[] = [];
    let imageBase: string | null = null;
    let entrypointRva: string | null = null;
    let entrypointVa: string | null = null;
    let isDll = false;

    if (tables === null) {
      peNotes.push(`${userPath} is not a parsable PE image — section/import/export tables skipped (native ELF/Mach-O tables not implemented)`);
    } else {
      imageBase = hex(tables.imageBase);
      entrypointRva = tables.entrypointRva === null ? null : hex(tables.entrypointRva);
      entrypointVa = tables.entrypointRva === null ? null : hex(tables.imageBase + tables.entrypointRva);
      isDll = (tables.characteristics & 0x2000) !== 0;
      for (const section of tables.sections) {
        peSections.push({
          name: section.name,
          virtualSize: section.virtualSize,
          rawSize: section.rawSize,
          va: hex(tables.imageBase + section.virtualAddress),
          rva: hex(section.virtualAddress),
          fileOffset: hex(section.pointerToRawData),
          entropyHint: entropyHint(section.name, section.rawSize, section.virtualSize),
          executable: (section.characteristics & 0x2000_0000) !== 0,
          writable: (section.characteristics & 0x8000_0000) !== 0,
        });
      }
      for (const entry of tables.imports.slice(0, SURVEY_INLINE_IMPORTS)) {
        imports.push({ dll: entry.dll, name: entry.name, iatVa: hex(entry.iatVa) });
      }
      for (const entry of tables.exports.slice(0, SURVEY_INLINE_EXPORTS)) {
        exportsList.push({ name: entry.name, ordinal: entry.ordinal, va: entry.va === null ? null : hex(entry.va) });
      }
      if (tables.imports.length > imports.length) peNotes.push(`imports truncated inline (${imports.length}/${tables.imports.length}) — full table in the artifact`);
      if (tables.imports.length === 0) peNotes.push("no imports resolved — IAT may be destroyed (packed) or the file is not a standard PE");
      if (tables.exports.length > exportsList.length) peNotes.push(`exports truncated inline (${exportsList.length}/${tables.exports.length})`);
      peNotes.push(...tables.partial);
    }

    let resources: SurveyFileReport["resources"] = {
      available: false,
      types: [],
      versionInfo: null,
      note: "resource parsing skipped (non-PE or resource plane unavailable)",
    };
    try {
      const report = await parsePeResources(workspace, userPath);
      resources = {
        available: true,
        types: report.types.map((type) => ({ typeName: type.typeName, entryCount: type.entryCount })),
        versionInfo: report.versionInfo === null ? null : report.versionInfo.strings,
        note: null,
      };
    } catch {
      resources = { available: false, types: [], versionInfo: null, note: "resource plane degraded for this file" };
    }

    const symbolEntries = await readSymbolMap(workspace, binary.sampleId);
    const symbolInline = symbolEntries.slice(0, SURVEY_INLINE_SYMBOLS);

    const cached = await loadCachedFunctions(workspace, binary.sampleId);
    const functionEntries = (cached.functions ?? []).slice(0, SURVEY_INLINE_FUNCTIONS).map((fn) => ({
      name: fn.name ?? "",
      va: typeof fn.offset === "number" ? hex(fn.offset) : "",
      size: typeof fn.realsz === "number" ? fn.realsz : typeof fn.size === "number" ? fn.size : null,
      blocks: typeof fn.nbbs === "number" ? fn.nbbs : null,
    }));

    const fileReport: SurveyFileReport = {
      path: binary.path,
      sampleId: binary.sampleId,
      sha256: binary.sha256,
      size: binary.size,
      format: { kind: binary.format.kind, architecture: binary.format.architecture, bits: binary.format.bits },
      pe: {
        available: tables !== null,
        imageBase,
        entrypointRva,
        entrypointVa,
        isDll,
        sections: peSections,
        imports: { dllCount: tables?.importDlls.length ?? 0, functions: imports, functionCount: tables?.imports.length ?? 0, truncated: (tables?.imports.length ?? 0) > imports.length },
        exports: { count: tables?.exports.length ?? 0, names: exportsList, truncated: (tables?.exports.length ?? 0) > exportsList.length },
        notes: peNotes,
      },
      resources,
      symbols: { count: symbolEntries.length, entries: symbolInline.map((entry) => ({ va: entry.va, name: entry.name, comment: entry.comment ?? null })), truncated: symbolEntries.length > symbolInline.length },
      functions: {
        available: cached.functions !== null,
        backend: cached.functions === null ? null : "radare2 (cached listing)",
        count: cached.functions?.length ?? 0,
        entries: functionEntries,
        truncated: (cached.functions?.length ?? 0) > functionEntries.length,
        note: cached.functions === null ? "no cached r2 function listing — run disassembly_functions once, then re-survey to merge the function table" : null,
      },
      fullTable: { artifactId: "", bytes: 0, pageWith: "artifact_read" },
    };

    // Full table artifact: everything untruncated.
    const fullPayload = JSON.stringify(
      {
        path: fileReport.path,
        sampleId: fileReport.sampleId,
        sha256: fileReport.sha256,
        format: fileReport.format,
        pe: {
          imageBase,
          entrypointRva,
          entrypointVa,
          isDll,
          sections: peSections,
          imports: (tables?.imports ?? []).map((entry) => ({ dll: entry.dll, name: entry.name, ordinal: entry.ordinal, iatVa: hex(entry.iatVa), nameOffset: entry.nameOffset })),
          exports: (tables?.exports ?? []).map((entry) => ({ name: entry.name, ordinal: entry.ordinal, va: entry.va === null ? null : hex(entry.va) })),
          notes: peNotes,
        },
        resources,
        symbols: symbolEntries,
        functions: cached.functions ?? [],
      },
      null,
      2,
    );
    const artifact = await storeArtifact(workspace, fullPayload, {
      mediaType: "application/json",
      sourceOperation: "batch.survey",
      description: `full structural table of ${binary.path}`,
      sampleId: binary.sampleId,
    });
    fileReport.fullTable = { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" };
    files.push(fileReport);
  }

  const anyFunctions = files.some((file) => file.functions.available);
  const next: string[] = [];
  if (anyFunctions) {
    next.push("memory_read (va from the tables above) turns any row into bytes/decoded values — no manual VA→offset math");
  } else {
    next.push("disassembly_functions first populates the function table; re-run batch_survey to merge it");
  }
  next.push("binary_explain (needle) adds xrefs + decompilation context around any string/address in these tables");
  if (files.some((file) => file.symbols.count > 0)) {
    next.push("annotate_symbol adds/edits names in the symbol plane; batch_survey reflects them on every later run");
  }

  return {
    files,
    fileCount: files.length,
    notes,
    next,
    command: null,
  };
}
