/**
 * binary.explain — the "who uses this and what does the code do" combo.
 * One call chains: streaming whole-file search (find the needle's file
 * offset → VA via random-access PE tables) → IDA xrefs (which functions
 * reference that VA; string-literal mode finds every occurrence of the
 * text and their referrers) → Hex-Rays decompilation of the top referring
 * functions. The workflow that previously took the agent 3-5 failing
 * calls (find capped → grep → manual VA math → ida.functions →
 * ida.decompile) becomes one verb. Each stage degrades independently:
 * no IDA → search results with VA context and a "run disassembly_functions"
 * hint; no refs → decompile skipped with the address handed back.
 */
import { runIdaExport, resolveIdat } from "./ida.js";
import { runGhidraAnalysis } from "./ghidra.js";
import { searchBinary } from "./search.js";
import type { SearchHit } from "./search.js";
import { loadSymbolIndex, lookupSymbol, parseVa } from "./symbols.js";
import type { SymbolEntry } from "./symbols.js";
import type { Workspace } from "./workspace.js";

export const EXPLAIN_MAX_DECOMPILES = 4;
export const EXPLAIN_MAX_SEARCH_HITS = 50;

export interface ExplainOptions {
  needle: string;
  kind?: "string" | "bytes" | "regex";
  caseSensitive?: boolean;
  /** Max referring functions to decompile (default 3, cap 4). */
  maxDecompiles?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface ExplainStage {
  stage: "search" | "xrefs" | "decompile";
  status: "ok" | "skipped" | "failed";
  detail?: string;
}

export interface ExplainFunction {
  name: string | null;
  start: string;
  pseudocodePreview: string | null;
  truncated: boolean;
  /** How many of the needle's references sit in this function. */
  references: number;
  error?: string;
}

export interface ExplainResult {
  needle: string;
  kind: "string" | "bytes" | "regex";
  sampleSha256: string | null;
  search: {
    hitCount: number;
    hits: Array<{ offset: number; va: string | null; section: string | null; preview: string; symbol: string | null }>;
    scanComplete: boolean;
  };
  referenceSites: Array<{ address: string; function: string | null; functionStart: string | null; references: number; symbol: string | null }>;
  functions: ExplainFunction[];
  stages: ExplainStage[];
  notes: string[];
  next: string[];
}

interface IdaXrefEntry {
  target?: string;
  kind?: string;
  address?: string;
  error?: string;
  occurrences?: string[];
  xrefs?: Array<{ from?: string; function?: string | null; functionStart?: string | null }>;
}

interface IdaDecompileEntry {
  target?: string;
  name?: string | null;
  start?: string;
  error?: string;
  pseudocode?: string;
  truncated?: boolean;
}

export async function explainNeedle(
  workspace: Workspace,
  userPath: string,
  options: ExplainOptions,
): Promise<ExplainResult> {
  const kind = options.kind ?? "string";
  const maxDecompiles = Math.min(EXPLAIN_MAX_DECOMPILES, Math.max(0, Math.floor(options.maxDecompiles ?? 3)));
  const stages: ExplainStage[] = [];
  const notes: string[] = [];
  const next: string[] = [];

  // ---- stage 1: streaming search for the needle's addresses -----------------
  const search = await searchBinary(workspace, userPath, {
    needle: options.needle,
    kind,
    ...(options.caseSensitive === undefined ? {} : { caseSensitive: options.caseSensitive }),
    maxHits: EXPLAIN_MAX_SEARCH_HITS,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  stages.push({ stage: "search", status: "ok" });

  const vaHits = search.hits.filter((hit) => hit.va !== null && hit.va !== undefined) as Array<SearchHit & { va: string }>;
  // The agent's symbol map (annotate_symbol) resolves hits it already named.
  const symbolIndex = await loadSymbolIndex(workspace, search.sampleId);
  const searchSummary = {
    hitCount: search.hitCount,
    hits: search.hits.slice(0, 10).map((hit) => ({
      offset: hit.offset,
      va: hit.va ?? null,
      section: hit.section ?? null,
      preview: hit.preview,
      symbol: hit.symbol ?? null,
    })),
    scanComplete: search.scanComplete,
  };
  const symbolFor = (va: string): string | null => {
    const parsed = parseVa(va);
    return parsed === null ? null : lookupSymbol(symbolIndex, parsed)?.name ?? null;
  };

  if (search.hitCount === 0) {
    stages.push({ stage: "xrefs", status: "skipped", detail: "no search hits" });
    stages.push({ stage: "decompile", status: "skipped", detail: "no search hits" });
    return {
      needle: options.needle,
      kind,
      sampleSha256: search.sha256,
      search: searchSummary,
      referenceSites: [],
      functions: [],
      stages,
      notes: search.notes,
      next: [
        "no static matches — try strings_extract_deep (FLOSS recovers obfuscated strings), a wider regex, or the unpacked image from dynamic_unpack",
      ],
    };
  }
  if (vaHits.length === 0) {
    stages.push({ stage: "xrefs", status: "skipped", detail: "hits carry no VA (non-PE file or unmapped offsets)" });
    stages.push({ stage: "decompile", status: "skipped", detail: "no addresses to reference" });
    return {
      needle: options.needle,
      kind,
      sampleSha256: search.sha256,
      search: searchSummary,
      referenceSites: [],
      functions: [],
      stages,
      notes: search.notes,
      next: search.next,
    };
  }

  // ---- stage 2: cross-references (IDA preferred, Ghidra fallback) -------------
  // The reference implementation of this combo was IDA-only and died on
  // hosts without it; Ghidra's references mode (functions that reference
  // the target VAs, exported WITH decompiled code) covers the same
  // question with the backends that ARE present.
  const idatPath = resolveIdat();
  const targetVas = [...new Set(vaHits.map((hit) => hit.va as string))].slice(0, 16);

  interface GhidraFunctionEntry {
    name?: string;
    entryPoint?: string;
    decompiledCode?: string | null;
    decompilationCompleted?: boolean;
    decompilationError?: string | null;
    decompilationTruncated?: boolean;
    referencedTargets?: Array<{ target?: string; fromAddress?: string; referenceType?: string }>;
  }

  if (idatPath === null) {
    // ---- Ghidra fallback: references-to + decompile in one run ---------------
    let ghidraReport: { functions?: GhidraFunctionEntry[] } | null = null;
    try {
      const ghidraRun = await runGhidraAnalysis(workspace, userPath, {
        referencesTo: targetVas,
        maxFunctions: Math.max(maxDecompiles * 2, 8),
        maxDecompiledChars: 10_000,
        ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: Math.min(options.timeoutSeconds, 900) }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (ghidraRun.command.exitCode !== 0 || ghidraRun.command.timedOut) {
        stages.push({
          stage: "decompile",
          status: "failed",
          detail: `ghidra exited ${ghidraRun.command.exitCode ?? -1}${ghidraRun.command.timedOut ? " (timed out)" : ""}`,
        });
      } else if (ghidraRun.report === null || ghidraRun.report === undefined) {
        stages.push({ stage: "decompile", status: "failed", detail: "ghidra produced no report" });
      } else {
        ghidraReport = ghidraRun.report as { functions?: GhidraFunctionEntry[] };
        stages.push({
          stage: "xrefs",
          status: "ok",
          detail: "Ghidra references backend resolved who references the needle (IDA not available)",
        });
      }
    } catch (error) {
      stages.push({
        stage: "decompile",
        status: "failed",
        detail: `ghidra backend unavailable: ${error instanceof Error ? error.message : String(error)}`,
      });
    }

    const ghidraFunctions = ghidraReport?.functions ?? [];
    const referenceSites: ExplainResult["referenceSites"] = [];
    const functions: ExplainFunction[] = [];
    for (const entry of ghidraFunctions) {
      for (const ref of entry.referencedTargets ?? []) {
        referenceSites.push({
          address: ref.fromAddress ?? "unknown",
          function: entry.name ?? null,
          functionStart: entry.entryPoint ?? null,
          references: 1,
          symbol: entry.entryPoint === undefined ? null : symbolFor(entry.entryPoint),
        });
        if (referenceSites.length >= 64) break;
      }
      if (functions.length < maxDecompiles) {
        functions.push({
          name: entry.name ?? null,
          start: entry.entryPoint ?? "?",
          pseudocodePreview: typeof entry.decompiledCode === "string" ? entry.decompiledCode.slice(0, 8000) : null,
          truncated: entry.decompilationTruncated ?? false,
          references: entry.referencedTargets?.length ?? 0,
          ...(entry.decompilationError !== null && entry.decompilationError !== undefined
            ? { error: entry.decompilationError }
            : {}),
        });
      }
    }
    stages.push({
      stage: "decompile",
      status: functions.length > 0 ? "ok" : "skipped",
      ...(functions.length > 0 ? {} : { detail: ghidraFunctions.length === 0 ? "Ghidra found no referring functions (data-only or computed access)" : "no decompilations returned" }),
    });
    if (ghidraFunctions.length === 0) {
      notes.push("Ghidra found no code references to the needle's addresses (data-only or computed access)");
      next.push("addresses are ready: binary_search found them — try disassembly_dump on the VA or check for indirect/computed access");
    }
    if (functions.length > 0) {
      next.push("pseudocode is bounded to 8000 chars per function; function_decompile (Ghidra) takes explicit addresses for more");
    }
    // When no backend found referrers (or none exist in a stub image), the
    // hit addresses themselves are still the actionable output — hand them
    // back as sites so the agent can disassembly_dump them.
    if (referenceSites.length === 0) {
      for (const hit of vaHits.slice(0, 8)) {
        referenceSites.push({
          address: hit.va as string,
          function: null,
          functionStart: null,
          references: 1,
          symbol: symbolFor(hit.va as string),
        });
      }
    }
    return {
      needle: options.needle,
      kind,
      sampleSha256: search.sha256,
      search: searchSummary,
      referenceSites,
      functions,
      stages,
      notes,
      next: [...next, ...search.next.filter((entry) => !entry.includes("binary_explain"))],
    };
  }

  // ---- IDA path -------------------------------------------------------------
  let xrefReport: Record<string, unknown> | null = null;
  try {
    const xrefRun = await runIdaExport(workspace, userPath, {
      mode: "xrefs",
      targets: targetVas,
      ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (xrefRun.command.exitCode !== 0 || xrefRun.report === null) {
      stages.push({
        stage: "xrefs",
        status: "failed",
        detail: `idat exited ${xrefRun.command.exitCode ?? -1}${xrefRun.command.timedOut ? " (timed out)" : ""}; report ${xrefRun.report === null ? "missing" : "present"}`,
      });
    } else {
      xrefReport = xrefRun.report;
      stages.push({ stage: "xrefs", status: "ok" });
    }
  } catch (error) {
    stages.push({ stage: "xrefs", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  // Reference sites ranked by how many targets land in the same function.
  const refCountByStart = new Map<string, { function: string | null; count: number }>();
  const referenceSites: ExplainResult["referenceSites"] = [];
  if (xrefReport !== null) {
    const entries = Array.isArray(xrefReport.xrefs) ? (xrefReport.xrefs as IdaXrefEntry[]) : [];
    for (const entry of entries) {
      for (const ref of entry.xrefs ?? []) {
        if (ref.functionStart === undefined || ref.functionStart === null) continue;
        const site = refCountByStart.get(ref.functionStart);
        if (site === undefined) {
          refCountByStart.set(ref.functionStart, { function: ref.function ?? null, count: 1 });
        } else {
          site.count += 1;
        }
        referenceSites.push({
          address: ref.from ?? "unknown",
          function: ref.function ?? null,
          functionStart: ref.functionStart,
          references: 1,
          symbol: ref.functionStart === undefined ? null : symbolFor(ref.functionStart),
        });
        if (referenceSites.length >= 64) break;
      }
    }
  }
  const xrefTargetsFound = refCountByStart.size > 0;
  if (!xrefTargetsFound && xrefReport !== null) {
    notes.push("IDA found no code references to the needle's addresses (data-only or computed access)");
  }

  // ---- stage 3: decompile the top referring functions ------------------------
  const ranked = [...refCountByStart.entries()]
    .sort((left, right) => right[1].count - left[1].count)
    .slice(0, maxDecompiles);
  if (ranked.length === 0) {
    stages.push({
      stage: "decompile",
      status: "skipped",
      detail: xrefReport === null ? "xrefs stage failed" : "no referring functions to decompile",
    });
    if (xrefReport !== null) {
      next.push("addresses are ready: binary_search found them, IDA sees no direct refs — try disassembly_dump on the VA or check for indirect/computed access");
    }
    return {
      needle: options.needle,
      kind,
      sampleSha256: search.sha256,
      search: searchSummary,
      referenceSites,
      functions: [],
      stages,
      notes,
      next: [...next, ...search.next.filter((entry) => !entry.includes("binary_explain"))],
    };
  }

  const decompileTargets = ranked.map(([start]) => start);
  const functions: ExplainFunction[] = [];
  try {
    const decompileRun = await runIdaExport(workspace, userPath, {
      mode: "decompile",
      targets: decompileTargets,
      ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (decompileRun.command.exitCode !== 0 || decompileRun.report === null) {
      stages.push({
        stage: "decompile",
        status: "failed",
        detail: `idat exited ${decompileRun.command.exitCode ?? -1}${decompileRun.command.timedOut ? " (timed out)" : ""}`,
      });
    } else {
      const entries = Array.isArray(decompileRun.report.decompilations)
        ? (decompileRun.report.decompilations as IdaDecompileEntry[])
        : [];
      for (const entry of entries) {
        const rank = ranked.find(([start]) => start === entry.start);
        functions.push({
          name: entry.name ?? null,
          start: entry.start ?? entry.target ?? "?",
          pseudocodePreview: typeof entry.pseudocode === "string" ? entry.pseudocode.slice(0, 8000) : null,
          truncated: entry.truncated ?? false,
          references: rank === undefined ? 0 : rank[1].count,
          ...(entry.error === undefined ? {} : { error: entry.error }),
        });
      }
      stages.push({
        stage: "decompile",
        status: functions.length > 0 ? "ok" : "failed",
        ...(functions.length > 0 ? {} : { detail: "no decompilations returned" }),
      });
    }
  } catch (error) {
    stages.push({ stage: "decompile", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  if (functions.length > 0) {
    next.push("pseudocode is bounded to 8000 chars per function; ida_decompile takes explicit targets for the full output");
  }

  return {
    needle: options.needle,
    kind,
    sampleSha256: search.sha256,
    search: searchSummary,
    referenceSites,
    functions,
    stages,
    notes,
    next: [...next, ...search.next.filter((entry) => !entry.includes("binary_explain"))],
  };
}
