/**
 * trace.source — the runtime→static bridge, the operation that replaces an
 * hour in a debugger. Known behavior ("this sample connects to X" / "drops
 * Y" / "reads key Z") becomes the FUNCTION that does it, in one call:
 *
 *   frida source-trace (hook the API, capture the caller's backtrace with
 *   module + offset per frame) → find the sample's module in the runtime
 *   module list → slide = runtimeBase − staticImageBase (the ASLR
 *   relocation the agent would otherwise compute by hand, wrongly) →
 *   every sample-module frame offset IS an RVA → static VA = imageBase +
 *   RVA → resolve through the symbol map (annotate.symbol names) →
 *   optionally decompile the hottest sites with IDA Hex-Rays.
 *
 * The result answers "who is making this call" with evidence: runtime
 * addresses, the slide, static VAs, per-site call counts and arguments,
 * and pseudocode. Dynamic-gated like every sample-executing operation.
 */
import { inspectBinary } from "./binary.js";
import { runFridaSourceTrace, SOURCE_TRACE_DEFAULT_TARGETS } from "./frida.js";
import type { SourceTraceTarget } from "./frida.js";
import { runIdaExport, resolveIdat } from "./ida.js";
import { parsePeTablesFromPath } from "./peimports.js";
import { loadSymbolIndex, parseVa, lookupSymbol } from "./symbols.js";
import type { SymbolEntry } from "./symbols.js";
import type { Workspace } from "./workspace.js";

export const TRACE_SOURCE_DEFAULT_PROBE_SECONDS = 10;
export const TRACE_SOURCE_MAX_PROBE_SECONDS = 60;
export const TRACE_SOURCE_MAX_DECOMPILES = 4;
export const TRACE_SOURCE_MAX_SITES = 32;

export interface TraceSourceOptions {
  /** API name(s) to hook; default: the behavioral catalog (file/registry/network/process/crypto). */
  apis?: string[];
  /** Case-insensitive substring the API's primary string argument must contain (C2 host, filename, key path...). */
  needle?: string;
  probeSeconds?: number;
  /** Command-line arguments for the sample (drives branchy validators). */
  args?: string[];
  entryExport?: string;
  /** Decompile the hottest sites with IDA when available (default true). */
  decompile?: boolean;
  maxDecompiles?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface TraceSourceSite {
  staticVa: string;
  /** How many captured calls had this address on their backtrace. */
  hits: number;
  /** APIs whose callers passed through this address. */
  apis: string[];
  /** Primary string arguments seen at those calls (deduped, bounded). */
  args: string[];
  symbol: string | null;
  symbolComment: string | null;
  pseudocodePreview: string | null;
  decompiledName: string | null;
  truncated: boolean;
}

export interface TraceSourceResult {
  path: string;
  sampleId: string;
  sha256: string;
  needle: string | null;
  hookedApis: string[];
  launchedVia: string;
  probeSeconds: number;
  /** runtimeBase − staticImageBase of the sample module; null when unresolved. */
  slide: string | null;
  sampleModule: { name: string; runtimeBase: string; staticImageBase: string; size: number } | null;
  eventCount: number;
  truncated: boolean;
  /** Sample-module frames converted to static VAs, ranked by hit count. */
  sites: TraceSourceSite[];
  /** Non-sample frames (API internals etc.), bounded context. */
  foreignFrames: Array<{ module: string; runtime: string; hits: number }>;
  stages: Array<{ stage: string; status: "ok" | "skipped" | "failed"; detail?: string }>;
  notes: string[];
  next: string[];
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

function parseHex(value: string): number {
  return Number.parseInt(value, 16);
}

/** Match the sample's runtime module by path (fallback: basename). */
function findSampleModule(
  absolutePath: string,
  modules: Array<{ name: string; base: string; size: number; path: string }>,
): { name: string; base: string; size: number; path: string } | null {
  const wanted = absolutePath.toLowerCase();
  const byPath = modules.find((module) => module.path.toLowerCase() === wanted);
  if (byPath !== undefined) return byPath;
  const base = absolutePath.split(/[\\/]/).pop() ?? "";
  return modules.find((module) => module.name.toLowerCase() === base) ?? null;
}

export async function runTraceSource(
  workspace: Workspace,
  userPath: string,
  options: TraceSourceOptions = {},
): Promise<TraceSourceResult> {
  const stages: TraceSourceResult["stages"] = [];
  const notes: string[] = [];
  const next: string[] = [];
  const binary = await inspectBinary(workspace, userPath);
  const absolutePath = await workspace.resolveFile(userPath);
  const probeSeconds = Math.min(
    TRACE_SOURCE_MAX_PROBE_SECONDS,
    Math.max(2, options.probeSeconds ?? TRACE_SOURCE_DEFAULT_PROBE_SECONDS),
  );
  const maxDecompiles = Math.min(TRACE_SOURCE_MAX_DECOMPILES, Math.max(0, options.maxDecompiles ?? 3));

  // Target selection: caller API names map onto the catalog's arg specs so
  // string filtering keeps working; unknown names hook with no arg capture.
  let targets: SourceTraceTarget[] = SOURCE_TRACE_DEFAULT_TARGETS;
  if (options.apis !== undefined && options.apis.length > 0) {
    const catalog = new Map(SOURCE_TRACE_DEFAULT_TARGETS.map((target) => [target.name.toLowerCase(), target]));
    targets = options.apis.map((api) => catalog.get(api.trim().toLowerCase()) ?? { name: api.trim() });
  }

  // ---- stage 1: dynamic source trace ----------------------------------------
  const trace = await runFridaSourceTrace(workspace, userPath, {
    targets,
    ...(options.needle === undefined ? {} : { needle: options.needle }),
    probeSeconds,
    ...(options.args === undefined ? {} : { args: options.args }),
    ...(options.entryExport === undefined ? {} : { entryExport: options.entryExport }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (trace.attachFailed !== null) {
    stages.push({ stage: "source-trace", status: "failed", detail: trace.attachFailed });
    return {
      path: binary.path,
      sampleId: binary.sampleId,
      sha256: binary.sha256,
      needle: options.needle ?? null,
      hookedApis: [],
      launchedVia: trace.launchedVia,
      probeSeconds,
      slide: null,
      sampleModule: null,
      eventCount: 0,
      truncated: false,
      sites: [],
      foreignFrames: [],
      stages,
      notes,
      next: ["the probe failed to attach — try a longer probeSeconds, or check the sample exits immediately"],
    };
  }
  stages.push({
    stage: "source-trace",
    status: "ok",
    detail: `${trace.events.length} call(s) captured across ${trace.hookedApis.length} hooked API(s)`,
  });
  if (trace.hookedApis.length === 0) {
    stages[stages.length - 1]!.status = "failed";
    stages[stages.length - 1]!.detail = "no target APIs were found in any loaded module";
  }

  // ---- stage 2: slide resolution ---------------------------------------------
  const tables = binary.format.kind === "pe" ? await parsePeTablesFromPath(absolutePath) : null;
  const sampleModule = findSampleModule(absolutePath, trace.modules);
  let slide: number | null = null;
  if (tables !== null && sampleModule !== null) {
    const runtimeBase = parseHex(sampleModule.base);
    slide = runtimeBase - tables.imageBase;
    stages.push({
      stage: "slide",
      status: "ok",
      detail: `runtime base ${sampleModule.base} − image base ${hex(tables.imageBase)} = slide ${hex(slide)}`,
    });
  } else {
    stages.push({
      stage: "slide",
      status: "skipped",
      detail: tables === null ? "not a PE sample" : "sample module not found in the runtime module list",
    });
    if (tables === null) notes.push("non-PE sample: frame offsets are reported as module-relative only");
  }

  // ---- stage 3: site conversion (runtime frames → static VAs) ------------------
  const symbolIndex = await loadSymbolIndex(workspace, binary.sampleId);
  const siteMap = new Map<number, TraceSourceSite>();
  const foreignMap = new Map<string, { module: string; runtime: string; hits: number }>();
  for (const event of trace.events) {
    for (const site of event.sites) {
      const isSample = sampleModule !== null && site.module === sampleModule.name;
      if (isSample && site.offset !== null && tables !== null) {
        const rva = site.offset;
        const staticVa = tables.imageBase + rva;
        const existing = siteMap.get(staticVa);
        if (existing === undefined) {
          const symbol: SymbolEntry | null = lookupSymbol(symbolIndex, staticVa);
          siteMap.set(staticVa, {
            staticVa: hex(staticVa),
            hits: 1,
            apis: [event.api],
            args: event.arg === null ? [] : [event.arg],
            symbol: symbol?.name ?? null,
            symbolComment: symbol?.comment ?? null,
            pseudocodePreview: null,
            decompiledName: null,
            truncated: false,
          });
        } else {
          existing.hits += 1;
          if (!existing.apis.includes(event.api)) existing.apis.push(event.api);
          if (event.arg !== null && !existing.args.includes(event.arg) && existing.args.length < 8) {
            existing.args.push(event.arg);
          }
        }
      } else if (site.module !== null && !isSample) {
        const key = `${site.module}!${site.runtime}`;
        const foreign = foreignMap.get(key);
        if (foreign === undefined) {
          foreignMap.set(key, { module: site.module, runtime: site.runtime, hits: 1 });
        } else {
          foreign.hits += 1;
        }
      }
    }
  }
  const sites = [...siteMap.values()].sort((left, right) => right.hits - left.hits).slice(0, TRACE_SOURCE_MAX_SITES);
  stages.push({
    stage: "sites",
    status: sites.length > 0 ? "ok" : "skipped",
    detail: sites.length > 0
      ? `${sites.length} static site(s) resolved from backtraces`
      : "no sample-module frames on any backtrace (the sample may delegate everything to system DLLs)",
  });
  if (sites.length === 0) {
    next.push("no in-sample callers captured: widen the API set (apis), drop the needle filter, or raise probeSeconds");
  }

  // ---- stage 4: IDA decompilation of the hottest sites --------------------------
  const decompile = options.decompile !== false;
  const idatPath = resolveIdat();
  if (!decompile || sites.length === 0) {
    stages.push({ stage: "decompile", status: "skipped", detail: decompile ? "no sites to decompile" : "decompile disabled" });
  } else if (idatPath === null) {
    stages.push({ stage: "decompile", status: "skipped", detail: "IDA not available (set MINUSONE_IDAT_PATH or install at the standard location)" });
    next.push("static VAs are ready for disassembly_dump (radare2) or ida_decompile once IDA is configured");
  } else {
    try {
      const run = await runIdaExport(workspace, userPath, {
        mode: "decompile",
        targets: sites.slice(0, maxDecompiles).map((site) => site.staticVa),
        ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (run.command.exitCode !== 0 || run.report === null) {
        stages.push({
          stage: "decompile",
          status: "failed",
          detail: `idat exited ${run.command.exitCode ?? -1}${run.command.timedOut ? " (timed out)" : ""}`,
        });
      } else {
        const decompilations = Array.isArray(run.report.decompilations)
          ? (run.report.decompilations as Array<Record<string, unknown>>)
          : [];
        for (const entry of decompilations) {
          const start = typeof entry.start === "string" ? parseVa(entry.start) : null;
          if (start === null) continue;
          const site = sites.find((candidate) => parseVa(candidate.staticVa) === start);
          if (site === undefined) continue;
          if (typeof entry.error === "string") {
            site.decompiledName = typeof entry.name === "string" ? entry.name : null;
            site.pseudocodePreview = `decompile error: ${entry.error}`;
            continue;
          }
          site.decompiledName = typeof entry.name === "string" ? entry.name : null;
          site.pseudocodePreview = typeof entry.pseudocode === "string" ? entry.pseudocode.slice(0, 8000) : null;
          site.truncated = entry.truncated === true;
        }
        stages.push({ stage: "decompile", status: "ok", detail: `${decompilations.length} site(s) decompiled` });
      }
    } catch (error) {
      stages.push({ stage: "decompile", status: "failed", detail: error instanceof Error ? error.message : String(error) });
    }
  }

  if (sites.length > 0) {
    next.push("record what you learned with annotate_symbol (va, name) — later finds/explains resolve these VAs by name");
  }

  return {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    needle: options.needle ?? null,
    hookedApis: trace.hookedApis,
    launchedVia: trace.launchedVia,
    probeSeconds,
    slide: slide === null ? null : hex(slide),
    sampleModule: sampleModule === null || tables === null
      ? null
      : { name: sampleModule.name, runtimeBase: sampleModule.base, staticImageBase: hex(tables.imageBase), size: sampleModule.size },
    eventCount: trace.events.length,
    truncated: trace.truncated,
    sites,
    foreignFrames: [...foreignMap.values()].sort((left, right) => right.hits - left.hits).slice(0, 16),
    stages,
    notes,
    next,
  };
}
