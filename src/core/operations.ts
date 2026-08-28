/**
 * Semantic operation registry: the agent-facing tool surface minus transport.
 * Operations are stable verbs (`function.decompile`, `strings.extract`);
 * providers behind them are replaceable. Hosts (dsh plugin, MCP facade)
 * render this table into their own tool registries.
 */
import path from "node:path";
import { cacheKeyDigest, exportArtifact, findArtifactByCacheKey, listArtifacts, listFindings, readArtifact, readArtifactFull, storeArtifact, storeFinding } from "./artifacts.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { baselineAnalyze, disassemble } from "./analyzer.js";
import { inspectBinary } from "./binary.js";
import { runBinwalkExtract, runBinwalkScan } from "./binwalk.js";
import { runCapaAnalysis, summarizeCapaReport } from "./capa.js";
import { runDieDetection, summarizeDieReport } from "./die.js";
import { executeSample, resolveDynamicTarget, unpackSample, launchDetachedSample, killProcessTree, DYNAMIC_EXECUTE_DEFAULT_SECONDS } from "./dynamic.js";
import { readConsoleScreen, sendConsoleInput } from "./console.js";
import { runDynamicRecon, runUnpackChain } from "./chains.js";
import { probeFridaAvailability, runFridaProbe, runFridaScript, runTraceDiff } from "./frida.js";
import {
  FLOSS_DUMPS_MAX_FILES,
  FLOSS_DUMPS_MAX_TIMEOUT_SECONDS,
  flossDumpDirectory,
  runFlossExtraction,
  summarizeFlossReport,
} from "./floss.js";
import { correlateEvidence } from "./correlate.js";
import { activeDebugSessionKind, buildStringBreakpoint, closeDebugSession, createDebugSession, killDebugInferior, parseWatchpointResult, sendDebugCommand } from "./debugger.js";
import { createDoctorReport } from "./doctor.js";
import { findInBinary } from "./find.js";
import { triageBinary } from "./triage.js";
import { searchBinary } from "./search.js";
import { explainNeedle } from "./explain.js";
import { unpackStatic } from "./unpack-static.js";
import { runTraceSource } from "./trace.js";
import { readSymbolMap, removeSymbols, upsertSymbols } from "./symbols.js";
import { extractConfig } from "./configextract.js";
import { runEmulation, runEmulationChain, runEmulationDiff } from "./emu.js";
import { isTtdAvailable, recordTtdTrace, replayTtdTrace } from "./ttd.js";
import { symbolicSolve, symbolicSimplify } from "./symbolic.js";
import { diffBinaries } from "./bindiff.js";
import { readMemory } from "./memoryread.js";
import { surveyBinaries } from "./survey.js";
import { verifySignature } from "./signatures.js";
import { classifyHandler, surveyVm } from "./devirt.js";
import { runGhidraAnalysis } from "./ghidra.js";
import { D810_DEFAULT_PROFILE, isD810Available, runD810Deobfuscation } from "./d810.js";
import { attachVerification, rankAssembly, rankPseudocode } from "./models.js";
import { resolveIdat, runIdaExport, summarizeIdaFunctions } from "./ida.js";
import { patchBinary } from "./pepatch.js";
import { rebuildPe } from "./perebuild.js";
import { inspectMinidump } from "./minidump.js";
import { parsePeResources } from "./peresources.js";
import { parseProcmonTrace } from "./procmon.js";
import { runRadareDump, runRadareFunctionList, runRadareXrefs, summarizeRadareFunctions } from "./radare.js";
import type { RadareFunction } from "./radare.js";
import { extractStrings } from "./strings.js";
import {
  runVolatilityPlugins,
  validateVolatilityPlugins,
  VOLATILITY_DEFAULT_MAX_ROWS,
  VOLATILITY_MAX_PLUGINS_PER_RUN,
  VOLATILITY_MAX_ROWS_HARD_CAP,
  VOLATILITY_MAX_TIMEOUT_SECONDS,
  VOLATILITY_MIN_TIMEOUT_SECONDS,
  VOLATILITY_PLUGINS,
} from "./volatility.js";
import { resolveYaraRulesRef, runYaraScan, summarizeYaraReport } from "./yara.js";
import type { YaraScanOptions } from "./yara.js";
import { detectWindowsToolchain } from "./windows-tools.js";
import type { Workspace } from "./workspace.js";

/** Minimal job-registry seam a host may provide for long-running providers. */
export interface JobSubmitSpec {
  kind: string;
  label: string;
  outputLimitBytes?: number;
  owner?: unknown;
  run: () => {
    cancel: (reason?: string) => void;
    done: Promise<{ status: "completed" | "killed" | "failed"; detail?: string; output?: string }>;
    readOutput?: () => string;
  };
}

export interface OperationServices {
  workspace: Workspace;
  /** Present when the host offers background jobs (dsh `ctx.jobs`). */
  jobs?: { start: (spec: JobSubmitSpec) => string };
  /** Job owner handle passed through by the host (dsh agent). */
  jobOwner?: unknown;
  /** Aborts when the host cancels the calling turn. */
  signal?: AbortSignal;
}

export interface SemanticOperation<Args = Record<string, unknown>> {
  /** Stable dotted operation id used in logs and docs. */
  id: string;
  /** Wire-safe tool name (dots are not portable across model APIs). */
  toolName: string;
  description: string;
  parameters: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  provider: string;
  timeoutMs?: number;
  execute: (args: Args, services: OperationServices) => Promise<unknown>;
}

const pathParameter = {
  type: "string",
  description: "Workspace-relative path to the binary",
};

function optional<T extends Record<string, unknown>>(value: T | undefined) {
  return value === undefined ? {} : value;
}

interface GhidraReport {
  program?: { name?: string; executableFormat?: string; language?: string; imageBase?: string };
  scope?: { targetedAddresses?: string[]; functionCountTotal?: number };
  functionCountTotal?: number;
  functionsExported?: number;
  truncated?: boolean;
  functions?: Array<{
    name?: string;
    entryPoint?: string;
    signature?: string;
    bodySize?: number;
    isThunk?: boolean;
    callers?: Array<{ fromAddress?: string; callerName?: string | null; callerEntryPoint?: string | null; referenceType?: string }>;
    callees?: Array<{ name?: string; entryPoint?: string; isThunk?: boolean }>;
    decompiledCode?: string | null;
    decompilationCompleted?: boolean;
    decompilationError?: string | null;
    rangeOverlap?: { bytes?: number } | null;
    disassemblyFallback?: string | null;
    /** A4 auto-fallback: set when the whole-function failure was re-run as range slices. */
    fallback?: "sliced";
    slices?: Array<{
      range: { rangeStart: string; rangeEnd: string };
      name: string | null;
      entryPoint: string | null;
      rangeOverlap: { bytes?: number } | null;
      decompiledCode: string | null;
      disassemblyFallback: string | null;
    }>;
  }>;
}

/**
 * A4 auto-fallback slice plan: overlapping range windows covering
 * [entry, entry+size). 8 KiB windows with a 512 B overlap walk a flattened
 * megaprocedure block-by-block.
 */
export function computeFallbackSlices(entry: number, size: number, sliceSize = 8192, overlap = 512): Array<{ rangeStart: string; rangeEnd: string }> {
  if (!Number.isFinite(entry) || !Number.isFinite(size) || entry <= 0 || size <= 0) return [];
  const slices: Array<{ rangeStart: string; rangeEnd: string }> = [];
  for (let start = entry; start < entry + size; start += sliceSize - overlap) {
    slices.push({
      rangeStart: `0x${start.toString(16)}`,
      rangeEnd: `0x${Math.min(start + sliceSize, entry + size - 1).toString(16)}`,
    });
    if (start + sliceSize >= entry + size) break;
  }
  return slices;
}

const SUMMARY_MAX_FUNCTIONS = 50;
const SUMMARY_PREVIEW_CHARS = 8 * 1024;
const SUMMARY_PREVIEW_FUNCTIONS = 2;

/**
 * Policy gate for the dynamic plane. Sample execution is opt-in: either a
 * one-time `minusone arm` (persisted to .minusone/config.json) or the
 * MINUSONE_ALLOW_DYNAMIC/MINUSONE_DYNAMIC_TARGET env vars for one-shot use.
 * The refusal is a structured result, not a throw: agents read it and
 * continue statically.
 */
async function refuseDynamic(operation: string, workspace?: Workspace): Promise<{
  status: "refused";
  reason: string;
  requirements: string[];
}> {
  const mode = await resolveDynamicTarget(workspace);
  const toolchain = await detectWindowsToolchain();
  const detected = toolchain.tools.filter((tool) => tool.available).map((tool) => tool.name);
  const reason =
    mode === "local"
      ? `${operation}: the local dynamic target is armed, but this operation needs a component that is not available yet (see requirements)`
      : mode === "armed-no-target"
        ? `${operation}: the dynamic plane is armed but no execution target is configured (run 'minusone arm', or set MINUSONE_DYNAMIC_TARGET=local to authorize the analyst host as a target by owner decision)`
        : `${operation}: dynamic analysis is disabled by policy; run 'minusone arm' (one-time) or set MINUSONE_ALLOW_DYNAMIC=1 + MINUSONE_DYNAMIC_TARGET=local to arm the local plane`;
  return {
    status: "refused",
    reason,
    requirements: [
      "run 'minusone arm' once to arm this workspace persistently, OR set MINUSONE_ALLOW_DYNAMIC=1 + MINUSONE_DYNAMIC_TARGET=local for a one-shot session",
      "arming authorizes the analyst host as the execution target — no VM boundary or network isolation applies locally",
      detected.length > 0
        ? `drivers already detected: ${detected.join(", ")}`
        : "sample_execute and dynamic_unpack need no debugger; cdb/x64dbg are optional drivers",
    ],
  };
}

function buildDecompileSummary(
  result: { backend: string; projectName: string; report?: unknown },
  artifact: { id: string; bytes: number; path: string },
  functionFilter: string | undefined,
): unknown {
  const report = (result.report ?? {}) as GhidraReport;
  const needle = functionFilter?.toLowerCase();
  const matched = (report.functions ?? []).filter((fn) => {
    if (needle === undefined || needle === "") return true;
    return (
      (fn.name ?? "").toLowerCase().includes(needle) ||
      (fn.entryPoint ?? "").toLowerCase().includes(needle)
    );
  });
  const preview: Array<{ name: string; entryPoint: string; decompiledCode: string }> = [];
  let previewChars = 0;
  for (const fn of matched) {
    if (preview.length >= SUMMARY_PREVIEW_FUNCTIONS) break;
    const code = fn.decompiledCode ?? "";
    if (code === "") continue;
    const slice = code.slice(0, Math.max(0, SUMMARY_PREVIEW_CHARS - previewChars));
    previewChars += slice.length;
    preview.push({ name: fn.name ?? "", entryPoint: fn.entryPoint ?? "", decompiledCode: slice });
  }
  return {
    backend: result.backend,
    projectName: result.projectName,
    program: report.program ?? {},
    scope: report.scope ?? {},
    functionCountTotal: report.functionCountTotal ?? 0,
    functionsExported: report.functionsExported ?? 0,
    functionsMatchingFilter: matched.length,
    summaryFunctions: matched.slice(0, SUMMARY_MAX_FUNCTIONS).map((fn) => ({
      name: fn.name ?? "",
      entryPoint: fn.entryPoint ?? "",
      signature: fn.signature ?? "",
      bodySize: typeof fn.bodySize === "number" ? fn.bodySize : null,
      ...(fn.fallback === "sliced" ? { fallback: "sliced" as const, sliceCount: fn.slices?.length ?? 0 } : {}),
      callers: (fn.callers ?? []).slice(0, 10).map((caller) => ({
        fromAddress: caller.fromAddress ?? "",
        callerName: caller.callerName ?? null,
        referenceType: caller.referenceType ?? "",
      })),
      callees: (fn.callees ?? []).slice(0, 10).map((callee) => ({
        name: callee.name ?? "",
        entryPoint: callee.entryPoint ?? "",
      })),
    })),
    decompiledPreview: preview,
    fullReport: { artifactId: artifact.id, bytes: artifact.bytes, path: artifact.path, pageWith: "artifact_read" },
  };
}

function omitNullable<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== null && entry !== undefined),
  ) as T;
}

/** Resolved idat path for cache keys (stable string, null when unavailable). */
function resolveIdatCached(): string | null {
  return resolveIdat() ?? null;
}

/** Tail of the idat.log from a finished run — surfaced in failure details. */
async function readIdatLogTail(workspace: Workspace, runDir: string): Promise<string> {
  try {
    const { readFile } = await import("node:fs/promises");
    const log = await readFile(`${workspace.root}\\${runDir}\\idat.log`.replace(/\\/g, path.sep), "utf8");
    return log.slice(-1024);
  } catch {
    return "";
  }
}

/**
 * IDA pseudocode preview (R3-3): a typical main() spends its first ~2500
 * chars on the Hex-Rays declaration block (`// rXX : <type>` and
 * `// [rsp+XX] : <type>` register/stack comments) — a naive slice(0, 4000)
 * showed ONLY declarations. Skip the leading declaration run (bounded: at
 * most half the budget) and preview actual statements from there; the
 * full pseudocode stays in the artifact.
 */
export function idaPreviewSlice(pseudocode: string): string {
  const BUDGET = 4000;
  if (pseudocode.length <= BUDGET) return pseudocode;
  const lines = pseudocode.split(/\r?\n/);
  let skip = 0;
  let consumed = 0;
  while (skip < lines.length) {
    const line: string = lines[skip] ?? "";
    // The declaration block is the signature line followed by a run of
    // comment-only lines; any code statement after it ends the skip.
    const previous: string = lines[skip - 1] ?? "";
    const isSignature = skip === 0 && /\)\s*\{?\s*$/.test(line);
    const isComment = line.trim().startsWith("//");
    const isBlank = line.trim() === "";
    if (!isSignature && !isComment && !isBlank) break;
    if (isBlank && skip > 0 && previous.trim() === "") break;
    consumed += line.length + 1;
    if (consumed > BUDGET / 2) break;
    skip += 1;
  }
  const rest = lines.slice(skip).join("\n");
  return rest.slice(0, BUDGET);
}

/** Compact view of a persisted finding for the listing. */
function summarizeFinding(artifact: { id: string; description: string; createdAt: number }): {
  artifactId: string;
  title: string;
  severity: string;
  createdAt: number;
} {
  const match = /^finding: (.*) \((info|low|medium|high|critical)\)$/.exec(artifact.description);
  return {
    artifactId: artifact.id,
    title: match?.[1] ?? artifact.description,
    severity: match?.[2] ?? "info",
    createdAt: artifact.createdAt,
  };
}

/**
 * The deep-floss job body, shared by `strings.extract.deep` (the alias) and
 * `strings.find` mode `deep-floss` (E13): FLOSS static emulation with a
 * sample-keyed cache and the full report in a CAS artifact.
 */
/**
 * Uniform job-ification for long-running operations (F4): guards the job
 * registry, wires an AbortController into the job's cancel AND the host's
 * turn-abort signal, wraps the body into the settled-promise contract, and
 * returns the standard immediate submission {jobId, status, label, poll}.
 */
function submitOperationJob(
  services: OperationServices,
  kind: string,
  label: string,
  runBody: (signal: AbortSignal) => Promise<unknown>,
): unknown {
  if (!services.jobs) {
    throw new Error(`${kind} requires a background job registry; this host does not provide one.`);
  }
  const abort = new AbortController();
  services.signal?.addEventListener("abort", () => abort.abort(), { once: true });
  const done = (async () => {
    try {
      const result = await runBody(abort.signal);
      return { status: "completed" as const, output: JSON.stringify(result, null, 2) };
    } catch (error) {
      return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
    }
  })();
  const jobId = services.jobs.start({
    kind,
    label,
    outputLimitBytes: 2 * 1024 * 1024,
    ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
    run: () => ({
      cancel: (reason) => abort.abort(reason),
      done,
    }),
  });
  return {
    jobId,
    status: "running",
    label,
    poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
  };
}

async function submitDeepFlossJob(
  services: OperationServices,
  path: string,
  options: { minLength?: number; includeStatic?: boolean; timeoutSeconds?: number },
): Promise<unknown> {
  const { minLength, includeStatic, timeoutSeconds } = options;
  if (!services.jobs) {
    throw new Error("strings_extract_deep requires a background job registry; this host does not provide one.");
  }
  const normalized = {
    ...(minLength === undefined ? {} : { minLength }),
    ...(includeStatic === undefined ? {} : { includeStatic }),
  };
  const sample = await inspectBinary(services.workspace, path);
  const cacheKey = cacheKeyDigest({
    sample: sample.sha256,
    operation: "strings.extract.deep",
    options: normalized,
    image: resolveDockerImage(process.env.MINUSONE_FLOSS_IMAGE, DEFAULT_IMAGES.floss),
    local: process.env.MINUSONE_FLOSS_BIN ?? null,
    schema: 1,
  });
  const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
  const abort = new AbortController();
  const label = `floss ${path}`;
  const done = (async () => {
    try {
      if (cached !== null) {
        const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as unknown;
        return {
          status: "completed" as const,
          output:
            JSON.stringify(
              { ...summarizeFlossReport(report), fullReport: { artifactId: cached.id, bytes: cached.bytes } },
              null,
              2,
            ) + `\n[cache: reused artifact ${cached.id}]`,
        };
      }
      const result = await runFlossExtraction(services.workspace, path, {
        ...normalized,
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        signal: abort.signal,
      });
      if (result.command.aborted) {
        return { status: "killed" as const, detail: "floss cancelled" };
      }
      if (result.command.exitCode !== 0 || result.command.timedOut) {
        return {
          status: "failed" as const,
          detail: `floss exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
        };
      }
      if (result.report === undefined) {
        return {
          status: "failed" as const,
          detail: `floss produced no parsable JSON report (result file ${result.resultPath}); stderr preview: ${result.command.stderr.slice(0, 512)}`,
        };
      }
      const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
        mediaType: "application/json",
        sourceOperation: "strings.extract.deep",
        description: `FLOSS deep string extraction (${result.backend} backend)`,
        sampleId: sample.sampleId,
        cacheKey,
        backend: result.backend,
      });
      return {
        status: "completed" as const,
        output: JSON.stringify(
          {
            ...summarizeFlossReport(result.report),
            fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
          },
          null,
          2,
        ),
      };
    } catch (error) {
      return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
    }
  })();
  const jobId = services.jobs.start({
    kind: "floss",
    label,
    outputLimitBytes: 2 * 1024 * 1024,
    ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
    run: () => ({
      cancel: (reason) => abort.abort(reason),
      done,
    }),
  });
  return {
    jobId,
    status: "running",
    label,
    poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
  };
}

export const operations: SemanticOperation[] = [
  {
    id: "binary.inspect",
    toolName: "binary_inspect",
    description:
      "Identify a binary, calculate SHA-256 and entropy, and detect its basic executable format. The file must be inside the workspace.",
    parameters: {
      type: "object",
      properties: { path: pathParameter },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sampleId: { type: "string" },
        sha256: { type: "string" },
        size: { type: "integer" },
        entropy: { type: "number" },
        format: { type: "object" },
      },
      required: ["path", "sampleId", "sha256", "size", "entropy", "format"],
    },
    provider: "binary-native",
    execute: async (rawArgs, { workspace }) => inspectBinary(workspace, (rawArgs as { path: string }).path),
  },
  {
    id: "binary.find",
    toolName: "binary_find",
    description:
      "Find a needle across every static plane of a binary in ONE call: raw bytes (file offsets), extracted strings (ASCII + UTF-16), PE import/export tables, PE resource strings, and the cached radare2 function listing (populated by disassembly_functions). Hits carry file offset, section, RVA/VA and — when a cached function list exists — the containing function. kind 'bytes' takes a hex needle like '4d5a'; 'regex' matches string/import/export/resource/symbol text; 'api' focuses on imports; 'symbol' on function/export names. Purely static and fast — no backend is spawned, the sample is never executed. Fast multi-plane fan-out over the leading scan window (default 128MB, maxScanBytes has no ceiling); when you need exhaustive whole-file coverage regardless of size, follow up with binary_search (streams the entire file). (Alias of strings_find mode 'leading-window' — prefer that for new work.)",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        needle: { type: "string", description: "What to look for: text, a hex byte pattern (kind 'bytes'), or a JavaScript regex (kind 'regex')" },
        kind: { type: "string", enum: ["string", "bytes", "regex", "api", "symbol"], description: "Search strategy (default: string)" },
        caseSensitive: { type: "boolean", description: "Case-sensitive matching (default: false)" },
        maxHits: { type: "integer", minimum: 1, maximum: 500 },
        maxScanBytes: { type: "integer", minimum: 1024, description: "Scan window in bytes (default 134217728; no ceiling — the file size bounds it)" },
      },
      required: ["path", "needle"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sha256: { type: "string" },
        needle: { type: "string" },
        kind: { type: "string" },
        hits: { type: "array", items: { type: "object" } },
        hitCount: { type: "integer" },
        truncated: { type: "boolean" },
        planeCounts: { type: "object" },
        planes: { type: "object" },
        scan: { type: "object" },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["path", "sha256", "needle", "kind", "hits", "hitCount", "truncated", "planeCounts", "planes", "scan", "notes", "next"],
    },
    provider: "find-native",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace }) => {
      const { path, needle, kind, caseSensitive, maxHits, maxScanBytes } = rawArgs as {
        path: string;
        needle: string;
        kind?: "string" | "bytes" | "regex" | "api" | "symbol";
        caseSensitive?: boolean;
        maxHits?: number;
        maxScanBytes?: number;
      };
      return findInBinary(workspace, path, {
        needle,
        ...(kind === undefined ? {} : { kind }),
        ...(caseSensitive === undefined ? {} : { caseSensitive }),
        ...(maxHits === undefined ? {} : { maxHits }),
        ...(maxScanBytes === undefined ? {} : { maxScanBytes }),
      });
    },
  },
  {
    id: "binary.search",
    toolName: "binary_search",
    description:
      "Exhaustive streaming whole-file search — NO byte ceiling, unlike binary_find's leading-window fan-out. The file is streamed in chunks (boundary-safe with overlap): text (ASCII + UTF-16LE), raw hex bytes (kind 'bytes'), or regex (kind 'regex'). Use this for large binaries (hundreds of MB) where the needle may live anywhere. Every hit carries file offset, PE section, RVA/VA (random-access table parsing — complete on images of any size). Resumable: a truncated run reports where to continue (startOffset). Purely static; the sample is never executed. (Alias of strings_find mode 'whole-file' — prefer that for new work.)",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        needle: { type: "string", description: "Text to find, a hex byte pattern like '4d5a' (kind 'bytes'), or a JavaScript regex (kind 'regex')" },
        kind: { type: "string", enum: ["string", "bytes", "regex"], description: "Search strategy (default: string)" },
        caseSensitive: { type: "boolean", description: "Case-sensitive matching (default: false)" },
        maxHits: { type: "integer", minimum: 1, maximum: 5000, description: "Hit cap (default 100); a truncated run reports the resume offset" },
        encodings: { type: "array", items: { type: "string", enum: ["ascii", "utf16le"] }, description: "Encodings for kind 'string' (default: both)" },
        startOffset: { type: "integer", minimum: 0, description: "Resume scanning from this file offset" },
        endOffset: { type: "integer", minimum: 1, description: "Stop scanning at this file offset (default: end of file)" },
        contextBytes: { type: "integer", minimum: 0, maximum: 4096, description: "Bytes of printable context around each hit (default 32)" },
      },
      required: ["path", "needle"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sha256: { type: "string" },
        needle: { type: "string" },
        kind: { type: "string" },
        hits: { type: "array", items: { type: "object" } },
        hitCount: { type: "integer" },
        truncated: { type: "boolean" },
        scanComplete: { type: "boolean" },
        scannedBytes: { type: "integer" },
        fileSize: { type: "integer" },
        durationMs: { type: "integer" },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["path", "sha256", "needle", "kind", "hits", "hitCount", "truncated", "scanComplete", "scannedBytes", "fileSize", "notes", "next"],
    },
    provider: "search-native",
    timeoutMs: 300_000,
    execute: async (rawArgs, { workspace }) => {
      const { path, needle, kind, caseSensitive, maxHits, encodings, startOffset, endOffset, contextBytes } = rawArgs as {
        path: string;
        needle: string;
        kind?: "string" | "bytes" | "regex";
        caseSensitive?: boolean;
        maxHits?: number;
        encodings?: Array<"ascii" | "utf16le">;
        startOffset?: number;
        endOffset?: number;
        contextBytes?: number;
      };
      return searchBinary(workspace, path, {
        needle,
        ...(kind === undefined ? {} : { kind }),
        ...(caseSensitive === undefined ? {} : { caseSensitive }),
        ...(maxHits === undefined ? {} : { maxHits }),
        ...(encodings === undefined ? {} : { encodings }),
        ...(startOffset === undefined ? {} : { startOffset }),
        ...(endOffset === undefined ? {} : { endOffset }),
        ...(contextBytes === undefined ? {} : { contextBytes }),
      });
    },
  },
  {
    id: "binary.explain",
    toolName: "binary_explain",
    description:
      "One call answers 'who uses this and what does the code do': chains streaming whole-file search (needle → file offset → VA) → IDA xrefs (which functions reference that VA) → Hex-Rays decompilation of the top referring functions. The workflow that took 3-5 manual calls (search capped → manual VA math → ida_functions → ida_decompile) in one verb. Each stage degrades independently: no IDA → hits with VA context and a radare2 hint; no refs → addresses returned for manual digging. Static — the sample is never executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        needle: { type: "string", description: "Text, hex pattern, or regex — the thing whose usage you want explained" },
        kind: { type: "string", enum: ["string", "bytes", "regex"], description: "Search strategy (default: string)" },
        caseSensitive: { type: "boolean", description: "Case-sensitive matching (default: false)" },
        maxDecompiles: { type: "integer", minimum: 0, maximum: 4, description: "Referring functions to decompile (default 3)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 3600, description: "Per-stage IDA timeout (default 900)" },
      },
      required: ["path", "needle"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        needle: { type: "string" },
        search: { type: "object" },
        referenceSites: { type: "array", items: { type: "object" } },
        functions: { type: "array", items: { type: "object" } },
        stages: { type: "array", items: { type: "object" } },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["needle", "search", "referenceSites", "functions", "stages", "notes", "next"],
    },
    provider: "explain-fusion",
    timeoutMs: 3_600_000,
    execute: async (rawArgs, services) => {
      const { path, needle, kind, caseSensitive, maxDecompiles, timeoutSeconds } = rawArgs as {
        path: string;
        needle: string;
        kind?: "string" | "bytes" | "regex";
        caseSensitive?: boolean;
        maxDecompiles?: number;
        timeoutSeconds?: number;
      };
      return explainNeedle(services.workspace, path, {
        needle,
        ...(kind === undefined ? {} : { kind }),
        ...(caseSensitive === undefined ? {} : { caseSensitive }),
        ...(maxDecompiles === undefined ? {} : { maxDecompiles }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
    },
  },
  {
    id: "binary.triage",
    toolName: "binary_triage",
    description:
      "The one-call first look at an unknown binary: fused report with format/arch/entropy, section table (with per-section entropy from DIE), imports with API-RISK classification (process-injection, anti-analysis, credential-theft, network, persistence, crypto), exports, PE version info, IOC string mining (URLs, IPs, registry paths, PDB paths, UNC shares), packer/packer-layout verdict, embedded binwalk signatures, and capa capabilities when cached. Contextual next steps tell you where to dig. Detect It Easy and binwalk run inline (sharing their own op caches); capa is cache-only unless includeCapabilities is true (slow). Every sub-plane degrades gracefully — a missing backend is recorded, never fatal.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        includeCapabilities: { type: "boolean", description: "Run capa inline when its artifact is not cached (minutes, not seconds)" },
        maxScanBytes: { type: "integer", minimum: 1024, description: "String-plane scan window (default 33554432 = 32MB; raise for large images, no ceiling)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sha256: { type: "string" },
        verdict: { type: "object" },
        sections: { type: "array", items: { type: "object" } },
        imports: { type: "object" },
        exports: { type: "object" },
        resources: { type: "object" },
        strings: { type: "object" },
        packer: { type: "object" },
        embedded: { type: "object" },
        capabilities: { type: "object" },
        planes: { type: "object" },
        next: { type: "array", items: { type: "string" } },
        fullReport: { type: "object" },
      },
      required: ["path", "sha256", "verdict", "sections", "next", "planes", "fullReport"],
    },
    provider: "triage-fusion",
    timeoutMs: 600_000,
    execute: async (rawArgs, services) => {
      const { path, includeCapabilities, maxScanBytes } = rawArgs as { path: string; includeCapabilities?: boolean; maxScanBytes?: number };
      return triageBinary(services.workspace, path, {
        ...(includeCapabilities === undefined ? {} : { includeCapabilities }),
        ...(maxScanBytes === undefined ? {} : { maxScanBytes }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
    },
  },
  {
    id: "strings.extract",
    toolName: "strings_extract",
    description:
      "Extract ASCII and UTF-16LE strings from a binary without executing it. Default window 512MB, default limit 20000 strings — both parameterizable with NO ceiling (the file size is the bound). For huge binaries raise maxScanBytes to cover the whole image. (Alias of strings_find mode 'plain-strings' — prefer that for new work.)",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        minLength: { type: "integer", minimum: 3, maximum: 128 },
        limit: { type: "integer", minimum: 1, description: "Max strings returned (default 20000; no ceiling)" },
        maxScanBytes: { type: "integer", minimum: 1024, description: "Scan window in bytes (default 536870912; no ceiling — whole-file on demand)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        scannedBytes: { type: "integer" },
        fileSize: { type: "integer" },
        scanTruncated: { type: "boolean" },
        resultTruncated: { type: "boolean" },
        strings: { type: "array", items: { type: "object" } },
      },
      required: ["path", "scannedBytes", "fileSize", "scanTruncated", "resultTruncated", "strings"],
    },
    provider: "strings-native",
    execute: async (rawArgs, { workspace }) => {
      const { path, minLength, limit, maxScanBytes } = rawArgs as { path: string; minLength?: number; limit?: number; maxScanBytes?: number };
      return extractStrings(workspace, path, {
        ...optional(minLength === undefined ? undefined : { minLength }),
        ...optional(limit === undefined ? undefined : { limit }),
        ...optional(maxScanBytes === undefined ? undefined : { maxScanBytes }),
      });
    },
  },
  {
    id: "strings.extract.deep",
    toolName: "strings_extract_deep",
    description:
      "Submit FLOSS deep string extraction as a background job: statically emulates decoding routines to recover stack, tight, and decoded (deobfuscated) strings that plain strings_extract cannot see — the sample is never executed. Returns the job id immediately; poll with job_output (wait: true). The finished output carries bounded per-class string lists (decoded strings include the decoding routine address in hex) plus an artifact id for the full JSON report. (Alias of strings_find mode 'deep-floss' — prefer that for new work.)",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        minLength: { type: "integer", minimum: 3, maximum: 32 },
        includeStatic: { type: "boolean", description: "Also include plain static strings (default: only stack, tight, and decoded)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 1800 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "floss",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, minLength, includeStatic, timeoutSeconds } = rawArgs as {
        path: string;
        minLength?: number;
        includeStatic?: boolean;
        timeoutSeconds?: number;
      };
      return await submitDeepFlossJob(services, path, {
        ...(minLength === undefined ? {} : { minLength }),
        ...(includeStatic === undefined ? {} : { includeStatic }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
      });
    },
  },
  {
    id: "strings.find",
    toolName: "strings_find",
    description:
      "ONE string/find plane with four modes (E13 — the older binary_find / binary_search / strings_extract / strings_extract_deep remain as working aliases with their own schemas; prefer this one). Modes: 'leading-window' (= binary_find: multi-plane needle fan-out — bytes, strings, imports, exports, resources, symbols — over the leading scan window, maxScanBytes uncapped); 'whole-file' (= binary_search: exhaustive streaming search with NO byte ceiling, resumable via startOffset, text/UTF-16/hex/regex); 'plain-strings' (= strings_extract: ASCII + UTF-16LE string dump, window and limit uncapped); 'deep-floss' (= strings_extract_deep: FLOSS static emulation recovering stack/tight/decoded strings — the ONLY mode that returns a background job id instead of inline results; poll with job_output). needle is required for the two search modes and meaningless for the extract modes (honest error, not silently ignored). kind 'api'/'symbol' exist only in leading-window mode. Static: the sample is never executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        mode: {
          type: "string",
          enum: ["leading-window", "whole-file", "plain-strings", "deep-floss"],
          description: "Which plane: multi-plane fan-out (leading-window) / exhaustive streaming search (whole-file) / plain string dump (plain-strings) / FLOSS deobfuscation job (deep-floss)",
        },
        needle: { type: "string", description: "REQUIRED for leading-window and whole-file: text, a hex byte pattern (kind 'bytes'), or a JavaScript regex (kind 'regex'); must NOT be passed for the extract modes" },
        kind: { type: "string", enum: ["string", "bytes", "regex", "api", "symbol"], description: "Search strategy (default: string); 'api' and 'symbol' only exist in leading-window mode" },
        caseSensitive: { type: "boolean", description: "Case-sensitive matching (default: false)" },
        maxHits: { type: "integer", minimum: 1, maximum: 5000, description: "Hit cap (default 500 leading-window, 100 whole-file; a truncated whole-file run reports the resume offset)" },
        maxScanBytes: { type: "integer", minimum: 1024, description: "Scan window in bytes (leading-window default 134217728, plain-strings default 536870912; no ceiling — the file size bounds it)" },
        encodings: { type: "array", items: { type: "string", enum: ["ascii", "utf16le"] }, description: "whole-file mode: encodings for kind 'string' (default: both)" },
        startOffset: { type: "integer", minimum: 0, description: "whole-file mode: resume scanning from this file offset" },
        endOffset: { type: "integer", minimum: 1, description: "whole-file mode: stop scanning at this file offset (default: end of file)" },
        contextBytes: { type: "integer", minimum: 0, maximum: 4096, description: "whole-file mode: bytes of printable context around each hit (default 32)" },
        minLength: { type: "integer", minimum: 3, maximum: 128, description: "plain-strings (max 128) / deep-floss (max 32): minimum string length" },
        limit: { type: "integer", minimum: 1, description: "plain-strings mode: max strings returned (default 20000; no ceiling)" },
        includeStatic: { type: "boolean", description: "deep-floss mode: also include plain static strings (default: only stack, tight, and decoded)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 1800, description: "deep-floss mode: FLOSS budget" },
      },
      required: ["path", "mode"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        mode: { type: "string" },
        jobId: { type: "string" },
        status: { type: "string" },
      },
      required: [],
    },
    provider: "find-native",
    timeoutMs: 300_000,
    execute: async (rawArgs, services) => {
      const args = rawArgs as {
        path: string;
        mode: "leading-window" | "whole-file" | "plain-strings" | "deep-floss";
        needle?: string;
        kind?: "string" | "bytes" | "regex" | "api" | "symbol";
        caseSensitive?: boolean;
        maxHits?: number;
        maxScanBytes?: number;
        encodings?: Array<"ascii" | "utf16le">;
        startOffset?: number;
        endOffset?: number;
        contextBytes?: number;
        minLength?: number;
        limit?: number;
        includeStatic?: boolean;
        timeoutSeconds?: number;
      };
      const searchMode = args.mode === "leading-window" || args.mode === "whole-file";
      if (searchMode && (args.needle === undefined || args.needle === "")) {
        throw new Error(`mode '${args.mode}' requires needle (text, hex pattern with kind 'bytes', or regex with kind 'regex')`);
      }
      if (!searchMode && args.needle !== undefined) {
        throw new Error(`mode '${args.mode}' does not take a needle — it extracts strings, it does not search them (use a search mode for that)`);
      }
      if (args.mode === "whole-file" && (args.kind === "api" || args.kind === "symbol")) {
        throw new Error(`kind '${args.kind}' exists only in leading-window mode (multi-plane fan-out); whole-file streams raw content — use string/bytes/regex`);
      }
      switch (args.mode) {
        case "leading-window":
          return await findInBinary(services.workspace, args.path, {
            needle: args.needle as string,
            ...(args.kind === undefined ? {} : { kind: args.kind }),
            ...(args.caseSensitive === undefined ? {} : { caseSensitive: args.caseSensitive }),
            ...(args.maxHits === undefined ? {} : { maxHits: args.maxHits }),
            ...(args.maxScanBytes === undefined ? {} : { maxScanBytes: args.maxScanBytes }),
          });
        case "whole-file": {
          // The guard above rejected kind 'api'/'symbol' — narrow for TS.
          const kind = args.kind as "string" | "bytes" | "regex" | undefined;
          return await searchBinary(services.workspace, args.path, {
            needle: args.needle as string,
            ...(kind === undefined ? {} : { kind }),
            ...(args.caseSensitive === undefined ? {} : { caseSensitive: args.caseSensitive }),
            ...(args.maxHits === undefined ? {} : { maxHits: args.maxHits }),
            ...(args.encodings === undefined ? {} : { encodings: args.encodings }),
            ...(args.startOffset === undefined ? {} : { startOffset: args.startOffset }),
            ...(args.endOffset === undefined ? {} : { endOffset: args.endOffset }),
            ...(args.contextBytes === undefined ? {} : { contextBytes: args.contextBytes }),
          });
        }
        case "plain-strings":
          return await extractStrings(services.workspace, args.path, {
            ...(args.minLength === undefined ? {} : { minLength: args.minLength }),
            ...(args.limit === undefined ? {} : { limit: args.limit }),
            ...(args.maxScanBytes === undefined ? {} : { maxScanBytes: args.maxScanBytes }),
          });
        case "deep-floss":
          if (args.minLength !== undefined && args.minLength > 32) {
            throw new Error("deep-floss mode caps minLength at 32 (FLOSS convention; plain-strings accepts up to 128)");
          }
          return await submitDeepFlossJob(services, args.path, {
            ...(args.minLength === undefined ? {} : { minLength: args.minLength }),
            ...(args.includeStatic === undefined ? {} : { includeStatic: args.includeStatic }),
            ...(args.timeoutSeconds === undefined ? {} : { timeoutSeconds: args.timeoutSeconds }),
          });
      }
    },
  },
  {
    id: "dumps.floss",
    toolName: "dumps_floss",
    description:
      "Auto-FLOSS a pe-sieve dump directory: walks the dumpDir produced by dynamic_unpack and runs FLOSS deep string extraction on every dumped PE module, recovering decoded/stack/tight strings from the unpacked image in one call instead of analyzing each dump by hand. Static analysis only — dumps are inert files, nothing is executed. Background job: poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        dumpDirPath: { type: "string", description: "Dump directory produced by dynamic_unpack (its dumpDir)" },
        maxFiles: { type: "integer", minimum: 1, maximum: FLOSS_DUMPS_MAX_FILES, description: "Cap on dumped modules analyzed (default 8)" },
        minLength: { type: "integer", minimum: 3, maximum: 32 },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: FLOSS_DUMPS_MAX_TIMEOUT_SECONDS, description: "Per-file FLOSS budget in seconds (default 300)" },
      },
      required: ["dumpDirPath"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "floss",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { dumpDirPath, maxFiles, minLength, timeoutSeconds } = rawArgs as {
        dumpDirPath: string;
        maxFiles?: number;
        minLength?: number;
        timeoutSeconds?: number;
      };
      if (!services.jobs) {
        throw new Error("dumps_floss requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `dumps-floss ${dumpDirPath}`;
      const done = (async () => {
        try {
          const { report, artifactId, cacheHit } = await flossDumpDirectory(services.workspace, dumpDirPath, {
            ...(maxFiles === undefined ? {} : { maxFiles }),
            ...(minLength === undefined ? {} : { minLength }),
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (abort.signal.aborted) {
            return { status: "killed" as const, detail: "dumps floss cancelled" };
          }
          const suffix = cacheHit
            ? `\n[cache: reused artifact ${artifactId}]`
            : `\n[artifact: ${artifactId} — page with artifact_read]`;
          return { status: "completed" as const, output: `${report}${suffix}` };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "dumps-floss",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "analysis.baseline",
    toolName: "analysis_baseline",
    description:
      "Legacy safe baseline (metadata, entropy, strings, headers). Prefer binary_triage, which subsumes this pipeline and adds imports/exports/resources/IOCs/packer/capabilities fusion. This never executes the sample.",
    parameters: {
      type: "object",
      properties: { path: pathParameter },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        binary: { type: "object" },
        strings: { type: "object" },
        headers: { type: "object" },
        limitations: { type: "array", items: { type: "string" } },
      },
      required: ["binary", "strings", "limitations"],
    },
    provider: "baseline-pipeline",
    execute: async (rawArgs, { workspace }) => baselineAnalyze(workspace, (rawArgs as { path: string }).path),
  },
  {
    id: "disassembly.list",
    toolName: "disassembly_list",
    description:
      "Disassemble a binary with objdump using bounded output. Constrain by symbol or address range, or pass section (e.g. .rdata, .rodata) to dump raw section contents instead of code.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        symbol: { type: "string" },
        startAddress: { type: "string" },
        stopAddress: { type: "string" },
        section: { type: "string", description: "Dump this section's raw contents (objdump -s -j) instead of disassembling code" },
        maxOutputBytes: { type: "integer", minimum: 4096, maximum: 1048576 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        // exitCode is normalized (spawn failure / kill → -1) because the host
        // tool pipeline rejects type arrays in schemas.
        exitCode: { type: "integer" },
        stdout: { type: "string" },
        stderr: { type: "string" },
        timedOut: { type: "boolean" },
        outputTruncated: { type: "boolean" },
        aborted: { type: "boolean" },
      },
      required: ["exitCode", "stdout", "stderr", "timedOut", "outputTruncated", "aborted"],
    },
    provider: "objdump",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace, signal }) => {
      const { path, symbol, startAddress, stopAddress, section, maxOutputBytes } = rawArgs as { path: string; symbol?: string; startAddress?: string; stopAddress?: string; section?: string; maxOutputBytes?: number };
      const command = await disassemble(workspace, path, {
        ...optional(symbol === undefined ? undefined : { symbol }),
        ...optional(startAddress === undefined ? undefined : { startAddress }),
        ...optional(stopAddress === undefined ? undefined : { stopAddress }),
        ...optional(section === undefined ? undefined : { section }),
        ...optional(maxOutputBytes === undefined ? undefined : { maxOutputBytes }),
        ...(signal === undefined ? {} : { signal }),
      });
      return { ...command, exitCode: command.exitCode ?? -1 };
    },
  },
  {
    id: "function.decompile",
    toolName: "function_decompile",
    description:
      "Submit a Ghidra headless import, analysis, and bounded decompiler export as a background job. Returns the job id immediately; poll with job_output (wait: true). Pass addresses (entry points found via disassembly) to decompile only those functions — the way to reach functions deep inside large binaries. The finished output carries a compact summary with call references plus an artifact id; page the full report with artifact_read. When a function comes back failed/timeout (flattened megaprocedure), the TRIGGER RULE applies: do not retry with bigger budgets — rank the raw disassembly of that zone with model_rank_assembly (CLAP works where the decompiler died), and feed the surrounding decompilable functions to model_rank_pseudocode for navigation.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 3600 },
        maxCpu: { type: "integer", minimum: 1, maximum: 32 },
        maxFunctions: { type: "integer", minimum: 1, maximum: 200 },
        maxDecompiledChars: { type: "integer", minimum: 256, maximum: 10000 },
        backend: { type: "string", enum: ["auto", "local", "docker"] },
        addresses: {
          type: "array",
          items: { type: "string" },
          maxItems: 64,
          description: "Entry addresses (e.g. \"0x140001450\") limiting the export to those functions",
        },
        functionFilter: { type: "string", description: "Substring (name or entry address) the summary's function list is filtered by" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "ghidra",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, timeoutSeconds, maxCpu, maxFunctions, maxDecompiledChars, backend, addresses, functionFilter } =
        rawArgs as {
          path: string;
          timeoutSeconds?: number;
          maxCpu?: number;
          maxFunctions?: number;
          maxDecompiledChars?: number;
          backend?: "auto" | "local" | "docker";
          addresses?: string[];
          functionFilter?: string;
        };
      if (!services.jobs) {
        throw new Error(
          "function_decompile requires a background job registry; this host does not provide one (the dsh plugin and the MCP facade both do).",
        );
      }
      const normalized = {
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(maxCpu === undefined ? {} : { maxCpu }),
        ...(maxFunctions === undefined ? {} : { maxFunctions }),
        ...(maxDecompiledChars === undefined ? {} : { maxDecompiledChars }),
        ...(backend === undefined ? {} : { backend }),
        ...(addresses === undefined || addresses.length === 0 ? {} : { addresses: [...addresses].sort() }),
      };
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        options: normalized,
        image: resolveDockerImage(process.env.MINUSONE_GHIDRA_IMAGE, DEFAULT_IMAGES.ghidra),
        local: process.env.MINUSONE_GHIDRA_HEADLESS ?? null,
        exportSchema: 2,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `ghidra ${path}${addresses && addresses.length > 0 ? ` @ ${addresses.length} address(es)` : ""}`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as unknown;
            return {
              status: "completed" as const,
              output: JSON.stringify(
                buildDecompileSummary(
                  { backend: cached.backend ?? "cached", projectName: cached.projectName ?? "", report },
                  cached,
                  functionFilter,
                ),
                null,
                2,
              ) + `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runGhidraAnalysis(services.workspace, path, {
            ...normalized,
            ...(addresses === undefined ? {} : { addresses }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "analysis cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `ghidra exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          // A4 auto-fallback: megaprocedures that the whole-function
          // decompiler could not link ("unique hash for varnode", timeouts)
          // are re-run as overlapping range slices — the agent gets
          // structure without having to know about function_decompile_range.
          const report = result.report as GhidraReport;
          const failures = (report.functions ?? []).filter(
            (fn) =>
              fn.isThunk !== true &&
              typeof fn.bodySize === "number" &&
              fn.bodySize >= 4096 &&
              ((fn.decompilationError ?? null) !== null || (fn.decompiledCode ?? null) === null),
          );
          const fallbackBudget = 2;
          for (const failed of failures.slice(0, fallbackBudget)) {
            if (abort.signal.aborted) break;
            const entry = Number.parseInt(failed.entryPoint ?? "", 16);
            const size = failed.bodySize as number;
            const slices = computeFallbackSlices(entry, size);
            if (slices.length === 0) continue;
            const sliceResults: NonNullable<NonNullable<GhidraReport["functions"]>[number]["slices"]> = [];
            for (const slice of slices) {
              if (abort.signal.aborted) break;
              const sliceRun = await runGhidraAnalysis(services.workspace, path, {
                ...normalized,
                rangeStart: slice.rangeStart,
                rangeEnd: slice.rangeEnd,
                signal: abort.signal,
              });
              if (sliceRun.command.exitCode !== 0 || sliceRun.command.timedOut) continue;
              for (const sliced of (sliceRun.report as GhidraReport).functions ?? []) {
                sliceResults.push({
                  range: slice,
                  name: sliced.name ?? null,
                  entryPoint: sliced.entryPoint ?? null,
                  rangeOverlap: sliced.rangeOverlap ?? null,
                  decompiledCode: sliced.decompiledCode ?? null,
                  disassemblyFallback: sliced.disassemblyFallback ?? null,
                });
              }
            }
            failed.slices = sliceResults;
            failed.fallback = "sliced";
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "function.decompile",
            description: `Ghidra decompiler export (${result.backend} backend, project ${result.projectName})`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
            projectName: result.projectName,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              buildDecompileSummary(result, artifact, functionFilter),
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "ghidra",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "function.decompile.range",
    toolName: "function_decompile_range",
    description:
      "The megaprocedure slicer: decompile a VA RANGE instead of whole functions. Control-flow flattening glues 250+ basic blocks into one function that no decompiler can link before timing out — this operation exports every function INTERSECTING [rangeStart, rangeEnd], attempts each with a SHORT decompile budget, and falls back to an annotated disassembly listing of the in-range portion for whatever cannot be decompiled. You always get structure: decompiledCode when the slice decompiles, disassemblyFallback when it does not, plus rangeOverlap (how much of the function the range covers) and cross-references. Slice a flattened monster into a series of small overlapping ranges and walk it block by block. Static: Ghidra headless, the sample is never executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        rangeStart: { type: "string", description: "Range start VA (hex like 0x140001234 or decimal)" },
        rangeEnd: { type: "string", description: "Range end VA (inclusive; hex or decimal)" },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 3600, description: "Analysis timeout (default 300)" },
        maxCpu: { type: "integer", minimum: 1, maximum: 32 },
        maxFunctions: { type: "integer", minimum: 1, maximum: 200, description: "Cap on intersecting functions exported (default 40)" },
        maxDecompiledChars: { type: "integer", minimum: 256, maximum: 10000, description: "Per-function code/listing char budget (default 2500)" },
        backend: { type: "string", enum: ["auto", "local", "docker"] },
      },
      required: ["path", "rangeStart", "rangeEnd"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "ghidra",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, rangeStart, rangeEnd, timeoutSeconds, maxCpu, maxFunctions, maxDecompiledChars, backend } =
        rawArgs as {
          path: string;
          rangeStart: string;
          rangeEnd: string;
          timeoutSeconds?: number;
          maxCpu?: number;
          maxFunctions?: number;
          maxDecompiledChars?: number;
          backend?: "auto" | "local" | "docker";
        };
      if (!services.jobs) {
        throw new Error("function_decompile_range requires a background job registry; this host does not provide one.");
      }
      const normalized = {
        rangeStart: rangeStart.toLowerCase(),
        rangeEnd: rangeEnd.toLowerCase(),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(maxCpu === undefined ? {} : { maxCpu }),
        ...(maxFunctions === undefined ? {} : { maxFunctions }),
        ...(maxDecompiledChars === undefined ? {} : { maxDecompiledChars }),
        ...(backend === undefined ? {} : { backend }),
      };
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        options: normalized,
        image: resolveDockerImage(process.env.MINUSONE_GHIDRA_IMAGE, DEFAULT_IMAGES.ghidra),
        local: process.env.MINUSONE_GHIDRA_HEADLESS ?? null,
        exportSchema: 2,
        mode: "range",
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `ghidra-range ${path} [${rangeStart}..${rangeEnd}]`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as unknown;
            return {
              status: "completed" as const,
              output: JSON.stringify(buildDecompileSummary({ backend: "cached", projectName: "", report }, cached, undefined), null, 2) +
                `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runGhidraAnalysis(services.workspace, path, {
            ...normalized,
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "analysis cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `ghidra exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "function.decompile.range",
            description: `Ghidra range export [${rangeStart}..${rangeEnd}] (${result.backend} backend)`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
            projectName: result.projectName,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(buildDecompileSummary(result, artifact, undefined), null, 2),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "ghidra",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "function.deobfuscate",
    toolName: "function_deobfuscate",
    description:
      "Deobfuscate a function with D810-ng (IDA Pro microcode rewriting): MBA expressions collapse, opaque predicates die, and unflattening rules restructure dispatcher loops — the decompiler output comes out READABLE instead of a wall of x ^ ~y + 2*(x & ~y). Runs headless under idat: baseline decompilation first, then the same function with D810 active (default profile: OLLVM unflattening), so the improvement is visible side by side. Requires IDA (licensed) + the d810-ng plugin installed once by the owner into %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng. Static: the sample is never executed by the analysis host. Background job: poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        target: { type: "string", description: "Function name or hex address to deobfuscate (default: first non-library function)" },
        profile: { type: "string", description: `D810 project profile file name (default: ${D810_DEFAULT_PROFILE}; alternatives: default_unflattening_switch_case, default_instruction_only, eidolon, ...)` },
        profilePath: { type: "string", description: "Workspace-relative path to a USER D810 project .json — staged into d810's user cfg dir (minusone- prefix, your files are never clobbered) and selected for this run. Bring custom MBA rules when the bundled profiles don't collapse your sample's expressions" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 1800, description: "idat timeout (default 600)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status"],
    },
    provider: "ida-d810",
    execute: async (rawArgs, services) => {
      const { path, target, profile, profilePath, timeoutSeconds } = rawArgs as {
        path: string;
        target?: string;
        profile?: string;
        profilePath?: string;
        timeoutSeconds?: number;
      };
      if (!(await isD810Available())) {
        return {
          status: "unavailable",
          d810Available: false,
          error: "D810-ng is not installed: copy the d810-ng repository to %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng (or set MINUSONE_D810_PATH); IDA (licensed) is also required",
        };
      }
      return submitOperationJob(services, "d810-deobfuscate", `d810 ${path}${target === undefined ? "" : ` @ ${target}`}`, async (signal) => {
        const result = await runD810Deobfuscation(services.workspace, path, {
          ...(target === undefined ? {} : { target }),
          ...(profile === undefined ? {} : { profile }),
          ...(profilePath === undefined ? {} : { profilePath }),
          ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
          signal,
        });
        return {
          status: result.error === null && result.d810Available ? "ok" : "error",
          d810Available: result.d810Available,
          target: result.target,
          profile: result.profile,
          ...(result.stagedProfile === null ? {} : { stagedProfile: result.stagedProfile }),
          baseline: result.baseline === null ? undefined : result.baseline.slice(0, 20_000),
          deobfuscated: result.deobfuscated === null ? undefined : result.deobfuscated.slice(0, 20_000),
          ...(result.error === null ? {} : { error: result.error }),
        };
      });
    },
  },
  {
    id: "model.rank.assembly",
    toolName: "model_rank_assembly",
    description:
      "CLAP zero-shot ranking of ASSEMBLY against natural-language descriptions. DOMAIN: obfuscated binaries where the decompiler died (megaprocedures, MBA, control-flow flattening) — it does not depend on decompilation at all. TRIGGER RULE: function_decompile returned failed/timeout for a function → immediately rank the DISASSEMBLY of that zone here (disassembly_dump/list output), do not retry the decompiler with bigger budgets. Give candidate descriptions like 'This function implements SHA-256', 'This is a TEA cipher', 'This is string comparison'. Returns a RANKED list with softmax scores, never a single verdict — the ranker-not-oracle contract. Crypto verdicts arrive with deterministic verification pairs (byte constants to confirm with binary_find kind=bytes: SHA-256 K[0] 982f8a42, TEA delta b979379e, ChaCha sigma 61707861 ...); a claim without a pair is marked a hypothesis. Opt-in plane: enable with 'minusone models on' (workspace config) or MINUSONE_MODELS=1; when disabled or Python/torch is missing, returns status=unavailable and nothing else breaks. Needs the models in ./models (clap-asm, clap-text).",
    parameters: {
      type: "object",
      properties: {
        assembly: { type: "string", maxLength: 60000, description: "The assembly listing to classify (objdump/radare output)" },
        prompts: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 32,
          description: "Candidate descriptions, e.g. 'This function implements SHA-256'",
        },
      },
      required: ["assembly", "prompts"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error", "unavailable"] },
        model: { type: "string" },
        device: { type: "string" },
        ranked: { type: "array", items: { type: "object" } },
        note: { type: "string" },
        error: { type: "string" },
      },
      required: ["status", "model"],
    },
    provider: "model-ranker",
    timeoutMs: 150_000,
    execute: async (rawArgs, services) => {
      const { assembly, prompts } = rawArgs as { assembly: string; prompts: string[] };
      const result = await rankAssembly(services.workspace, { assembly, prompts });
      return {
        status: result.status,
        model: result.model,
        ...(result.device === undefined ? {} : { device: result.device }),
        ...(result.ranked === undefined
          ? {}
          : { ranked: attachVerification(result.ranked), rankedBy: "softmax score, highest first" }),
        ...(result.note === undefined ? {} : { note: result.note }),
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "model.rank.pseudocode",
    toolName: "model_rank_pseudocode",
    description:
      "BinSeek retrieval: rank PSEUDOCODE snippets against a natural-language query — 'find the serial validator', 'which function parses the config'. DOMAIN: normal, decompilable binaries (the 90% case — software, DLLs, firmware, legit audit). THE MANDATORY FIRST STEP after decompilation on such binaries: decompile a batch of functions, then ONE call here ranks 'where is the validator/parser/crypto' and cuts the library noise (90% of a binary) before any deep dive — reading 300 functions one by one is the expensive alternative this replaces. Give up to 32 snippets (function.decompile exports) each with a stable ref (entry VA) and optional name. Returns cosine-similarity scores with xref/size advice attached, never a single verdict — attach cross-references and verify the top candidates by reading them. Not for obfuscated binaries: when the decompiler cannot produce pseudocode there is nothing to rank (that is model_rank_assembly's domain, on raw disassembly). Opt-in plane: 'minusone models on' or MINUSONE_MODELS=1; disabled/missing-Python returns status=unavailable. Needs the models in ./models (BinSeek-Embedding).",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", maxLength: 4000, description: "What to look for, e.g. 'the function that validates the license key'" },
        snippets: {
          type: "array",
          minItems: 1,
          maxItems: 32,
          items: {
            type: "object",
            properties: {
              ref: { type: "string", description: "Stable reference (entry VA) reported back in the ranking" },
              name: { type: "string", description: "Function name when known" },
              code: { type: "string", description: "Decompiled pseudocode" },
            },
            required: ["ref", "code"],
            additionalProperties: false,
          },
        },
      },
      required: ["query", "snippets"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error", "unavailable"] },
        model: { type: "string" },
        device: { type: "string" },
        ranked: { type: "array", items: { type: "object" } },
        note: { type: "string" },
        error: { type: "string" },
      },
      required: ["status", "model"],
    },
    provider: "model-ranker",
    timeoutMs: 150_000,
    execute: async (rawArgs, services) => {
      const { query, snippets } = rawArgs as {
        query: string;
        snippets: Array<{ ref: string; name?: string; code: string }>;
      };
      const result = await rankPseudocode(services.workspace, { query, snippets });
      return {
        status: result.status,
        model: result.model,
        ...(result.device === undefined ? {} : { device: result.device }),
        ...(result.ranked === undefined ? {} : { ranked: result.ranked, rankedBy: "cosine similarity, highest first" }),
        ...(result.note === undefined ? {} : { note: result.note }),
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "artifact.read",
    toolName: "artifact_read",
    description:
      "Read one window of a stored analysis artifact (bounded, page with offset/limit and follow nextOffset). Use it to page large decompiler reports referenced by job outputs.",
    parameters: {
      type: "object",
      properties: {
        id: { type: "string", description: "Artifact id of the form sha256:<64 hex chars>" },
        offset: { type: "integer", minimum: 0 },
        limit: { type: "integer", minimum: 1, maximum: 262144 },
      },
      required: ["id"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        sha256: { type: "string" },
        mediaType: { type: "string" },
        totalBytes: { type: "integer" },
        offset: { type: "integer" },
        length: { type: "integer" },
        truncated: { type: "boolean" },
        nextOffset: { type: "integer" },
        content: { type: "string" },
      },
      required: ["id", "sha256", "mediaType", "totalBytes", "offset", "length", "truncated", "content"],
    },
    provider: "artifact-store",
    execute: async (rawArgs, { workspace }) => {
      const { id, offset, limit } = rawArgs as { id: string; offset?: number; limit?: number };
      const window = await readArtifact(workspace, id, {
        ...optional(offset === undefined ? undefined : { offset }),
        ...optional(limit === undefined ? undefined : { limit }),
      });
      return {
        ...window,
        ...(window.nextOffset === null ? {} : { nextOffset: window.nextOffset }),
      };
    },
  },
  {
    id: "artifact.list",
    toolName: "artifact_list",
    description: "List stored analysis artifacts with their ids, sizes, and source operations.",
    parameters: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    outputSchema: {
      type: "array",
      items: { type: "object" },
    },
    provider: "artifact-store",
    execute: async (_args, { workspace }) => listArtifacts(workspace),
  },
  {
    id: "artifact.export",
    toolName: "artifact_export",
    description:
      "Materialize a stored artifact's content as a real workspace file: the content blob is read from the content-addressed store and written (binary-safe) to a caller-chosen writable path. Use it to grab decoded strings, carved files, decompiled code, or a debug transcript as an ordinary file the operator/other tools can open. The artifact is unchanged; export is a copy out of the CAS.",
    parameters: {
      type: "object",
      properties: {
        id: { type: "string", description: "Artifact id of the form sha256:<64 hex chars>" },
        path: {
          type: "string",
          description: "Writable workspace path for the exported file (the tree is created, e.g. exports/report.json)",
        },
      },
      required: ["id", "path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        exportedPath: { type: "string" },
        artifactId: { type: "string" },
        sha256: { type: "string" },
        mediaType: { type: "string" },
        bytes: { type: "integer" },
      },
      required: ["exportedPath", "artifactId", "sha256", "mediaType", "bytes"],
    },
    provider: "artifact-store",
    timeoutMs: 30_000,
    execute: async (rawArgs, { workspace }) => {
      const { id, path } = rawArgs as { id: string; path: string };
      return await exportArtifact(workspace, id, path);
    },
  },
  {
    id: "capabilities.detect",
    toolName: "capabilities_detect",
    description:
      "Submit a capa analysis as a background job: detects a binary's capabilities and MITRE ATT&CK techniques from static features against a version-pinned rule set. Returns the job id immediately; poll with job_output (wait: true). The finished output carries a bounded rule summary plus an artifact id for the full capa JSON.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "capa",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path } = rawArgs as { path: string };
      if (!services.jobs) {
        throw new Error("capabilities_detect requires a background job registry; this host does not provide one.");
      }
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "capabilities.detect",
        image: resolveDockerImage(process.env.MINUSONE_CAPA_IMAGE, DEFAULT_IMAGES.capa),
        local: process.env.MINUSONE_CAPA_BIN ?? null,
        rules: process.env.MINUSONE_CAPA_RULES ?? "bundled",
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `capa ${path}`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as unknown;
            return {
              status: "completed" as const,
              output: JSON.stringify({ ...summarizeCapaReport(report), fullReport: { artifactId: cached.id, bytes: cached.bytes } }, null, 2) +
                `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runCapaAnalysis(services.workspace, path, { signal: abort.signal });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "capa cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `capa exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "capabilities.detect",
            description: `capa capability detection (${result.backend} backend)`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              { ...summarizeCapaReport(result.report), fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" } },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "capa",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "disassembly.functions",
    toolName: "disassembly_functions",
    description:
      "Submit a radare2 analysis as a background job and list discovered functions — the way to enumerate functions in stripped binaries where symbol-based lookups fail. Returns the job id immediately; poll with job_output (wait: true). The finished output carries a bounded function list (name, entry offset, size, blocks) plus an artifact id for the full listing; filter the summary with functionFilter.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        functionFilter: { type: "string", description: "Substring (name or hex offset) the function list is filtered by" },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 900 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "radare2",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, functionFilter, timeoutSeconds } = rawArgs as { path: string; functionFilter?: string; timeoutSeconds?: number };
      if (!services.jobs) {
        throw new Error("disassembly_functions requires a background job registry; this host does not provide one.");
      }
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "disassembly.functions",
        image: resolveDockerImage(process.env.MINUSONE_R2_IMAGE, DEFAULT_IMAGES.radare2),
        local: process.env.MINUSONE_R2_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `r2 functions ${path}`;
      const done = (async () => {
        try {
          const build = (functions: RadareFunction[] | undefined, artifact: { id: string; bytes: number }, cache?: "reused") =>
            JSON.stringify(
              {
                backend: cache === "reused" ? "cached" : "radare2",
                ...summarizeRadareFunctions(functions, functionFilter),
                fullReport: {
                  artifactId: artifact.id,
                  bytes: artifact.bytes,
                  ...(cache === undefined ? { pageWith: "artifact_read" } : { cache }),
                },
              },
              null,
              2,
            );
          if (cached !== null) {
            const functions = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as RadareFunction[];
            return {
              status: "completed" as const,
              output: `${build(functions, cached, "reused")}\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runRadareFunctionList(services.workspace, path, {
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "radare2 cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `r2 exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          if (result.functions === undefined) {
            return {
              status: "failed" as const,
              detail: `r2 produced no parsable aflj listing; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.functions, null, 2), {
            mediaType: "application/json",
            sourceOperation: "disassembly.functions",
            description: `radare2 function listing (${result.backend} backend)`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
          });
          return { status: "completed" as const, output: build(result.functions, artifact) };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "radare2",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "disassembly.dump",
    toolName: "disassembly_dump",
    description:
      "Dump disassembly or raw hex with radare2 at an address or symbol, bounded by count (instructions for code mode, bytes for hex mode). Analysis-backed, so names and cross-references appear even in stripped binaries. Complements disassembly_list (objdump).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        address: { type: "string", description: "Hex address like 0x140001450" },
        symbol: { type: "string", description: "Symbol name (a sym. prefix is added automatically for plain names)" },
        count: { type: "integer", minimum: 1, maximum: 4096 },
        mode: { type: "string", enum: ["code", "hex"] },
      },
      required: ["path", "count"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        exitCode: { type: "integer" },
        stdout: { type: "string" },
        stderr: { type: "string" },
        timedOut: { type: "boolean" },
        outputTruncated: { type: "boolean" },
        aborted: { type: "boolean" },
      },
      required: ["exitCode", "stdout", "stderr", "timedOut", "outputTruncated", "aborted"],
    },
    provider: "radare2",
    timeoutMs: 180_000,
    execute: async (rawArgs, { workspace, signal }) => {
      const { path, address, symbol, count, mode } = rawArgs as {
        path: string;
        address?: string;
        symbol?: string;
        count: number;
        mode?: "code" | "hex";
      };
      if (address === undefined && symbol === undefined) {
        throw new Error("disassembly_dump requires address or symbol");
      }
      const { command } = await runRadareDump(workspace, path, {
        ...(address === undefined ? {} : { address }),
        ...(symbol === undefined ? {} : { symbol }),
        count,
        mode: mode ?? "code",
        ...(signal === undefined ? {} : { signal }),
      });
      return { ...command, exitCode: command.exitCode ?? -1 };
    },
  },
  {
    id: "xref.query",
    toolName: "xref_query",
    description:
      "Cross-references through the cached radare2 session: 'who references this address?'. Give va ('0x1400d3970'), rva or file offset (PE section-table arithmetic included — the reason raw byte-search for absolute VAs fails on rip-relative code); get every code/data reference (address, type, opcode) enriched with the containing function, plus the function containing the target itself. The session analyzes a sample ONCE and reuses it — repeated queries are milliseconds, not minutes. Static: the sample is never executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        va: { type: "string", description: "Virtual address, hex ('0x1400d3970') or decimal" },
        rva: { type: "string", description: "Relative virtual address (PE only)" },
        offset: { type: "integer", minimum: 0, description: "Raw file offset (PE only)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        target: { type: "string" },
        targetKind: { type: "string", enum: ["va", "rva", "offset"] },
        xrefCount: { type: "integer" },
        xrefs: {
          type: "array",
          items: {
            type: "object",
            properties: {
              from: { type: "string" },
              type: { type: "string" },
              opcode: { type: ["string", "null"] },
              functionName: { type: ["string", "null"] },
              functionOffset: { type: ["string", "null"] },
            },
          },
        },
        containingFunction: { type: ["object", "null"] },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["backend", "target", "targetKind", "xrefCount", "xrefs", "containingFunction", "notes"],
    },
    provider: "radare2",
    timeoutMs: 180_000,
    execute: async (rawArgs, { workspace, signal }) => {
      const { path, va, rva, offset } = rawArgs as { path: string; va?: string; rva?: string; offset?: number };
      if (va === undefined && rva === undefined && offset === undefined) {
        throw new Error("xref_query needs one of va, rva or offset");
      }
      const result = await runRadareXrefs(workspace, path, {
        ...(va === undefined ? {} : { va }),
        ...(rva === undefined ? {} : { rva }),
        ...(offset === undefined ? {} : { offset }),
        ...(signal === undefined ? {} : { signal }),
      });
      const notes: string[] = [];
      if (result.xrefs.length === 0) {
        notes.push("no references collected by the boot analysis — for strings/data also try binary_find (the reference may be an immediate built on the stack) or disassembly_dump at the target");
      }
      return {
        backend: result.backend,
        target: result.target,
        targetKind: result.targetKind,
        xrefCount: result.xrefs.length,
        xrefs: result.xrefs,
        containingFunction: result.containingFunction,
        notes,
      };
    },
  },
  {
    id: "rules.scan",
    toolName: "rules_scan",
    description:
      "Submit a YARA-X scan as a background job. Provide rules either as inline SOURCE text (compiled inside the sandbox) or as a workspace rules FILE: a .yar source, or a precompiled ruleset (yr compile output) together with compiled: true (loaded via --compiled-rules). Returns the job id immediately; poll with job_output (wait: true). The finished output lists matched rules with pattern offsets plus an artifact id for the full JSON report.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        rules: {
          type: "string",
          description: 'Complete YARA rule source text, e.g. "rule marker { strings: $a = { 37 33 34 } condition: $a }". Provide exactly one of rules or rulesFile.',
        },
        rulesFile: {
          type: "string",
          description: "Workspace path to a YARA rules file: .yar source (compiled inside the sandbox) or a compiled ruleset (pass compiled: true to load it via --compiled-rules).",
        },
        compiled: {
          type: "boolean",
          description: "rulesFile is a compiled ruleset (yr compile output). Only valid with rulesFile; inline rules are always compiled in-sandbox.",
        },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 600 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "yara-x",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, rules, rulesFile, compiled, timeoutSeconds } = rawArgs as {
        path: string;
        rules?: string;
        rulesFile?: string;
        compiled?: boolean;
        timeoutSeconds?: number;
      };
      if (!services.jobs) {
        throw new Error("rules_scan requires a background job registry; this host does not provide one.");
      }
      const rulesOptions: YaraScanOptions = {
        ...(rules === undefined ? {} : { rules }),
        ...(rulesFile === undefined ? {} : { rulesFile }),
        ...(compiled === undefined ? {} : { compiled }),
      };
      // Exactly-one-of validation + digest, before the job is scheduled.
      const ref = await resolveYaraRulesRef(services.workspace, rulesOptions);
      const digest = ref.digest;
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "rules.scan",
        rules: digest,
        image: resolveDockerImage(process.env.MINUSONE_YARA_IMAGE, DEFAULT_IMAGES.yaraX),
        local: process.env.MINUSONE_YARA_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `yara ${path} (rules ${digest.slice(0, 8)})`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as unknown;
            return {
              status: "completed" as const,
              output:
                JSON.stringify(
                  { ...summarizeYaraReport(report), fullReport: { artifactId: cached.id, bytes: cached.bytes } },
                  null,
                  2,
                ) + `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runYaraScan(services.workspace, path, {
            ...rulesOptions,
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "yara scan cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `yr exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          if (result.report === undefined) {
            return {
              status: "failed" as const,
              detail: `yr produced no parsable JSON report (result file ${result.resultPath}); stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "rules.scan",
            description: `YARA-X scan (${result.backend} backend, rules staged at ${result.rulesFile})`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                ...summarizeYaraReport(result.report),
                fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "yara",
        label,
        outputLimitBytes: 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "signature.verify",
    toolName: "signature_verify",
    description:
      "Authenticode signature verification, the legitimacy check triage leans on: Get-AuthenticodeSignature (WinVerifyTrust) validates the PKCS#7 SignedData, the certificate chain and the file digest against the local trust store — natively, no downloads. A VALID signature is decisive: the file digest matches what the publisher signed, so the file cannot simultaneously be packed or patched (packing rewrites the image). The report distinguishes NOT SIGNED / VALID / HashMismatch (patched after signing) / present-but-invalid. Run it BEFORE believing any 'packed' entropy verdict on a large legitimate-looking binary — this one check killed half a session of manual debunking in the field.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        path: { type: "string" },
        sampleId: { type: "string" },
        signaturePresent: { type: "boolean" },
        status: { type: "string" },
        signer: { type: "string" },
        signerCommonName: { type: "string" },
        valid: { type: "boolean" },
        verdict: { type: "string" },
        notes: { type: "array", items: { type: "string" } },
        command: { type: "object" },
      },
      required: ["backend", "path", "sampleId", "signaturePresent", "valid", "verdict", "notes"],
    },
    provider: "win-native",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace }) => {
      const { path } = rawArgs as { path: string };
      return verifySignature(workspace, path);
    },
  },
  {
    id: "devirt.survey",
    toolName: "devirt_survey",
    description:
      "VM-obfuscation detector — localize the virtual machine before lifting it. Full automatic devirtualization does not exist as a tool (it is per-VM reverse engineering); what CAN be automated honestly is DETECTION and LOCALIZATION: protector-named sections (.vmp/.themida), uninitialized executable sections, skeletal IAT vs code volume, computed-jump dispatcher idioms (jmp [reg*scale+disp] / jmp reg density) with VAs, and candidate bytecode regions. Output: the dispatcher/handler-table/bytecode map the manual lift starts from, plus the workbench recipe (devirt_classify names handlers under emulation). Every indicator carries evidence.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sampleId: { type: "string" },
        sha256: { type: "string" },
        vmDetected: { type: "boolean" },
        confidence: { type: "string", enum: ["high", "medium", "low", "none"] },
        verdict: { type: "string" },
        indicators: { type: "array", items: { type: "string" } },
        vmSections: { type: "array", items: { type: "object" } },
        dispatchers: { type: "array", items: { type: "object" } },
        bytecodeRegions: { type: "array", items: { type: "object" } },
        next: { type: "array", items: { type: "string" } },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["path", "sampleId", "sha256", "vmDetected", "confidence", "verdict", "indicators", "vmSections", "dispatchers", "bytecodeRegions", "next", "notes"],
    },
    provider: "pe-native",
    timeoutMs: 120_000,
    execute: async (rawArgs, { workspace }) => {
      const { path } = rawArgs as { path: string };
      return surveyVm(workspace, path);
    },
  },
  {
    id: "devirt.classify",
    toolName: "devirt_classify",
    description:
      "Handler classifier for VM lifting — the lift-assist primitive. Carve a VM handler's bytes (binary_find / memory_read / disassembly_list) and this operation runs them under Unicorn with TWO different synthetic VM contexts, comparing register/memory deltas: input-dependent register transform without memory writes → COMPUTE (XOR/ADD-style); memory changed → STORE/LOAD; identical state across different inputs → NO-EFFECT junk handler. Run it over every carved handler to build the VM's opcode table with semantic names instead of raw bytes — the mechanical part of devirtualization, automated. Nothing executes on the host: emulation only, docker --network none.",
    parameters: {
      type: "object",
      properties: {
        codeHex: { type: "string", description: "Handler code bytes as hex (carved by you)" },
        arch: { type: "string", enum: ["x86", "x64"], description: "CPU mode (default x64)" },
        handlerVa: { type: "string", description: "The handler's VA — label only, for your bookkeeping" },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 300 },
      },
      required: ["codeHex"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        status: { type: "string", enum: ["ok", "error"] },
        error: { type: "string" },
        classification: { type: "string" },
        effects: { type: "array", items: { type: "string" } },
        runA: { type: "object" },
        runB: { type: "object" },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["backend", "status", "error", "classification", "effects", "runA", "runB", "next"],
    },
    provider: "unicorn",
    timeoutMs: 300_000,
    execute: async (rawArgs, services) => {
      const { codeHex, arch, handlerVa, timeoutSeconds } = rawArgs as { codeHex: string; arch?: "x86" | "x64"; handlerVa?: string; timeoutSeconds?: number };
      if (handlerVa !== undefined) {
        throw new Error("handlerVa is a label field and not yet wired into the report; pass codeHex only");
      }
      return classifyHandler(services.workspace, {
        codeHex,
        ...(arch === undefined ? {} : { arch }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
      });
    },
  },
  {
    id: "packer.detect",
    toolName: "packer_detect",
    description:
      "Identify packers, compilers, linkers, and protectors in a binary with Detect It Easy, plus per-section entropy and a packed verdict. Static signature matching only — the sample is never executed. Fast enough to run synchronously; the full JSON lands in an artifact.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        deep: { type: "boolean", description: "Enable deep scanning for thorough analysis (slower)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        filetypes: { type: "array", items: { type: "string" } },
        detectionCount: { type: "integer" },
        truncated: { type: "boolean" },
        detections: { type: "array", items: { type: "object" } },
        entropyAvailable: { type: "boolean" },
        packed: { type: "boolean" },
        entropyStatus: { type: "string" },
        totalEntropy: { type: "number" },
        entropyRecords: { type: "array", items: { type: "object" } },
        fullReport: { type: "object" },
      },
      required: [
        "filetypes",
        "detectionCount",
        "truncated",
        "detections",
        "entropyAvailable",
        "packed",
        "entropyRecords",
        "fullReport",
      ],
    },
    provider: "detect-it-easy",
    timeoutMs: 180_000,
    execute: async (rawArgs, services) => {
      const { path, deep } = rawArgs as { path: string; deep?: boolean };
      const sample = await inspectBinary(services.workspace, path);
      const normalized = deep === undefined ? {} : { deep };
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "packer.detect",
        options: normalized,
        image: resolveDockerImage(process.env.MINUSONE_DIE_IMAGE, DEFAULT_IMAGES.die),
        local: process.env.MINUSONE_DIE_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      if (cached !== null) {
        const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as {
          detections?: unknown;
          entropy?: unknown;
        };
        return {
          ...omitNullable(summarizeDieReport(report)),
          fullReport: { artifactId: cached.id, bytes: cached.bytes, cache: "reused" },
        };
      }
      const result = await runDieDetection(services.workspace, path, {
        ...(deep === undefined ? {} : { deep }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
      if (result.command.exitCode !== 0 || result.command.timedOut) {
        throw new Error(
          `packer_detect: diec exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
        );
      }
      if (result.report === undefined) {
        throw new Error(
          `packer_detect: diec produced no parsable JSON (result file ${result.resultPath}); stderr preview: ${result.command.stderr.slice(0, 512)}`,
        );
      }
      const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
        mediaType: "application/json",
        sourceOperation: "packer.detect",
        description: `Detect It Easy identification (${result.backend} backend)`,
        sampleId: sample.sampleId,
        cacheKey,
        backend: result.backend,
      });
      return {
        ...omitNullable(summarizeDieReport(result.report)),
        fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
      };
    },
  },
  {
    id: "embedded.scan",
    toolName: "embedded_scan",
    description:
      "Scan a binary for embedded signatures with binwalk: packed payloads, embedded archives, filesystems, certificates, and other file types with their offsets. Scan-only by design — extraction is not performed. Use it before deep analysis to find appended or embedded objects.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        signatureCount: { type: "integer" },
        truncated: { type: "boolean" },
        signatures: { type: "array", items: { type: "object" } },
        fullReport: { type: "object" },
      },
      required: ["signatureCount", "truncated", "signatures", "fullReport"],
    },
    provider: "binwalk",
    timeoutMs: 180_000,
    execute: async (rawArgs, services) => {
      const { path } = rawArgs as { path: string };
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "embedded.scan",
        image: resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk),
        local: process.env.MINUSONE_BINWALK_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      if (cached !== null) {
        const parsed = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as { signatures: unknown[]; truncated: boolean };
        return {
          signatureCount: parsed.signatures.length,
          truncated: parsed.truncated,
          signatures: parsed.signatures,
          fullReport: { artifactId: cached.id, bytes: cached.bytes, cache: "reused" },
        };
      }
      const result = await runBinwalkScan(services.workspace, path, {
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
      if (result.command.exitCode !== 0 || result.command.timedOut) {
        throw new Error(
          `embedded_scan: binwalk exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
        );
      }
      const payload = { signatures: result.signatures, truncated: result.truncated };
      const artifact = await storeArtifact(services.workspace, JSON.stringify(payload, null, 2), {
        mediaType: "application/json",
        sourceOperation: "embedded.scan",
        description: `binwalk signature scan (${result.backend} backend, scan-only)`,
        sampleId: sample.sampleId,
        cacheKey,
        backend: result.backend,
      });
      return {
        signatureCount: result.signatures.length,
        truncated: result.truncated,
        signatures: result.signatures,
        fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
      };
    },
  },
  {
    id: "embedded.extract",
    toolName: "embedded_extract",
    description:
      "Carve embedded objects out of a binary with binwalk (carve-only: --dd='.*' matches every signature and runs no external extractor, so nothing carved is ever executed). Returns the job id immediately; poll with job_output (wait: true). The finished output lists the carved files (workspace-relative paths + sha256) under .minusone/binwalk/out and an artifact id for the full manifest. Rails: maxFiles caps count, maxBytesPerFile caps per-file bytes, depth caps matryoshka recursion (default 1, no recursion).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        maxFiles: { type: "integer", minimum: 1, maximum: 512 },
        maxBytesPerFile: { type: "integer", minimum: 1024, maximum: 67108864 },
        depth: { type: "integer", minimum: 1, maximum: 3 },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 900 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "binwalk",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, maxFiles, maxBytesPerFile, depth, timeoutSeconds } = rawArgs as {
        path: string;
        maxFiles?: number;
        maxBytesPerFile?: number;
        depth?: number;
        timeoutSeconds?: number;
      };
      if (!services.jobs) {
        throw new Error("embedded_extract requires a background job registry; this host does not provide one.");
      }
      const sample = await inspectBinary(services.workspace, path);
      const extractOptions = {
        ...(maxFiles === undefined ? {} : { maxFiles }),
        ...(maxBytesPerFile === undefined ? {} : { maxBytesPerFile }),
        ...(depth === undefined ? {} : { depth }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
      };
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "embedded.extract",
        ...extractOptions,
        image: resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk),
        local: process.env.MINUSONE_BINWALK_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `binwalk extract ${path} (depth ${depth ?? 1}, max ${maxFiles ?? 64} files)`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const manifest = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as {
              outDirectory: string;
              carved: unknown[];
              signatures: unknown[];
              truncated: boolean;
            };
            return {
              status: "completed" as const,
              output:
                JSON.stringify(
                  {
                    outDirectory: manifest.outDirectory,
                    carvedCount: manifest.carved.length,
                    truncated: manifest.truncated,
                    carved: manifest.carved,
                    signatureCount: manifest.signatures.length,
                    fullManifest: { artifactId: cached.id, bytes: cached.bytes, cache: "reused" },
                  },
                  null,
                  2,
                ) + `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runBinwalkExtract(services.workspace, path, {
            ...extractOptions,
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "binwalk extract cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut) {
            return {
              status: "failed" as const,
              detail: `binwalk exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}; stderr preview: ${result.command.stderr.slice(0, 512)}`,
            };
          }
          const manifest = {
            outDirectory: result.outDirectory,
            backend: result.backend,
            carved: result.carved,
            signatures: result.signatures,
            truncated: result.truncated,
          };
          const artifact = await storeArtifact(services.workspace, JSON.stringify(manifest, null, 2), {
            mediaType: "application/json",
            sourceOperation: "embedded.extract",
            description: `binwalk carve-only extract (${result.backend} backend, ${result.carved.length} carved files)`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                outDirectory: result.outDirectory,
                carvedCount: result.carved.length,
                truncated: result.truncated,
                carved: result.carved,
                signatureCount: result.signatures.length,
                fullManifest: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "binwalk",
        label,
        outputLimitBytes: 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; the carved files appear under .minusone/binwalk/out`,
      };
    },
  },
  {
    id: "pe.resources",
    toolName: "pe_resources",
    description:
      "Parse the PE resource directory natively (no external tools): lists resource types and extracts the triage payloads — version information (file/product version plus StringFileInfo such as CompanyName, FileDescription, OriginalFilename, ProductName, InternalName) and the application manifest preview. Purely static; the sample is never loaded or executed.",
    parameters: {
      type: "object",
      properties: { path: pathParameter },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        types: { type: "array", items: { type: "object" } },
        versionInfo: { type: "object" },
        manifestPreview: { type: "string" },
        manifestTruncated: { type: "boolean" },
        truncated: { type: "boolean" },
      },
      required: ["types", "manifestTruncated", "truncated"],
    },
    provider: "pe-parser-native",
    timeoutMs: 30_000,
    execute: async (rawArgs, { workspace }) => {
      const { path } = rawArgs as { path: string };
      const report = await parsePeResources(workspace, path);
      return {
        types: report.types,
        ...(report.versionInfo === null ? {} : { versionInfo: report.versionInfo }),
        ...(report.manifestPreview === null ? {} : { manifestPreview: report.manifestPreview }),
        manifestTruncated: report.manifestTruncated,
        truncated: report.truncated,
      };
    },
  },
  {
    id: "binary.patch",
    toolName: "binary_patch",
    description:
      "Write bytes at a file offset into a COPY of the sample — the original is never modified. Returns the patched-path (under .minusone/exports/ by default, or a caller-chosen writable path), both sha256 hashes, and a per-patch diff (original bytes vs patched bytes). This is the act operation: patch a byte, then run the patched copy via sample_execute (dynamic-gated) to confirm the behavior change. Offset-based and portable (no PE parser); bounds-checked. Multiple patches are applied in one pass.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        patches: {
          type: "array",
          minItems: 1,
          maxItems: 64,
          items: {
            type: "object",
            properties: {
              offset: { type: "integer", minimum: 0, description: "File offset (decimal) to write at" },
              bytes: { type: "string", description: 'Hex bytes to write, e.g. "9090" (NOP NOP) or "eb" (jmp short)' },
            },
            required: ["offset", "bytes"],
            additionalProperties: false,
          },
        },
        outputPath: { type: "string", description: "Optional writable workspace path for the patched copy (default: .minusone/exports/<stem>-patched-<sha8><ext>)" },
      },
      required: ["path", "patches"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        patchedPath: { type: "string" },
        originalSha256: { type: "string" },
        patchedSha256: { type: "string" },
        bytes: { type: "integer" },
        patchesApplied: { type: "integer" },
        diff: { type: "array", items: { type: "object" } },
      },
      required: ["patchedPath", "originalSha256", "patchedSha256", "bytes", "patchesApplied", "diff"],
    },
    provider: "pe-patch",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, patches, outputPath } = rawArgs as {
        path: string;
        patches: Array<{ offset: number; bytes: string }>;
        outputPath?: string;
      };
      const result = await patchBinary(services.workspace, path, patches, outputPath);
      return {
        patchedPath: result.patchedPath,
        originalSha256: result.originalSha256,
        patchedSha256: result.patchedSha256,
        bytes: result.bytes,
        patchesApplied: result.patchesApplied,
        diff: result.diff,
        next: "run the patched copy via sample_execute (dynamic-gated) to confirm the behavior change; the original at the given path is untouched",
      };
    },
  },
  {
    id: "pe.rebuild",
    toolName: "pe_rebuild",
    description:
      "Reconstruct a loadable PE from a pe-sieve memory dump (the dumpDir output of dynamic_unpack) with LIEF: transplants the original sample's import table when the dump lost it, normalizes section raw sizes, and rebuilds the import directory — the Scylla workflow without the GUI. Best-effort by design (IAT reconstruction after unpacking is an art); the report lists every repair. The rebuilt PE lands under .minusone/exports/ (or a chosen writable path); the dump and original are never modified. Purely static — the container never executes anything.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Workspace-relative path to the pe-sieve dump (.exe of the dumped module)" },
        originalPath: { type: "string", description: "Workspace-relative path to the ORIGINAL sample — the import donor when the dump's import table is destroyed" },
        outputPath: { type: "string", description: "Optional writable path for the rebuilt PE (default: .minusone/exports/<stem>.rebuilt.exe)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        rebuiltPath: { type: "string" },
        bytes: { type: "integer" },
        sha256: { type: "string" },
        report: { type: "object" },
        next: { type: "string" },
      },
      required: ["rebuiltPath", "bytes", "sha256", "report", "next"],
    },
    provider: "pe-tools-lief",
    timeoutMs: 360_000,
    execute: async (rawArgs, services) => {
      const { path, originalPath, outputPath } = rawArgs as {
        path: string;
        originalPath?: string;
        outputPath?: string;
      };
      const result = await rebuildPe(services.workspace, path, {
        ...(originalPath === undefined ? {} : { originalPath }),
        ...(outputPath === undefined ? {} : { outputPath }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
      return {
        rebuiltPath: result.rebuiltPath,
        bytes: result.bytes,
        sha256: result.sha256,
        report: result.report,
        next: "verify the rebuilt PE with binary_triage / binary_find, or run it via sample_execute (dynamic-gated); strings_extract_deep (FLOSS) now works on the rebuilt image",
      };
    },
  },
  {
    id: "ida.functions",
    toolName: "ida_functions",
    description:
      "Submit an IDA Pro headless analysis (idat batch, Hex-Rays included) as a background job and list the functions it recovers — names, start/end addresses, sizes, basic-block counts, plus import modules and exports in the overview. IDA's FLIRT/DWARF symbol recovery finds what radare2 misses in complex binaries. Requires a licensed local IDA (MINUSONE_IDAT_PATH / MINUSONE_IDA_HOME; standard 'IDA Professional' install is auto-detected). Static: the sample is disassembled by IDA, never executed. The full JSON lands in an artifact; poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        functionFilter: { type: "string", description: "Substring (name or hex address) the function list is filtered by" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 3600 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "idat",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, functionFilter, timeoutSeconds } = rawArgs as { path: string; functionFilter?: string; timeoutSeconds?: number };
      if (!services.jobs) {
        throw new Error("ida_functions requires a background job registry; this host does not provide one.");
      }
      const sample = await inspectBinary(services.workspace, path);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "ida.functions",
        idat: resolveIdatCached(),
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `ida functions ${path}`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as Record<string, unknown>;
            return {
              status: "completed" as const,
              output:
                JSON.stringify(
                  {
                    backend: "cached",
                    ...summarizeIdaFunctions(report, functionFilter),
                    fullReport: { artifactId: cached.id, bytes: cached.bytes, cache: "reused" },
                  },
                  null,
                  2,
                ) + `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runIdaExport(services.workspace, path, {
            mode: "overview",
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "idat cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut || result.report === null) {
            return {
              status: "failed" as const,
              detail: `idat exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}${result.report === null ? "; no report was produced" : ""}; idat.log tail: ${(await readIdatLogTail(services.workspace, result.runDir)).slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "ida.functions",
            description: `IDA headless overview (${result.idatPath})`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: "idat",
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                backend: "idat",
                fileType: result.report.fileType ?? null,
                imageBase: result.report.imageBase ?? null,
                ...summarizeIdaFunctions(result.report, functionFilter),
                fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "idat",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "ida.decompile",
    toolName: "ida_decompile",
    description:
      "Submit an IDA Pro headless Hex-Rays decompilation as a background job: pseudocode for chosen functions (by name or hex address, e.g. \"main\" or \"0x140001450\"), bounded to 20000 chars per function, with caller cross-references. Use ida_functions first to find the names/addresses. Requires a licensed local IDA (auto-detected at the standard install). Static: the sample is never executed. Poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        targets: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 16,
          description: "Function names or hex entry addresses to decompile",
        },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 3600 },
      },
      required: ["path", "targets"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "idat",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, targets, timeoutSeconds } = rawArgs as { path: string; targets: string[]; timeoutSeconds?: number };
      if (!services.jobs) {
        throw new Error("ida_decompile requires a background job registry; this host does not provide one.");
      }
      const sample = await inspectBinary(services.workspace, path);
      const normalized = { targets: [...targets].sort() };
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        operation: "ida.decompile",
        ...normalized,
        idat: resolveIdatCached(),
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `ida decompile ${path} (${targets.length} target(s))`;
      const done = (async () => {
        try {
          if (cached !== null) {
            const report = JSON.parse(await readArtifactFull(services.workspace, cached.id)) as Record<string, unknown>;
            return {
              status: "completed" as const,
              output:
                JSON.stringify({ backend: "cached", decompilations: report.decompilations ?? [], fullReport: { artifactId: cached.id, bytes: cached.bytes, cache: "reused" } }, null, 2) +
                `\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runIdaExport(services.workspace, path, {
            mode: "decompile",
            targets,
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "idat cancelled" };
          }
          if (result.command.exitCode !== 0 || result.command.timedOut || result.report === null) {
            return {
              status: "failed" as const,
              detail: `idat exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}${result.report === null ? "; no report was produced" : ""}; idat.log tail: ${(await readIdatLogTail(services.workspace, result.runDir)).slice(0, 512)}`,
            };
          }
          const artifact = await storeArtifact(services.workspace, JSON.stringify(result.report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "ida.decompile",
            description: `IDA Hex-Rays decompilation (${targets.length} target(s))`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: "idat",
          });
          const decompilations = (result.report.decompilations ?? []) as Array<Record<string, unknown>>;
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                backend: "idat",
                decompiled: decompilations.map((entry) => ({
                  target: entry.target,
                  name: entry.name ?? null,
                  start: entry.start ?? null,
                  error: entry.error ?? null,
                  ...(entry.error === undefined ? { pseudocodePreview: typeof entry.pseudocode === "string" ? idaPreviewSlice(entry.pseudocode) : null, truncated: entry.truncated ?? false, callers: entry.callers ?? [] } : {}),
                })),
                fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" },
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "idat",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "dump.inspect",
    toolName: "dump_inspect",
    description:
      "Inspect a Windows user-mode minidump (crash dump, procdump/comsvcs capture) entirely offline: architecture, OS build, loaded modules with versions, threads with stack ranges, memory regions, and the exception record when present. Reading a dump never executes the captured process — this is the postmortem plane, not dynamic analysis.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        moduleFilter: { type: "string", description: "Substring filter for the module list (name substring)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        dumpKind: { type: "string" },
        architecture: { type: "string" },
        os: { type: "object" },
        timestamp: { type: "integer" },
        exception: { type: "object" },
        moduleCountTotal: { type: "integer" },
        modules: { type: "array", items: { type: "object" } },
        threadCountTotal: { type: "integer" },
        threads: { type: "array", items: { type: "object" } },
        memory: { type: "object" },
        streams: { type: "array", items: { type: "object" } },
        truncated: { type: "boolean" },
        bytes: { type: "integer" },
      },
      required: ["dumpKind", "architecture", "os", "moduleCountTotal", "modules", "threadCountTotal", "threads", "memory", "streams", "truncated", "bytes"],
    },
    provider: "minidump-parser",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace }) => {
      const { path, moduleFilter } = rawArgs as { path: string; moduleFilter?: string };
      const report = await inspectMinidump(workspace, path);
      const needle = moduleFilter?.toLowerCase();
      const modules = needle === undefined || needle === ""
        ? report.modules
        : report.modules.filter((module) => module.name.toLowerCase().includes(needle));
      return {
        dumpKind: report.dumpKind,
        timestamp: report.timestamp ?? 0,
        architecture: report.architecture,
        os: report.os,
        ...(report.exception === null ? {} : { exception: report.exception }),
        moduleCountTotal: report.moduleCountTotal,
        modules,
        threadCountTotal: report.threadCountTotal,
        threads: report.threads,
        memory: report.memory,
        streams: report.streams,
        truncated: report.truncated || modules.length < report.modules.length,
        bytes: report.bytes,
      };
    },
  },
  {
    id: "trace.procmon",
    toolName: "trace_procmon",
    description:
      "Parse a Process Monitor (Procmon) CSV export offline and summarize it: event count and time range, top processes with PIDs, operation and result histograms, path-category buckets (filesystem/registry/network/process), and the busiest paths. Optional substring filters on process name, operation, and path narrow the trace before summarizing; maxEvents bounds how many rows are read. The trace is data — nothing in it is executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        filterProcess: { type: "string", description: "Case-insensitive substring filter on the process name" },
        filterOperation: { type: "string", description: "Case-insensitive substring filter on the operation (e.g. WriteFile, RegSet, TCP)" },
        filterPath: { type: "string", description: "Case-insensitive substring filter on the path" },
        maxEvents: { type: "integer", minimum: 1, maximum: 1000000 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        eventCount: { type: "integer" },
        scannedEvents: { type: "integer" },
        parseErrors: { type: "integer" },
        truncated: { type: "boolean" },
        timeRange: { type: "object" },
        processes: { type: "array", items: { type: "object" } },
        operations: { type: "array", items: { type: "object" } },
        results: { type: "array", items: { type: "object" } },
        pathCategories: { type: "array", items: { type: "object" } },
        topPaths: { type: "array", items: { type: "object" } },
      },
      required: ["eventCount", "scannedEvents", "parseErrors", "truncated", "processes", "operations", "results", "pathCategories", "topPaths"],
    },
    provider: "procmon-parser-native",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace }) => {
      const { path: tracePath, filterProcess, filterOperation, filterPath, maxEvents } = rawArgs as {
        path: string;
        filterProcess?: string;
        filterOperation?: string;
        filterPath?: string;
        maxEvents?: number;
      };
      const report = await parseProcmonTrace(workspace, tracePath, {
        ...(filterProcess === undefined ? {} : { filterProcess }),
        ...(filterOperation === undefined ? {} : { filterOperation }),
        ...(filterPath === undefined ? {} : { filterPath }),
        ...(maxEvents === undefined ? {} : { maxEvents }),
      });
      return {
        eventCount: report.eventCount,
        scannedEvents: report.scannedEvents,
        parseErrors: report.parseErrors,
        truncated: report.truncated,
        ...(report.timeRange === null ? {} : { timeRange: report.timeRange }),
        processes: report.processes,
        operations: report.operations,
        results: report.results,
        pathCategories: report.pathCategories,
        topPaths: report.topPaths,
      };
    },
  },
  {
    id: "memory.volatility",
    toolName: "memory_volatility",
    description:
      "Analyze a full memory capture (raw/dd/lime image, Windows crash dump) offline with Volatility 3: pick read-only DFIR plugins from the whitelist (windows.info for OS identification, windows.pslist/pstree/cmdline for processes, windows.netscan for network artifacts, windows.malfind for injected code, windows.registry.hivelist, windows.filescan, ...). The capture is never executed; the container runs with no network and kernel symbols come from the host cache. Whole-image scans (malfind, filescan) take minutes — background job: poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        plugins: {
          type: "array",
          items: { type: "string", enum: [...VOLATILITY_PLUGINS] },
          maxItems: VOLATILITY_MAX_PLUGINS_PER_RUN,
          description: "Volatility 3 plugins to run (default: windows.info)",
        },
        maxRows: { type: "integer", minimum: 1, maximum: VOLATILITY_MAX_ROWS_HARD_CAP, description: "Row cap per plugin table (default 200)" },
        timeoutSeconds: { type: "integer", minimum: VOLATILITY_MIN_TIMEOUT_SECONDS, maximum: VOLATILITY_MAX_TIMEOUT_SECONDS, description: "Total budget, split across plugins (default 900)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "volatility3",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path: imagePath, plugins, maxRows, timeoutSeconds } = rawArgs as {
        path: string;
        plugins?: string[];
        maxRows?: number;
        timeoutSeconds?: number;
      };
      if (!services.jobs) {
        throw new Error("memory_volatility requires a background job registry; this host does not provide one.");
      }
      const selected = validateVolatilityPlugins(plugins);
      const normalizedMaxRows = Math.min(Math.max(maxRows ?? VOLATILITY_DEFAULT_MAX_ROWS, 1), VOLATILITY_MAX_ROWS_HARD_CAP);
      const sample = await inspectBinary(services.workspace, imagePath);
      const cacheKey = cacheKeyDigest({
        sample: sample.sha256,
        options: { plugins: selected, maxRows: normalizedMaxRows },
        image: resolveDockerImage(process.env.MINUSONE_VOLATILITY_IMAGE, DEFAULT_IMAGES.volatility3),
        local: process.env.MINUSONE_VOLATILITY_BIN ?? null,
        schema: 1,
      });
      const cached = await findArtifactByCacheKey(services.workspace, cacheKey);
      const abort = new AbortController();
      const label = `volatility ${path.basename(imagePath)} [${selected.join(", ")}]`;
      const done = (async () => {
        try {
          if (cached !== null) {
            return {
              status: "completed" as const,
              output: `${await readArtifactFull(services.workspace, cached.id)}\n[cache: reused artifact ${cached.id}]`,
            };
          }
          const result = await runVolatilityPlugins(services.workspace, imagePath, {
            plugins: selected,
            maxRows: normalizedMaxRows,
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (abort.signal.aborted) {
            return { status: "killed" as const, detail: "volatility run cancelled" };
          }
          const report = {
            schema: 1,
            backend: result.backend,
            backendPath: result.backendPath,
            image: services.workspace.relative(await services.workspace.resolveFile(imagePath)),
            sampleId: sample.sampleId,
            plugins: result.plugins,
            next: "drill into a table with a follow-up run (e.g. windows.malfind after pslist flags a suspicious PID); page large histories with smaller maxRows",
          };
          const artifact = await storeArtifact(services.workspace, JSON.stringify(report, null, 2), {
            mediaType: "application/json",
            sourceOperation: "memory.volatility",
            description: `Volatility 3 report: ${selected.join(", ")} over ${report.image} (${result.backend} backend)`,
            sampleId: sample.sampleId,
            cacheKey,
            backend: result.backend,
          });
          return {
            status: "completed" as const,
            output: `${JSON.stringify(report, null, 2)}\n[artifact: ${artifact.id} — page with artifact_read]`,
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "volatility",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels`,
      };
    },
  },
  {
    id: "report.correlate",
    toolName: "report_correlate",
    description:
      "Correlate evidence collected across the planes into one bounded report: a Procmon CSV trace (the same input trace_procmon accepts), the persisted Frida call log (the callLogPath reported by dynamic_frida), a pe-sieve dump directory (the dumpDir from dynamic_unpack), a debug transcript artifact (the artifactId from debug_session_close), and the sample itself (samplePath: mines static IOCs — URLs/IPs/registry/PDB/UNC — and imports, then cross-references them against every dynamic source present). Produces cross-referenced network endpoints, file paths touched by more than one source, persistence points, the dumped module list, the debug command history, and confirmed static↔dynamic evidence. Reads workspace data only — nothing is executed.",
    parameters: {
      type: "object",
      properties: {
        procmonPath: { type: "string", description: "Procmon CSV export" },
        fridaLogPath: { type: "string", description: "frida-call-events.json persisted by dynamic_frida (its callLogPath)" },
        dumpDirPath: { type: "string", description: "Dump directory produced by dynamic_unpack (its dumpDir)" },
        transcriptArtifactId: { type: "string", description: "Artifact id returned by debug_session_close" },
        samplePath: { type: "string", description: "The sample itself — static IOCs and imports cross-referenced against the dynamic sources" },
        maxEvents: { type: "integer", minimum: 1, maximum: 100000, description: "Cap on Procmon events read (default 100000)" },
        maxScanBytes: { type: "integer", minimum: 1024, description: "Static-anchor string window (default 33554432 = 32MB; no ceiling)" },
      },
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        schema: { type: "integer" },
        sources: { type: "object" },
        networkEndpoints: { type: "array", items: { type: "object" } },
        fileActivity: { type: "array", items: { type: "object" } },
        persistence: { type: "array", items: { type: "object" } },
        dumps: { type: "array", items: { type: "object" } },
        transcriptCommands: { type: "array", items: { type: "string" } },
        staticDynamic: { type: "object" },
      },
      required: ["schema", "sources", "networkEndpoints", "fileActivity", "persistence", "dumps", "transcriptCommands", "staticDynamic"],
    },
    provider: "correlate-native",
    timeoutMs: 120_000,
    execute: async (rawArgs, { workspace }) => {
      const { procmonPath, fridaLogPath, dumpDirPath, transcriptArtifactId, samplePath, maxEvents, maxScanBytes } = rawArgs as {
        procmonPath?: string;
        fridaLogPath?: string;
        dumpDirPath?: string;
        transcriptArtifactId?: string;
        samplePath?: string;
        maxEvents?: number;
        maxScanBytes?: number;
      };
      return await correlateEvidence(workspace, {
        ...(procmonPath === undefined ? {} : { procmonPath }),
        ...(fridaLogPath === undefined ? {} : { fridaLogPath }),
        ...(dumpDirPath === undefined ? {} : { dumpDirPath }),
        ...(transcriptArtifactId === undefined ? {} : { transcriptArtifactId }),
        ...(samplePath === undefined ? {} : { samplePath }),
        ...(maxEvents === undefined ? {} : { maxEvents }),
        ...(maxScanBytes === undefined ? {} : { maxScanBytes }),
      });
    },
  },
  {
    id: "config.extract",
    toolName: "config_extract",
    description:
      "Heuristic malware-configuration extraction — the C2/mutex/campaign/key harvest that takes an analyst an hour of strings reading. Sources the sample's DECODED strings first (FLOSS: obfuscated configs are the norm), falls back to plain static strings. Every field — C2 endpoints (host:port, URLs), mutexes, registry persistence keys, campaign/build IDs, PDB paths, XOR/password-like keys, base64-decoded blobs — carries its evidence trail (which string, which decoder VA) and a confidence label: OBSERVED-as-data, never confirmed behavior. Family signatures (AsyncRAT/Quasar/XWorm/Remcos/njRAT/Warzone/UPX) frame the report when they match. Static: the sample is never executed.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        useFloss: { type: "boolean", description: "Use the FLOSS decoded-strings plane when available (default true — plain strings miss obfuscated configs)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 1800, description: "FLOSS timeout (default 900)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        sha256: { type: "string" },
        families: { type: "array", items: { type: "object" } },
        fields: { type: "array", items: { type: "object" } },
        fieldCount: { type: "integer" },
        extractionDepth: { type: "string", enum: ["floss", "static-strings"] },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["path", "sha256", "families", "fields", "fieldCount", "extractionDepth", "notes", "next"],
    },
    provider: "config-heuristics",
    timeoutMs: 600_000,
    execute: async (rawArgs, services) => {
      const { path, useFloss, timeoutSeconds } = rawArgs as { path: string; useFloss?: boolean; timeoutSeconds?: number };
      return extractConfig(services.workspace, path, {
        ...(useFloss === undefined ? {} : { useFloss }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
    },
  },
  {
    id: "symbolic.solve",
    toolName: "symbolic_solve",
    description:
      "The keygen question, answered by symbolic execution: WHICH INPUTS reach the target address? angr (docker, --network none) loads the sample as DATA and explores it concolically — the sample never executes on the host. Give the address (or symbol) that means 'input accepted' (the success branch of the validator) and optionally the 'rejected' addresses to prune; model the input as argv (pass args:[\"SYMBOL\"]) or as N symbolic stdin bytes (stdinLen). Returns concrete solutions that reach the target plus the register state at arrival — then VERIFY by running the sample with the input (console.send or sample.execute): the solver proves reachability, not semantics. The tool class that attacks obfuscated megaprocedures directly, where decompilers time out. Background job: poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        target: { type: "string", description: "Address (hex like 0x4012f0 or decimal) or symbol name that means the input is ACCEPTED" },
        avoid: { type: "array", items: { type: "string" }, maxItems: 16, description: "Addresses/symbols meaning 'rejected' — prunes the search" },
        stdinLen: { type: "integer", minimum: 0, maximum: 64, description: "Model the input as N symbolic stdin bytes (mutually exclusive with args SYMBOL)" },
        args: { type: "array", items: { type: "string" }, maxItems: 8, description: "argv entries; the literal \"SYMBOL\" becomes a symbolic string (up to 64 chars)" },
        maxStates: { type: "integer", minimum: 10, maximum: 20000, description: "Exploration budget in found states (default 2000)" },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 1800, description: "Solving budget (default 300)" },
      },
      required: ["path", "target"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status"],
    },
    provider: "symbolic-angr",
    execute: async (rawArgs, services) => {
      const { path, target, avoid, stdinLen, args, maxStates, timeoutSeconds } = rawArgs as {
        path: string;
        target: string;
        avoid?: string[];
        stdinLen?: number;
        args?: string[];
        maxStates?: number;
        timeoutSeconds?: number;
      };
      return submitOperationJob(services, "symbolic-solve", `angr ${path} → ${target}`, (signal) =>
        symbolicSolve(services.workspace, path, {
          target,
          ...(avoid === undefined ? {} : { avoid }),
          ...(stdinLen === undefined ? {} : { stdinLen }),
          ...(args === undefined ? {} : { args }),
          ...(maxStates === undefined ? {} : { maxStates }),
          ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
          signal,
        }),
      );
    },
  },
  {
    id: "symbolic.simplify",
    toolName: "symbolic_simplify",
    description:
      "Collapse and PROVE MBA (mixed boolean arithmetic) expressions with z3: the (x ^ y) + 2*(x & y) walls obfuscators emit become x + y. Give the expression (python syntax over the named vars: ^ & | ~ + - * << >>) and its free variables. The strong half of the contract is `candidate`: pass your guessed simpler form (\"x + y\") and z3 PROVES equivalence ForAll — true/false on every input, not vibes. Use it on the raw pseudocode expressions of an obfuscated validator before reading them.",
    parameters: {
      type: "object",
      properties: {
        expression: { type: "string", maxLength: 4000, description: 'Expression in python syntax, e.g. "(x ^ y) + 2*(x & y)"' },
        vars: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8, description: "Free variables of the expression" },
        bits: { type: "integer", minimum: 8, maximum: 64, description: "Bit width (default 32)" },
        candidate: { type: "string", maxLength: 4000, description: 'Guessed simpler form to PROVE equal, e.g. "x + y" — the response carries candidateEquivalent: true/false (z3 ForAll)' },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 600, description: "Budget (default 120)" },
      },
      required: ["expression", "vars"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        backend: { type: "string" },
        original: { type: "string" },
        simplified: { type: "string" },
        candidate: { type: "string" },
        candidateEquivalent: { type: "boolean" },
        equivalenceChecked: { type: "boolean" },
        equivalent: { type: "boolean" },
        notes: { type: "array", items: { type: "string" } },
        error: { type: "string" },
      },
      required: ["status", "backend"],
    },
    provider: "symbolic-claripy",
    timeoutMs: 660_000,
    execute: async (rawArgs, services) => {
      const { expression, vars, bits, candidate, timeoutSeconds } = rawArgs as {
        expression: string;
        vars: string[];
        bits?: number;
        candidate?: string;
        timeoutSeconds?: number;
      };
      return await symbolicSimplify(services.workspace, {
        expression,
        vars,
        ...(bits === undefined ? {} : { bits }),
        ...(candidate === undefined ? {} : { candidate }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
    },
  },
  {
    id: "emu.run",
    toolName: "emu_run",
    description:
      "Emulate a code snippet with the Unicorn engine — the SAFE way to run untrusted logic: a CPU with mapped memory WE control, no process, no syscalls, nothing to escape from (docker, --network none). The canonical workflow: binary_find the decryptor stub (kind bytes) → carve the bytes → emu_run with the encrypted blob mapped as data → read the decrypted output from the returned memory regions. Also runs shellcode for triage (what does it compute?). Returns final registers, post-run memory for every mapping, and a SHORT trace preview — the full per-instruction trace goes to an artifact (page with artifact_read) so a long run never overflows context. base, data sizes AND data addresses are AUTO-ALIGNED to 4KB (Unicorn requirement; the notes field reports wrapper-side roundings, the runner handles the rest — payload writes and read-backs always target the address YOU gave). Sentinel: a bare `ret` at the end of the snippet lands on the stop condition automatically (a return address pointing at the until-address is pushed) — no stack wiring needed. The job never touches disk on the host.",
    parameters: {
      type: "object",
      properties: {
        arch: { type: "string", enum: ["x86", "x64"], description: "CPU mode (default x86)" },
        codeHex: { type: "string", description: "Code bytes as hex, executed at the entry point" },
        base: { type: "string", description: "Code mapping base address (default 0x100000)" },
        entryOffset: { type: "integer", minimum: 0, description: "Entry offset inside the code mapping (default 0)" },
        runAddress: { type: "string", description: "Start address override (default base + entryOffset)" },
        until: { type: "string", description: "Stop address (default: end of the code mapping)" },
        data: {
          type: "array",
          maxItems: 16,
          items: {
            type: "object",
            properties: {
              address: { type: "string", description: "Mapping address, e.g. 0x200000" },
              bytesHex: { type: "string", description: "Initial bytes (hex) — the encrypted blob, a buffer, etc." },
              size: { type: "integer", minimum: 1, description: "Mapping size in bytes (default: payload length or 4096)" },
            },
            required: ["address"],
            additionalProperties: false,
          },
          description: "Data mappings: inputs (encrypted blobs) and outputs (write buffers) — post-run contents are returned",
        },
        registers: { type: "object", description: "Initial register values, e.g. {\"ecx\": \"0x10\", \"esi\": \"0x200000\"} — x86: eax..eip; x64: rax..rip plus r8–r15 (the compiled-code loop/calling-convention registers)" },
        timeoutUs: { type: "integer", minimum: 1000, description: "Emulation timeout in microseconds (default 1000000)" },
        count: { type: "integer", minimum: 1, description: "Max instructions (default 10000000)" },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 300, description: "Command timeout (default 60)" },
      },
      required: ["codeHex"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        error: { type: "string", description: "null when status is ok" },
        arch: { type: "string" },
        registers: { type: "object" },
        memory: { type: "array", items: { type: "object" } },
        traceHead: { type: "array", items: { type: "object" } },
        traceTruncated: { type: "boolean" },
        traceArtifact: { type: "object" },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["status", "arch", "registers", "memory", "traceHead", "traceTruncated", "traceArtifact", "notes"],
    },
    provider: "unicorn",
    timeoutMs: 300_000,
    execute: async (rawArgs, services) => {
      const { arch, codeHex, base, entryOffset, runAddress, until, data, registers, timeoutUs, count, timeoutSeconds } = rawArgs as {
        arch?: "x86" | "x64";
        codeHex: string;
        base?: string;
        entryOffset?: number;
        runAddress?: string;
        until?: string;
        data?: Array<{ address: string; bytesHex?: string; size?: number }>;
        registers?: Record<string, string>;
        timeoutUs?: number;
        count?: number;
        timeoutSeconds?: number;
      };
      return runEmulation({
        codeHex,
        ...(arch === undefined ? {} : { arch }),
        ...(base === undefined ? {} : { base }),
        ...(entryOffset === undefined ? {} : { entryOffset }),
        ...(runAddress === undefined ? {} : { runAddress }),
        ...(until === undefined ? {} : { until }),
        ...(data === undefined ? {} : { data }),
        ...(registers === undefined ? {} : { registers }),
        ...(timeoutUs === undefined ? {} : { timeoutUs }),
        ...(count === undefined ? {} : { count }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      }, services.workspace);
    },
  },
  {
    id: "emu.chain",
    toolName: "emu_chain",
    description:
      "Multi-step stateful emulation — the crypto-chain workhorse. One docker session, one CPU instance: MEMORY AND REGISTERS CARRY ACROSS STEPS. The class it serves: 'init → key schedule → encrypt' sequences (the universal shape of crypto code) where today each function must be emulated separately with state ferried between runs through files. Give steps [{codeHex, registers, until, ...}] (max 16, each step's code is written at the shared base); data mappings and initial registers are set once and persist. Per-step results: registers, memory, a short trace head. The chain stops at the first failed step (state past a failure is garbage) — stepsCompleted tells you how far it got. The full per-step trace heads go to an artifact (page with artifact_read). Same safety model as emu_run: no process, no syscalls, docker --network none.",
    parameters: {
      type: "object",
      properties: {
        arch: { type: "string", enum: ["x86", "x64"], description: "CPU mode (default x86)" },
        base: { type: "string", description: "Code mapping base address shared by every step (default 0x100000)" },
        data: {
          type: "array",
          maxItems: 16,
          items: {
            type: "object",
            properties: {
              address: { type: "string", description: "Mapping address, e.g. 0x200000" },
              bytesHex: { type: "string", description: "Initial bytes (hex) — the encrypted blob, a buffer, etc." },
              size: { type: "integer", minimum: 1, description: "Mapping size in bytes (default: payload length or 4096)" },
            },
            required: ["address"],
            additionalProperties: false,
          },
          description: "Data mappings shared by ALL steps — post-run contents are returned per step",
        },
        registers: { type: "object", description: "Initial register values applied before step 1, e.g. {\"rcx\": \"0x10\"} — x86: eax..eip; x64: rax..rip plus r8–r15" },
        steps: {
          type: "array",
          minItems: 1,
          maxItems: 16,
          items: {
            type: "object",
            properties: {
              codeHex: { type: "string", description: "Code bytes (hex) for THIS step, written at the chain's base" },
              entryOffset: { type: "integer", minimum: 0, description: "Entry offset inside the code mapping for this step (default 0)" },
              runAddress: { type: "string", description: "Start address override for this step (default base + entryOffset)" },
              until: { type: "string", description: "Stop address for this step (default: end of the code mapping)" },
              registers: { type: "object", description: "Register values applied before this step — state carries across steps" },
              timeoutUs: { type: "integer", minimum: 1000, description: "Emulation timeout in microseconds for this step (default 1000000)" },
              count: { type: "integer", minimum: 1, description: "Max instructions for this step (default 10000000)" },
            },
            required: ["codeHex"],
            additionalProperties: false,
          },
          description: "The chain: each step's code runs at the shared base with carried state",
        },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 300, description: "Command timeout (default 60)" },
      },
      required: ["steps"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        error: { type: "string", description: "null when status is ok" },
        arch: { type: "string" },
        stepsCompleted: { type: "integer", description: "How many steps ran ok before the chain stopped" },
        steps: { type: "array", items: { type: "object" } },
        stepsArtifact: { type: "object" },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["status", "arch", "stepsCompleted", "steps", "stepsArtifact", "notes"],
    },
    provider: "unicorn",
    timeoutMs: 300_000,
    execute: async (rawArgs, services) => {
      const { arch, base, data, registers, steps, timeoutSeconds } = rawArgs as {
        arch?: "x86" | "x64";
        base?: string;
        data?: Array<{ address: string; bytesHex?: string; size?: number }>;
        registers?: Record<string, string>;
        steps: Array<{ codeHex: string; entryOffset?: number; runAddress?: string; until?: string; registers?: Record<string, string>; timeoutUs?: number; count?: number }>;
        timeoutSeconds?: number;
      };
      return runEmulationChain({
        steps,
        ...(arch === undefined ? {} : { arch }),
        ...(base === undefined ? {} : { base }),
        ...(data === undefined ? {} : { data }),
        ...(registers === undefined ? {} : { registers }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      }, services.workspace);
    },
  },
  {
    id: "emu.diff",
    toolName: "emu_diff",
    description:
      "The reconstruction oracle — 'is my reimplementation byte-identical to THEIRS?'. Give THEIR carved function (codeHex, run under Unicorn) plus YOUR python reimplementation; the operation emulates both against the same inputs and reports the FIRST DIVERGING BYTE (offset, their value, your value) and the full divergence profile. The class it serves: crypto/parser reconstruction where every component verifies in isolation but the composed result fails — instead of re-verifying algorithms a third time, one call points at the exact wrong byte. Your snippet runs in the same sandboxed container with `mem` (address int → ORIGINAL input bytes), `regs` (name → int), `struct`, and whitelisted builtins; it must assign `out = bytes(...)`. Point outputAddress at the window their code writes its result to. No process, no syscalls, docker --network none.",
    parameters: {
      type: "object",
      properties: {
        arch: { type: "string", enum: ["x86", "x64"], description: "CPU mode (default x86)" },
        codeHex: { type: "string", description: "THEIR function — carved code bytes (hex), emulated under Unicorn" },
        base: { type: "string", description: "Code mapping base address (default 0x100000)" },
        entryOffset: { type: "integer", minimum: 0, description: "Entry offset inside the code mapping (default 0)" },
        runAddress: { type: "string", description: "Start address override for the reference run (default base + entryOffset)" },
        until: { type: "string", description: "Stop address for the reference run (default: end of the code mapping)" },
        data: {
          type: "array",
          maxItems: 16,
          items: {
            type: "object",
            properties: {
              address: { type: "string", description: "Mapping address, e.g. 0x200000" },
              bytesHex: { type: "string", description: "Initial bytes (hex) — the input blob" },
              size: { type: "integer", minimum: 1, description: "Mapping size in bytes (default: payload length or 4096)" },
            },
            required: ["address"],
            additionalProperties: false,
          },
          description: "Input mappings — YOUR candidate sees the ORIGINAL bytes via mem[address]",
        },
        registers: { type: "object", description: "Initial register values shared by both sides, e.g. {\"esi\": \"0x200000\", \"ecx\": \"4\"}" },
        candidatePython: { type: "string", description: "YOUR reimplementation — python source with `mem`, `regs`, `struct`, whitelisted builtins; must assign `out = bytes(...)`" },
        outputAddress: { type: "string", description: "The window THEIR code writes its result to (must be a mapped address)" },
        outputLength: { type: "integer", minimum: 1, description: "Compare length (default: the mapping size at outputAddress)" },
        timeoutUs: { type: "integer", minimum: 1000, description: "Emulation timeout in microseconds (default 1000000)" },
        count: { type: "integer", minimum: 1, description: "Max instructions (default 10000000)" },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 300, description: "Command timeout (default 60)" },
      },
      required: ["codeHex", "candidatePython", "outputAddress"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        error: { type: "string", description: "null when status is ok" },
        arch: { type: "string" },
        match: { type: "boolean", description: "true when reference and candidate outputs are identical" },
        comparedBytes: { type: "integer" },
        referenceBytes: { type: "integer" },
        candidateBytes: { type: "integer" },
        lengthMismatch: { type: "boolean" },
        divergenceCount: { type: "integer" },
        firstDivergence: { type: "object", description: "{offset, referenceHex, candidateHex} or null when identical" },
        divergenceOffsets: { type: "array", items: { type: "integer" }, maxItems: 64 },
        reference: { type: "object", description: "final registers/stoppedAt of the reference run" },
        referenceOutputHex: { type: "string", description: "their output (first 512 bytes)" },
        candidateOutputHex: { type: "string", description: "your output (first 512 bytes)" },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["status", "arch", "match", "comparedBytes", "divergenceCount", "firstDivergence", "referenceOutputHex", "candidateOutputHex", "notes"],
    },
    provider: "unicorn",
    timeoutMs: 300_000,
    execute: async (rawArgs, services) => {
      const { arch, codeHex, base, entryOffset, runAddress, until, data, registers, candidatePython, outputAddress, outputLength, timeoutUs, count, timeoutSeconds } = rawArgs as {
        arch?: "x86" | "x64";
        codeHex: string;
        base?: string;
        entryOffset?: number;
        runAddress?: string;
        until?: string;
        data?: Array<{ address: string; bytesHex?: string; size?: number }>;
        registers?: Record<string, string>;
        candidatePython: string;
        outputAddress: string;
        outputLength?: number;
        timeoutUs?: number;
        count?: number;
        timeoutSeconds?: number;
      };
      return runEmulationDiff({
        codeHex,
        candidatePython,
        outputAddress,
        ...(arch === undefined ? {} : { arch }),
        ...(base === undefined ? {} : { base }),
        ...(entryOffset === undefined ? {} : { entryOffset }),
        ...(runAddress === undefined ? {} : { runAddress }),
        ...(until === undefined ? {} : { until }),
        ...(data === undefined ? {} : { data }),
        ...(registers === undefined ? {} : { registers }),
        ...(outputLength === undefined ? {} : { outputLength }),
        ...(timeoutUs === undefined ? {} : { timeoutUs }),
        ...(count === undefined ? {} : { count }),
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      }, services.workspace);
    },
  },
  {
    id: "binary.diff",
    toolName: "binary_diff",
    description:
      "Patch analysis between two versions of a binary — 'what changed in the update', 'where does the cracked build differ'. Byte-level diff with run-length changed regions, per-region sha256 and previews, PE section/RVA/VA context for every region (the report says .text @ RVA 0x140001234, not a raw offset), and agent symbols. The deep pass decompiles the changed .text regions with Ghidra so you see the code that differs. Same-size binaries = clean patch diff; wildly different sizes are flagged as a REBUILD with the honest advice to compare triage verdicts instead. Background job: poll with job_output (wait: true).",
    parameters: {
      type: "object",
      properties: {
        oldPath: { type: "string", description: "Old/original version (the baseline), workspace-relative" },
        newPath: { type: "string", description: "New/modified version, workspace-relative" },
        decompile: { type: "boolean", description: "Decompile changed code regions with Ghidra (default true)" },
        maxDecompiles: { type: "integer", minimum: 0, maximum: 4, description: "Regions to decompile (default 3)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 900, description: "Ghidra timeout (default 300)" },
      },
      required: ["oldPath", "newPath"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status"],
    },
    provider: "diff-native",
    execute: async (rawArgs, services) => {
      const { oldPath, newPath, decompile, maxDecompiles, timeoutSeconds } = rawArgs as {
        oldPath: string;
        newPath: string;
        decompile?: boolean;
        maxDecompiles?: number;
        timeoutSeconds?: number;
      };
      return submitOperationJob(services, "binary-diff", `diff ${oldPath} ↔ ${newPath}`, (signal) =>
        diffBinaries(services.workspace, {
          oldPath,
          newPath,
          ...(decompile === undefined ? {} : { decompile }),
          ...(maxDecompiles === undefined ? {} : { maxDecompiles }),
          ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
          signal,
        }),
      );
    },
  },
  {
    id: "memory.read",
    toolName: "memory_read",
    description:
      "The address plane: turn an address into bytes/decoded values with NO manual VA/RVA/offset arithmetic. File mode (path) resolves va ('0x140001000'), rva ('0x1000') or offset through the PE section table — positioned reads, fine for images of any size; the report always shows va+rva+offset+section together so one command teaches the mapping. Session mode (sessionId) reads a LIVE runtime address from a gdb or cdb session (ASLR included; use the runtime base the debugger reported). Decode: scalars (u8..f64, with elements=N for whole TABLES), cstr/utf16 strings. chasePointers follows in-image u32/u64 values (depth-limited) with section/symbol annotation at every hop — the manual pointer-table walk becomes one call. The classic 'one byte off and I patched the wrong place' trap is structurally closed.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Workspace-relative path (file mode)" },
        sessionId: { type: "string", description: "Debugger session id from debug_session_create (session mode)" },
        va: { type: "string", description: "Virtual address, hex ('0x140001000') or decimal" },
        rva: { type: "string", description: "Relative virtual address (file mode)" },
        offset: { type: "integer", minimum: 0, description: "Raw file offset (file mode)" },
        count: { type: "integer", minimum: 1, maximum: 4194304, description: "Bytes to read (default 64; for cstr/utf16 the max scan length)" },
        type: {
          type: "string",
          enum: ["u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "f32", "f64", "cstr", "utf16"],
          description: "Decode the window as this type instead of raw dump",
        },
        elements: { type: "integer", minimum: 1, description: "Element count for type decodes (default 1) — reads a whole TABLE in one call" },
        chasePointers: { type: "boolean", description: "Follow in-image pointer values with section/symbol annotation (file mode, type u32/u64)" },
      },
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["file", "session"] },
        path: { type: "string" },
        sessionId: { type: "string" },
        debugger: { type: "string" },
        address: { type: "object" },
        requestedBytes: { type: "integer" },
        readBytes: { type: "integer" },
        truncated: { type: "boolean" },
        hexdump: { type: "string" },
        hexdumpTruncated: { type: "boolean" },
        bytesHex: { type: "string" },
        ascii: { type: "string" },
        decode: { type: "object" },
        pointers: { type: "array", items: { type: "object" } },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["mode", "sessionId", "debugger", "address", "requestedBytes", "readBytes", "truncated", "hexdump", "hexdumpTruncated", "bytesHex", "ascii", "decode", "pointers", "notes", "next"],
    },
    provider: "pe-native",
    timeoutMs: 60_000,
    execute: async (rawArgs, { workspace }) => {
      const { path, sessionId, va, rva, offset, count, type, elements, chasePointers } = rawArgs as {
        path?: string;
        sessionId?: string;
        va?: string;
        rva?: string;
        offset?: number;
        count?: number;
        type?: "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" | "cstr" | "utf16";
        elements?: number;
        chasePointers?: boolean;
      };
      return readMemory(workspace, {
        ...(path === undefined ? {} : { path }),
        ...(sessionId === undefined ? {} : { sessionId }),
        ...(va === undefined ? {} : { va }),
        ...(rva === undefined ? {} : { rva }),
        ...(offset === undefined ? {} : { offset }),
        ...(count === undefined ? {} : { count }),
        ...(type === undefined ? {} : { type }),
        ...(elements === undefined ? {} : { elements }),
        ...(chasePointers === undefined ? {} : { chasePointers }),
      });
    },
  },
  {
    id: "batch.survey",
    toolName: "batch_survey",
    description:
      "ONE command → the complete structural table of one or several binaries as JSON: sections (with VA/RVA/offset per section), full import table (per-function IAT slots), full export table, entrypoint (RVA+VA), resource/version summary, annotated symbols (annotate.symbol), and — when a cached r2 listing exists — the function table with names. This is the hours-of-manual-browsing killer: no more walking the file in a hex editor. The inline answer is bounded; the FULL untruncated table of every file is stored as an artifact (page with artifact_read). Re-run after disassembly_functions to merge the function table; re-run after annotate_symbol to reflect new names.",
    parameters: {
      type: "object",
      properties: {
        paths: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 8,
          description: "Workspace-relative paths to survey (1..8 files per call)",
        },
      },
      required: ["paths"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        files: { type: "array", items: { type: "object" } },
        fileCount: { type: "integer" },
        notes: { type: "array", items: { type: "string" } },
        next: { type: "array", items: { type: "string" } },
      },
      required: ["files", "fileCount", "notes", "next"],
    },
    provider: "pe-native",
    timeoutMs: 120_000,
    execute: async (rawArgs, { workspace }) => {
      const { paths } = rawArgs as { paths: string[] };
      return surveyBinaries(workspace, paths);
    },
  },
  {
    id: "report.findings",
    toolName: "report_findings",
    description:
      "The analyst-facing case file: persist a conclusion (title, severity, notes, evidence artifact ids) that survives sessions, or list the findings already recorded in this workspace. Composite operations like binary_triage / unpack chains / correlate produce evidence; report_findings turns the conclusions into a durable record. Call with no arguments to list; with title+severity+notes to record (evidence is an optional list of artifact ids).",
    parameters: {
      type: "object",
      properties: {
        title: { type: "string", description: "Finding title (omit to list existing findings)" },
        severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
        notes: { type: "string", description: "What was concluded and why" },
        evidence: { type: "array", items: { type: "string" }, maxItems: 32, description: "Artifact ids backing this finding" },
      },
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        saved: { type: "object" },
        findings: { type: "array", items: { type: "object" } },
      },
      required: ["findings"],
    },
    provider: "artifacts-native",
    timeoutMs: 30_000,
    execute: async (rawArgs, { workspace }) => {
      const { title, severity, notes, evidence } = rawArgs as {
        title?: string;
        severity?: "info" | "low" | "medium" | "high" | "critical";
        notes?: string;
        evidence?: string[];
      };
      if (title !== undefined) {
        if (severity === undefined || notes === undefined) {
          throw new Error("saving a finding requires title, severity, and notes");
        }
        const stored = await storeFinding(workspace, {
          title,
          severity,
          notes,
          evidence: evidence ?? [],
        }, "report.findings");
        return {
          saved: { artifactId: stored.id, title, severity },
          findings: (await listFindings(workspace)).map(summarizeFinding),
        };
      }
      return { findings: (await listFindings(workspace)).map(summarizeFinding) };
    },
  },
  {
    id: "provider.report",
    toolName: "provider_report",
    description:
      "Report which reverse-engineering providers are available (objdump, Ghidra backends, Docker, debuggers) and the dynamic-analysis policy, without modifying the workspace.",
    parameters: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        platform: { type: "string" },
        readyForBaselineAnalysis: { type: "boolean" },
        readyForGhidra: { type: "boolean" },
        dynamicAnalysisPolicy: { type: "string" },
        capabilities: { type: "array", items: { type: "object" } },
      },
      required: ["platform", "readyForBaselineAnalysis", "readyForGhidra", "dynamicAnalysisPolicy", "capabilities"],
    },
    provider: "doctor",
    execute: async (_args, { workspace }) => createDoctorReport(workspace),
  },
  {
    id: "sample.execute",
    toolName: "sample_execute",
    description:
      "Execute a sample on the LOCAL dynamic target (requires MINUSONE_ALLOW_DYNAMIC=1 and MINUSONE_DYNAMIC_TARGET=local — owner-authorized; no network isolation applies). Runs it in an isolated run directory with a hard timeout, then reports exit code, stdout/stderr previews, duration behavior, and any files it dropped. stdin pipes UTF-8 text to the sample (interactive crackmes that read name/serial from the prompt — use \\n for line breaks). DLLs are hosted through rundll32 (DllMain runs; entryExport picks the export to call, default: first export). Submit as a background job; poll with job_output (wait: true); job_kill terminates the process tree. LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments passed to the sample (direct EXE spawn; disables rundll32 hosting)" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs and when args is set" },
        stdin: { type: "string", description: "UTF-8 text piped to the sample's stdin (interactive prompts: name/serial entry; \\n for line breaks)" },
        timeoutSeconds: { type: "integer", minimum: 5, maximum: 600 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "local-supervisor",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, args, entryExport, stdin, timeoutSeconds } = rawArgs as { path: string; args?: string[]; entryExport?: string; stdin?: string; timeoutSeconds?: number };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("sample.execute", services.workspace);
      if (!services.jobs) {
        throw new Error("sample_execute requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `exec ${path}${args !== undefined && args.length > 0 ? ` (${args.length} arg(s))` : ""}${stdin !== undefined ? " +stdin" : ""}`;
      const done = (async () => {
        try {
          const result = await executeSample(services.workspace, path, {
            ...(args === undefined ? {} : { args }),
            ...(entryExport === undefined || args !== undefined ? {} : { entryExport }),
            ...(stdin === undefined ? {} : { stdin }),
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          if (result.command.aborted) {
            return { status: "killed" as const, detail: "sample terminated by job_kill" };
          }
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                target: "local",
                exitCode: result.command.exitCode ?? -1,
                timedOut: result.command.timedOut,
                stdoutPreview: result.command.stdout.slice(0, 4096),
                stderrPreview: result.command.stderr.slice(0, 4096),
                outputTruncated: result.command.outputTruncated,
                runDir: result.runDir,
                droppedFiles: result.droppedFiles,
                ...(result.launchedVia === undefined ? {} : { launchedVia: result.launchedVia }),
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "exec",
        label,
        outputLimitBytes: 256 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill terminates the sample`,
      };
    },
  },
  {
    id: "console.launch",
    toolName: "console_launch",
    description:
      "Launch a console sample DETACHED so it keeps running with its own (hidden by default) console — the entry point of the interactive TUI loop. Full-screen TUIs (ratatui/crossterm, ncurses ports) read INPUT_RECORDs, not stdin bytes, so sample_execute's stdin pipe is dead for them: launch here, then drive the UI with console.send and read the screen with console.read (or console.send with readBack to do both in one call). The PID returned is what console.send/console.read attach to. Kill it with process.kill {pid} when done. Windows-only. Dynamic-gated: the sample executes.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments passed to the sample (direct EXE spawn; disables rundll32 hosting)" },
        visible: { type: "boolean", description: "Show the sample's console window (default false — the screen buffer is fully readable and drivable while hidden)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["launched", "refused"] },
        pid: { type: "integer" },
        runDir: { type: "string" },
        visible: { type: "boolean" },
        launchedVia: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "console-plane",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path: samplePath, args, visible } = rawArgs as { path: string; args?: string[]; visible?: boolean };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("console.launch", services.workspace);
      const launched = await launchDetachedSample(services.workspace, samplePath, {
        ...(args === undefined ? {} : { args }),
        ...(visible === undefined ? {} : { visible }),
      });
      return {
        status: "launched",
        pid: launched.pid,
        runDir: launched.runDir,
        visible: launched.visible,
        ...(launched.launchedVia === undefined ? {} : { launchedVia: launched.launchedVia }),
      };
    },
  },
  {
    id: "console.send",
    toolName: "console_send",
    description:
      "Type into the console of a LIVE detached process (from console.launch) via WriteConsoleInputW — the only way full-screen TUI crackmes accept input, because they read INPUT_RECORDs, not stdin bytes. Plain characters ride as Unicode key events; \\n (or enter:true) types Enter; special keys use {ENTER} {ESC} {TAB} {BACKSPACE} {DEL} {INS} {HOME} {END} {PGUP} {PGDN} {UP} {DOWN} {LEFT} {RIGHT} {F1}..{F12} {SPACE} {CTRL+X}. Set readBack:true to read the screen back in the same call (send → settle → read) — the round-trip loop for driving menus. Windows-only. NOT dynamic-gated: it only touches the console of an already-running process.",
    parameters: {
      type: "object",
      properties: {
        pid: { type: "integer", description: "PID of the detached process (from console.launch)", minimum: 1 },
        text: { type: "string", maxLength: 2000, description: "Text to type; \\n = Enter, {UP}/{ENTER}/... = special keys" },
        enter: { type: "boolean", description: "Append one Enter after the text (default false)" },
        readBack: { type: "boolean", description: "Read the screen back in the same call (send → settle → read); default true for the round-trip loop" },
        keyDelayMs: { type: "integer", minimum: 0, maximum: 500, description: "Delay between keystrokes (default 15ms; raise for sluggish TUIs)" },
        settleMs: { type: "integer", minimum: 0, maximum: 10000, description: "How long to wait for the TUI to redraw before reading back (default 400ms)" },
        maxRows: { type: "integer", minimum: 1, maximum: 200, description: "Screen rows to read back (default 200)" },
      },
      required: ["pid", "text"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        pid: { type: "integer" },
        attached: { type: "boolean" },
        keysSent: { type: "integer" },
        screen: { type: "object" },
        error: { type: "string" },
      },
      required: ["status", "pid"],
    },
    provider: "console-plane",
    timeoutMs: 120_000,
    execute: async (rawArgs, services) => {
      const { pid, text, enter, readBack, keyDelayMs, settleMs, maxRows } = rawArgs as {
        pid: number;
        text: string;
        enter?: boolean;
        readBack?: boolean;
        keyDelayMs?: number;
        settleMs?: number;
        maxRows?: number;
      };
      if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
        throw new Error("pid must be a positive integer — get one from console.launch");
      }
      const result = await sendConsoleInput(services.workspace, pid, text, {
        ...(enter === undefined ? {} : { enter }),
        readBack: readBack !== false,
        ...(keyDelayMs === undefined ? {} : { keyDelayMs }),
        ...(settleMs === undefined ? {} : { settleMs }),
        ...(maxRows === undefined ? {} : { maxRows }),
      });
      return {
        status: result.error === undefined ? "ok" : "error",
        pid: result.pid,
        attached: result.attached,
        keysSent: result.keysSent,
        ...(result.screen === undefined ? {} : { screen: result.screen }),
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "console.read",
    toolName: "console_read",
    description:
      "Read the screen of a LIVE detached process (from console.launch): ReadConsoleOutputCharacterW the console screen buffer as trimmed text rows plus cursor position and dimensions. This is how you see what a full-screen TUI (ratatui/crossterm, ncurses ports) currently shows — its stdout is not piped anywhere. Windows-only. NOT dynamic-gated: it only reads the console of an already-running process.",
    parameters: {
      type: "object",
      properties: {
        pid: { type: "integer", description: "PID of the detached process (from console.launch)", minimum: 1 },
        maxRows: { type: "integer", minimum: 1, maximum: 200, description: "Screen rows to read (default 200)" },
      },
      required: ["pid"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        pid: { type: "integer" },
        attached: { type: "boolean" },
        screen: { type: "object" },
        error: { type: "string" },
      },
      required: ["status", "pid"],
    },
    provider: "console-plane",
    timeoutMs: 60_000,
    execute: async (rawArgs, services) => {
      const { pid, maxRows } = rawArgs as { pid: number; maxRows?: number };
      if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
        throw new Error("pid must be a positive integer — get one from console.launch");
      }
      const result = await readConsoleScreen(services.workspace, pid, {
        ...(maxRows === undefined ? {} : { maxRows }),
      });
      return {
        status: result.error === undefined ? "ok" : "error",
        pid: result.pid,
        attached: result.attached,
        ...(result.screen === undefined ? {} : { screen: result.screen }),
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "process.kill",
    toolName: "process_kill",
    description:
      "Kill a process tree by PID (taskkill /T /F) — the cleanup path for processes launched detached by console.launch (the gdb debug session has debug.session.close for itself). NOT dynamic-gated: it terminates, it does not execute anything.",
    parameters: {
      type: "object",
      properties: {
        pid: { type: "integer", minimum: 1, description: "PID of the process tree to terminate" },
      },
      required: ["pid"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error"] },
        pid: { type: "integer" },
        error: { type: "string" },
      },
      required: ["status", "pid"],
    },
    provider: "console-plane",
    timeoutMs: 30_000,
    execute: async (rawArgs) => {
      const { pid } = rawArgs as { pid: number };
      if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
        throw new Error("pid must be a positive integer");
      }
      try {
        await killProcessTree(pid);
        return { status: "ok", pid };
      } catch (error) {
        return { status: "error", pid, error: error instanceof Error ? error.message : String(error) };
      }
    },
  },
  {
    id: "unpack.static",
    toolName: "unpack_static",
    description:
      "UPX static decompression — the seconds-fast path for UPX-packed samples (dynamic.unpack's pe-sieve route stays for everything else). Pure file transformation (upx -d): the sample is NEVER executed, so this is NOT dynamic-gated and needs no arming. Also serves as a probe: packed=false with upx's own refusal message means 'not UPX — use the dynamic path'. Local upx when present, else the pe-tools docker image. The unpacked copy lands under .minusone/unpack-static/<sampleId>/; triage it afterwards.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        timeoutSeconds: { type: "integer", minimum: 15, maximum: 600, description: "Timeout (default 120)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        packed: { type: "boolean" },
        outputPath: { type: "string", description: "null when packed=false" },
        outputSha256: { type: "string", description: "null when packed=false" },
        outputBytes: { type: "integer", description: "null when packed=false" },
        ratio: { type: "string", description: "null when unavailable" },
        command: { type: "object" },
        notes: { type: "array", items: { type: "string" } },
      },
      required: ["backend", "packed", "outputPath", "notes"],
    },
    provider: "upx",
    timeoutMs: 600_000,
    execute: async (rawArgs, services) => {
      const { path, timeoutSeconds } = rawArgs as { path: string; timeoutSeconds?: number };
      return unpackStatic(services.workspace, path, {
        ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
        ...(services.signal === undefined ? {} : { signal: services.signal }),
      });
    },
  },
  {
    id: "dynamic.unpack",
    toolName: "dynamic_unpack",
    description:
      "Run a sample on the LOCAL dynamic target for a bounded window (default 8s), then scan its memory with pe-sieve and dump replaced or implanted modules — the route to statically recovering the unpacked payload of packed samples without a GUI debugger. DLLs are hosted through rundll32 so DllMain (where packers unpack) executes; entryExport picks the export to call (default: first export). Requires MINUSONE_ALLOW_DYNAMIC=1 and MINUSONE_DYNAMIC_TARGET=local. Dumped files land under the job's run directory; analyze them with the static tools afterwards. Background job: poll with job_output (wait: true). LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        runSeconds: { type: "integer", minimum: 2, maximum: 120, description: "How long the sample runs before the memory scan" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "pe-sieve",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, runSeconds, entryExport } = rawArgs as { path: string; runSeconds?: number; entryExport?: string };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("dynamic.unpack", services.workspace);
      if (!services.jobs) {
        throw new Error("dynamic_unpack requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `unpack ${path}`;
      const done = (async () => {
        try {
          const result = await unpackSample(services.workspace, path, {
            ...(runSeconds === undefined ? {} : { runSeconds }),
            ...(entryExport === undefined ? {} : { entryExport }),
            signal: abort.signal,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                target: "local",
                pid: result.pid,
                stillRunningAtScan: result.stillRunningAtScan,
                launchedVia: result.launchedVia,
                runDir: result.runDir,
                dumpDir: result.dumpDir,
                dumpedFiles: result.dumpedFiles,
                sanitizedHeaders: result.sanitizedHeaders,
                sieveExitCode: result.sieve.exitCode ?? -1,
                sieveReport: result.sieve.stdout.slice(0, 8192),
                next: "run dumps_floss on dumpDir to auto-extract decoded strings from every dumped module; then point static tools (binary_inspect, strings_extract_deep, function_decompile) at individual dumps",
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "unpack",
        label,
        outputLimitBytes: 256 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill stops the sample`,
      };
    },
  },
  {
    id: "unpack.chain",
    toolName: "unpack_chain",
    description:
      "The packed-sample workflow as ONE call (dynamic-gated): pre-triage (packed verdict) → UPX static fast-path when the sample is UPX-packed (upx -d, seconds, no execution — skips the dynamic stages entirely) → otherwise run the sample and dump the unpacked image with pe-sieve (headers sanitized) → rebuild an analysis-grade PE from the dump with LIEF (imports restored) → re-triage the rebuilt image (strings/imports/IOCs now statically reachable). DLLs are hosted through rundll32 so DllMain (where packers unpack) executes; entryExport picks the export to call. Every stage degrades individually — the report records stage statuses, so a failed LIEF rebuild never hides a successful dump. Background job: poll with job_output (wait: true). LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        runSeconds: { type: "integer", minimum: 2, maximum: 120, description: "How long the sample runs before the memory scan (default 8)" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "chain-unpack",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, runSeconds, entryExport } = rawArgs as { path: string; runSeconds?: number; entryExport?: string };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("unpack.chain", services.workspace);
      if (!services.jobs) {
        throw new Error("unpack_chain requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `unpack chain ${path}`;
      const done = (async () => {
        try {
          const result = await runUnpackChain(services.workspace, path, {
            ...(runSeconds === undefined ? {} : { runSeconds }),
            ...(entryExport === undefined ? {} : { entryExport }),
            signal: abort.signal,
          });
          return { status: "completed" as const, output: JSON.stringify(result, null, 2) };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "chain-unpack",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill stops the sample`,
      };
    },
  },
  {
    id: "dynamic.recon",
    toolName: "dynamic_recon",
    description:
      "The behavioral recon workflow as ONE call (dynamic-gated): bounded frida probe (modules + file/registry/network API calls) → pe-sieve unpack of the live process → FLOSS deep strings over the dumps → report.correlate fusing every observation with the static sample anchors (IOCs and imports confirmed by dynamic evidence). DLLs are hosted through rundll32 so DllMain executes; entryExport picks the export to call. Stages degrade individually; the final correlation carries confirmedIocs and importedApisSeenAtRuntime. Background job: poll with job_output (wait: true). LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        probeSeconds: { type: "integer", minimum: 2, maximum: 60, description: "How long each dynamic stage observes (default 8)" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "chain-recon",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, args, probeSeconds, entryExport } = rawArgs as { path: string; args?: string[]; probeSeconds?: number; entryExport?: string };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("dynamic.recon", services.workspace);
      if (!services.jobs) {
        throw new Error("dynamic_recon requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `dynamic recon ${path}`;
      const done = (async () => {
        try {
          const result = await runDynamicRecon(services.workspace, path, {
            ...(probeSeconds === undefined ? {} : { probeSeconds }),
            ...(entryExport === undefined ? {} : { entryExport }),
            signal: abort.signal,
          });
          return { status: "completed" as const, output: JSON.stringify(result, null, 2) };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "chain-recon",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill stops the sample`,
      };
    },
  },
  {
    id: "trace.source",
    toolName: "trace_source",
    description:
      "The runtime→static bridge: ONE call turns known behavior into the FUNCTION that performs it — the work that otherwise takes an hour in a debugger. Runs the sample under a Frida source-trace (hooks the behavioral API catalog — file/registry/network/process/crypto — or your explicit apis list), captures each call's caller BACKTRACE with module+offset per frame, computes the sample's ASLR slide (runtimeBase − imageBase) automatically, converts sample-module frames to STATIC VAs, resolves them through the annotate_symbol map, and (when IDA is available) decompiles the hottest sites with Hex-Rays. Optional needle filters to calls whose string argument contains it (the C2 host, the dropped filename, the registry key). Result: ranked static sites with hit counts, APIs, arguments, pseudocode. This REPLACES the manual workflow of breakpoint-on-API → stack trace → manual base math → disassembler lookup. Dynamic-gated (executes the sample): requires an armed plane. Background job: poll with job_output (wait: true). LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        apis: { type: "array", items: { type: "string" }, maxItems: 16, description: "API names to hook (default: the behavioral catalog: CreateFileW, RegSetValueExW, WinHttpConnect, connect, VirtualAllocEx, CryptUnprotectData, ...)" },
        needle: { type: "string", description: "Case-insensitive substring the API's primary string argument must contain (C2 host, filename, key path) — filters to the behavior you care about" },
        probeSeconds: { type: "integer", minimum: 2, maximum: 60, description: "Observation window (default 10)" },
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments for the sample (drives branchy validators); ignored for DLLs" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs" },
        decompile: { type: "boolean", description: "Decompile hottest sites with IDA Hex-Rays when available (default true)" },
        maxDecompiles: { type: "integer", minimum: 0, maximum: 4, description: "Sites to decompile (default 3)" },
        timeoutSeconds: { type: "integer", minimum: 60, maximum: 3600, description: "IDA decompile timeout (default 900)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "frida-runtime",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, apis, needle, args, probeSeconds, entryExport, decompile, maxDecompiles, timeoutSeconds } = rawArgs as {
        path: string;
        apis?: string[];
        needle?: string;
        probeSeconds?: number;
        args?: string[];
        entryExport?: string;
        decompile?: boolean;
        maxDecompiles?: number;
        timeoutSeconds?: number;
      };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("trace.source", services.workspace);
      if (!services.jobs) {
        throw new Error("trace_source requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `trace source ${path}${needle === undefined ? "" : ` (needle: ${needle})`}`;
      const done = (async () => {
        try {
          const result = await runTraceSource(services.workspace, path, {
            ...(apis === undefined ? {} : { apis }),
            ...(needle === undefined ? {} : { needle }),
            ...(args === undefined ? {} : { args }),
            ...(probeSeconds === undefined ? {} : { probeSeconds }),
            ...(entryExport === undefined ? {} : { entryExport }),
            ...(decompile === undefined ? {} : { decompile }),
            ...(maxDecompiles === undefined ? {} : { maxDecompiles }),
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          return { status: "completed" as const, output: JSON.stringify(result, null, 2) };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "frida-runtime",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill stops the sample`,
      };
    },
  },
  {
    id: "annotate.symbol",
    toolName: "annotate_symbol",
    description:
      "The write-back plane: name what you understand so every later operation shows your names. Persist VA → name (+ optional comment) for a sample; binary_find / binary_search hits, binary_explain and trace_source sites, and ida_decompile targets all resolve through this map (hits carry symbol/symbolComment fields). This is the compounding loop: decompile → understand → rename → every subsequent view shows the rename, no disassembler-side state needed. Call with entries to upsert; with vas to remove; with neither to list the map.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        entries: {
          type: "array",
          maxItems: 256,
          items: {
            type: "object",
            properties: {
              va: { type: "string", description: "Virtual address, e.g. \"0x140001450\"" },
              name: { type: "string" },
              comment: { type: "string" },
            },
            required: ["va", "name"],
            additionalProperties: false,
          },
          description: "Symbols to upsert",
        },
        vas: { type: "array", items: { type: "string" }, maxItems: 256, description: "VAs to remove from the map" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        sampleId: { type: "string" },
        sha256: { type: "string" },
        entries: { type: "array", items: { type: "object" } },
        entryCount: { type: "integer" },
      },
      required: ["sampleId", "sha256", "entries", "entryCount"],
    },
    provider: "symbols-native",
    execute: async (rawArgs, { workspace }) => {
      const { path, entries, vas } = rawArgs as {
        path: string;
        entries?: Array<{ va: string; name: string; comment?: string }>;
        vas?: string[];
      };
      const binary = await inspectBinary(workspace, path);
      let symbols: Awaited<ReturnType<typeof readSymbolMap>> = [];
      if (entries !== undefined && entries.length > 0) {
        symbols = await upsertSymbols(workspace, binary.sampleId, entries);
      } else if (vas !== undefined && vas.length > 0) {
        symbols = await removeSymbols(workspace, binary.sampleId, vas);
      } else {
        symbols = await readSymbolMap(workspace, binary.sampleId);
      }
      return {
        sampleId: binary.sampleId,
        sha256: binary.sha256,
        entries: symbols,
        entryCount: symbols.length,
      };
    },
  },
  {
    id: "trace.record",
    toolName: "trace_record",
    description:
      "Record a TIME-TRAVEL trace of the sample with TTD (Microsoft): the full instruction stream lands in a .run file, replayable FORWARD and BACKWARD under WinDbg — walk from the INVALID verdict back to the birth of the compared value, the question static analysis cannot answer. TWO MODES: default LAUNCHES the sample under the recorder (args passed through); pid ATTACHES the recorder to an already-running process (TTD -attach) — the driven-instance pattern: console_launch the sample, submit this job with its pid, drive the scenario with console_send while it records, then kill the process to finalize the trace. children:true records spawned child processes too (launch mode; nanomite self-debug families); maxFileMb bounds the ring buffer. The .out sidecar reports recording health. REQUIRES ELEVATION (the host must run elevated) and tools/ttd/TTD.exe (minusone setup extracts it from the WinDbg MSIX). Dynamic-gated: the sample executes. Background job: poll with job_output (wait: true) — the recording runs for the whole budget while you drive the scenario.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        pid: { type: "integer", minimum: 1, description: "ATTACH mode: record this already-running pid (TTD -attach) — drive it with console.send while recording; args/children are launch-only" },
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments passed to the sample (launch mode)" },
        children: { type: "boolean", description: "Record spawned child processes too, each into its own trace (launch mode)" },
        maxFileMb: { type: "integer", minimum: 1, maximum: 32768, description: "Ring-buffer cap in MB (bounds the trace size)" },
        timeoutSeconds: { type: "integer", minimum: 10, maximum: 300, description: "Recording budget (default 120)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "ttd",
    execute: async (rawArgs, services) => {
      const { path, pid, args, children, maxFileMb, timeoutSeconds } = rawArgs as {
        path: string;
        pid?: number;
        args?: string[];
        children?: boolean;
        maxFileMb?: number;
        timeoutSeconds?: number;
      };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("trace.record", services.workspace);
      return submitOperationJob(services, "ttd-record", pid === undefined ? `ttd-record ${path}` : `ttd-attach ${path} (pid ${pid})`, async (signal) => {
        const result = await recordTtdTrace(services.workspace, path, {
          ...(pid === undefined ? {} : { pid }),
          ...(args === undefined ? {} : { args }),
          ...(children === undefined ? {} : { children }),
          ...(maxFileMb === undefined ? {} : { maxFileMb }),
          ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
          signal,
        });
        return {
          status: result.status,
          ...(result.tracePath === null ? {} : { tracePath: result.tracePath, traceBytes: result.traceBytes }),
          ...(result.outLogPath === null ? {} : { outLogPath: result.outLogPath }),
          ...(result.exitSummary === null ? {} : { exitSummary: result.exitSummary }),
          ...(result.error === undefined ? {} : { error: result.error }),
        };
      });
    },
  },
  {
    id: "trace.replay",
    toolName: "trace_replay",
    description:
      "Replay a recorded TTD trace HEADLESS under WinDbg: your commands run at the trace start — jump with !tt <position>, step BACK with g-, list interesting events with !positions, breakpoint forward with bp+g. This is the backward walk: from the INVALID verdict to the value's origin. Background job: the response returns IMMEDIATELY with the job id and BOTH log paths (logPath = WinDbg banner log, outputLogPath = your commands' captured output via .logopen) — a replay runs for minutes on big traces, so poll job_output (wait: true) OR watch outputLogPath grow with shell tools; an empty response at 30s means the replay is still working, never that it failed. Needs WinDbgX (winget install Microsoft.WinDbg) — the SDK cdb cannot open .run traces. NOT dynamic-gated: it replays recorded data, nothing executes.",
    parameters: {
      type: "object",
      properties: {
        tracePath: { type: "string", description: "Workspace-relative .run trace path (from trace.record)" },
        commands: { type: "string", maxLength: 4000, description: 'Debugger commands separated by ";", e.g. "!positions; !tt 12:0; k; g-"' },
        timeoutSeconds: { type: "integer", minimum: 30, maximum: 300, description: "Replay budget (default 120)" },
      },
      required: ["tracePath", "commands"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        logPath: { type: "string" },
        outputLogPath: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status"],
    },
    provider: "ttd",
    execute: async (rawArgs, services) => {
      if (!services.jobs) {
        throw new Error("trace_replay requires a background job registry; this host does not provide one.");
      }
      const { tracePath, commands, timeoutSeconds } = rawArgs as {
        tracePath: string;
        commands: string;
        timeoutSeconds?: number;
      };
      // The replay's log paths are deterministic (written beside the trace) and
      // known up front — the immediate response carries them so the caller can
      // watch outputLogPath grow without waiting for job settlement.
      const traceAbsolute = await services.workspace.resolveFile(tracePath);
      const runDir = path.dirname(traceAbsolute);
      const relLog = services.workspace.relative(path.join(runDir, "replay.log"));
      const relOut = services.workspace.relative(path.join(runDir, "replay-out.txt"));
      const abort = new AbortController();
      const label = `ttd-replay ${tracePath}`;
      const done = (async () => {
        try {
          const result = await replayTtdTrace(services.workspace, tracePath, commands, {
            ...(timeoutSeconds === undefined ? {} : { timeoutSeconds }),
            signal: abort.signal,
          });
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                status: result.status,
                ...(result.logPath === null ? {} : { logPath: result.logPath, logBytes: result.logBytes }),
                ...(result.output === undefined ? {} : { output: result.output }),
                ...(result.outputLogPath === undefined ? {} : { outputLogPath: result.outputLogPath }),
                ...(result.error === undefined ? {} : { error: result.error }),
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "ttd-replay",
        label,
        outputLimitBytes: 2 * 1024 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        logPath: relLog,
        outputLogPath: relOut,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill cancels; or watch ${relOut} grow — it receives every command's output live via .logopen`,
      };
    },
  },
  {
    id: "frida.script",
    toolName: "frida_script",
    description:
      "Run YOUR OWN Frida agent against the sample for a bounded window — persistent instrumentation instead of the canned probes: Interceptor.attach wherever you want, Stalker.follow for coverage, rpc for interaction. Events sent via send() stream to a JSONL log AS THEY HAPPEN (the log path comes back in the response). childGating:true enables spawn gating on the device so SPAWNED CHILDREN are held suspended, the agent attaches to them, and only then do they run — the nanomite/self-debug counter (a scheme where the parent spawns a debugger child). TWO MODES: default SPAWNS a fresh instance (batch samples); pid ATTACHES to an already-running process — THE mode for driven TUI/stateful targets (pass console_launch's pid; the process is left running at teardown, you own its lifecycle). Dynamic-gated: the sample executes on the armed local plane. Background job: poll with job_output (wait: true); the event log streams live while the probe window runs.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        source: { type: "string", maxLength: 65536, description: "Frida agent JavaScript (use send() to stream events)" },
        pid: { type: "integer", minimum: 1, description: "ATTACH mode: instrument this already-running pid instead of spawning (driven TUI/stateful targets; the process is NOT killed at teardown — you own it). args/entryExport are spawn-only" },
        probeSeconds: { type: "integer", minimum: 2, maximum: 120, description: "Observation window (default 15)" },
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments for the sample (drives branchy validators: GOOD-KEY vs BAD-KEY). DLL samples ignore args (rundll32 hosting). Spawn mode only" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (DLL samples only). Spawn mode only" },
        childGating: { type: "boolean", description: "Hold spawned children suspended, attach the agent, then resume — the nanomite/self-debug counter (default false)" },
      },
      required: ["path", "source"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "frida-bridge",
    execute: async (rawArgs, services) => {
      const { path, source, pid, args, probeSeconds, entryExport, childGating } = rawArgs as {
        path: string;
        source: string;
        pid?: number;
        args?: string[];
        probeSeconds?: number;
        entryExport?: string;
        childGating?: boolean;
      };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("frida.script", services.workspace);
      return submitOperationJob(services, "frida-script", pid === undefined ? `frida ${path}` : `frida-attach ${path} (pid ${pid})`, async (signal) => {
        const result = await runFridaScript(services.workspace, path, {
          source,
          ...(pid === undefined ? {} : { pid }),
          ...(args === undefined ? {} : { args }),
          ...(probeSeconds === undefined ? {} : { probeSeconds }),
          ...(entryExport === undefined ? {} : { entryExport }),
          ...(childGating === undefined ? {} : { childGating }),
          signal,
        });
        return {
          status: result.attachFailed === null ? "ok" : "error",
          pid: result.pid,
          launchMode: result.launchMode,
          attachedPids: result.attachedPids,
          events: result.events.slice(0, 200),
          eventLogPath: result.eventLogPath,
          notes: result.notes,
          ...(result.attachFailed === null ? {} : { error: result.attachFailed }),
        };
      });
    },
  },
  {
    id: "trace.diff",
    toolName: "trace_diff",
    description:
      "Execution DIFF of two runs of the same sample (args A vs args B): Frida Stalker records the basic blocks each run executes inside the sample module, and the response is a SUMMARY of the symmetric difference — block counts per run, firstDivergence (the earliest block only one run executed: the branch-point proxy), reconvergences (shared blocks both runs reached after diverging), plus the earliest 50 diverging blocks per side (candidate VALID-path fragments). When the diff is larger, the full RVA-sorted block lists are saved to a file under .minusone/outputs/ and fullDiffFile carries the path — the reply never balloons to megabytes of raw RVAs. THE validator localizer when you have one input known-good-ish and one known-bad: no breakpoints, no decompilation, just two runs and a set difference. Events throttle to block granularity, sample-module addresses only (RVA normalized). Dynamic-gated: the sample executes twice. Background job: poll with job_output (wait: true). LIFECYCLE: SPAWNS its own instance per run — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        argsA: { type: "array", items: { type: "string" }, maxItems: 8, description: "argv for run A (e.g. ['GOOD-KEY'])" },
        argsB: { type: "array", items: { type: "string" }, maxItems: 8, description: "argv for run B (the differing input)" },
        probeSeconds: { type: "integer", minimum: 2, maximum: 60, description: "Window per run (default 10)" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string" },
        label: { type: "string" },
        poll: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "frida-bridge",
    execute: async (rawArgs, services) => {
      const { path, argsA, argsB, probeSeconds } = rawArgs as {
        path: string;
        argsA?: string[];
        argsB?: string[];
        probeSeconds?: number;
      };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("trace.diff", services.workspace);
      return submitOperationJob(services, "trace-diff", `trace-diff ${path}`, (signal) =>
        runTraceDiff(services.workspace, path, {
          ...(argsA === undefined ? {} : { argsA }),
          ...(argsB === undefined ? {} : { argsB }),
          ...(probeSeconds === undefined ? {} : { probeSeconds }),
          signal,
        }),
      );
    },
  },
  {
    id: "dynamic.frida",
    toolName: "dynamic_frida",
    description:
      "Run a sample on the LOCAL dynamic target and attach a Frida probe for a bounded window: enumerates loaded modules and hooks the classic behavioral API surface (file/registry/network calls with argument previews). DLLs are hosted through rundll32 so DllMain executes; entryExport picks the export to call (default: first export). Requires MINUSONE_ALLOW_DYNAMIC=1, MINUSONE_DYNAMIC_TARGET=local, and the frida node runtime (npm install frida). Background job: poll with job_output (wait: true); job_kill stops the sample. LIFECYCLE: SPAWNS its own instance — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        probeSeconds: { type: "integer", minimum: 2, maximum: 120, description: "How long the probe observes API calls" },
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments for the sample (drives branchy validators); ignored for DLLs" },
        entryExport: { type: "string", description: "DLL export for rundll32 to call (default: first export); ignored for EXEs" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        jobId: { type: "string" },
        status: { type: "string", enum: ["running"] },
        label: { type: "string" },
        poll: { type: "string" },
      },
      required: ["jobId", "status", "label", "poll"],
    },
    provider: "frida-runtime",
    timeoutMs: 30_000,
    execute: async (rawArgs, services) => {
      const { path, args, probeSeconds, entryExport } = rawArgs as { path: string; args?: string[]; probeSeconds?: number; entryExport?: string };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("dynamic.frida", services.workspace);
      if (!services.jobs) {
        throw new Error("dynamic_frida requires a background job registry; this host does not provide one.");
      }
      const abort = new AbortController();
      const label = `frida probe ${path}`;
      const done = (async () => {
        try {
          const availability = await probeFridaAvailability();
          if (!availability.available) {
            return {
              status: "failed" as const,
              detail: `frida runtime is not installed (npm install frida); probe error: ${availability.error ?? "unknown"}`,
            };
          }
          const result = await runFridaProbe(services.workspace, path, {
            ...(args === undefined ? {} : { args }),
            ...(probeSeconds === undefined ? {} : { probeSeconds }),
            ...(entryExport === undefined ? {} : { entryExport }),
            signal: abort.signal,
          });
          if (abort.signal.aborted) {
            return { status: "killed" as const, detail: "frida probe terminated by job_kill" };
          }
          return {
            status: "completed" as const,
            output: JSON.stringify(
              {
                target: "local",
                pid: result.pid,
                launchedVia: result.launchedVia,
                probeSeconds: result.probeSeconds,
                ...(result.attachFailed === null ? {} : { attachFailed: result.attachFailed }),
                moduleCount: result.moduleCount,
                modules: result.modules.slice(0, 20),
                hookedApis: result.hookedApis,
                callEventCount: result.callEvents.length,
                callLogTruncated: result.callLogTruncated,
                callEvents: result.callEvents,
                runDir: result.runDir,
                ...(result.callLogPath === null ? {} : { callLogPath: result.callLogPath }),
                next: "join this evidence with traces/dumps via report_correlate (fridaLogPath = callLogPath); rerun with a longer probeSeconds for deeper coverage",
              },
              null,
              2,
            ),
          };
        } catch (error) {
          return { status: "failed" as const, detail: error instanceof Error ? error.message : String(error) };
        }
      })();
      const jobId = services.jobs.start({
        kind: "frida",
        label,
        outputLimitBytes: 512 * 1024,
        ...(services.jobOwner === undefined ? {} : { owner: services.jobOwner }),
        run: () => ({
          cancel: (reason) => abort.abort(reason),
          done,
        }),
      });
      return {
        jobId,
        status: "running",
        label,
        poll: `call job_output with job_id "${jobId}" and wait: true; job_kill stops the sample`,
      };
    },
  },
  {
    id: "debug.session.create",
    toolName: "debug_session_create",
    description:
      "Create a scriptable debugger session. gdb (default) runs the sample under gdb on the LOCAL dynamic target and stops at its first instruction (starti) — interactive prompt loop, full console incl. python/shell; requires an armed dynamic plane. cdb (postmortem) takes a Windows minidump (.dmp) as `path`: cdb re-runs an accumulated batch against the frozen dump, the captured process is never executed, so cdb is NOT dynamic-gated. x64dbg (headless) loads the sample under x64dbg headless.exe and runs a COMPLETE native script per debug_command (bp/run/mov) — each command reloads the sample, so there is no shared state; x64dbg returns the debugger EVENT stream (module loads, breakpoint hits, state, exit code), not structured register/memory values (for those use gdb/cdb); loading a sample is live, so x64dbg IS dynamic-gated. Release the session with debug_session_close, which archives the transcript. cdb blocks .shell/$</.foreach. LIFECYCLE: gdb/x64dbg SPAWN their own instance (cdb is postmortem data) — for interactive/stateful targets (TUI, accumulated state) use the attach-capable plane: console_launch + frida_script{pid} + trace_record{pid}.",
    parameters: {
      type: "object",
      properties: {
        path: pathParameter,
        debugger: {
          type: "string",
          enum: ["gdb", "cdb", "x64dbg"],
          description: "gdb (default, live, interactive, dynamic-gated) | cdb (postmortem minidump, ungated — path is a .dmp) | x64dbg (headless native script batch, live, dynamic-gated)",
        },
        args: { type: "array", items: { type: "string" }, maxItems: 16, description: "Command-line arguments passed to the sample (gdb only)" },
        stopAtEntry: { type: "boolean", description: "Stop at the first instruction via starti (gdb only, default true)" },
        harden: { type: "boolean", description: "Anti-anti-debug hardening (gdb only): neutralize PEB.BeingDebugged, NtGlobalFlag and process-heap debug flags at every stop — makes the debugger usable against protected samples that detect it and silently exit" },
      },
      required: ["path"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["created", "refused"] },
        sessionId: { type: "string" },
        debugger: { type: "string" },
        runDir: { type: "string" },
        stopAtEntry: { type: "boolean" },
        harden: { type: "object" },
        startupOutput: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "debugger-bridge",
    timeoutMs: 120_000,
    execute: async (rawArgs, services) => {
      const { path: samplePath, debugger: dbg, args, stopAtEntry, harden } = rawArgs as {
        path: string;
        debugger?: "gdb" | "cdb" | "x64dbg";
        args?: string[];
        stopAtEntry?: boolean;
        harden?: boolean;
      };
      // cdb postmortem inspects a frozen dump (no execution) — NOT dynamic-gated.
      // gdb runs the live sample on the local target — gated.
      if (dbg !== "cdb") {
        if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("debug.session.create", services.workspace);
      }
      const created = await createDebugSession(services.workspace, samplePath, {
        debugger: dbg ?? "gdb",
        ...(args === undefined ? {} : { args }),
        ...(stopAtEntry === undefined ? {} : { stopAtEntry }),
        ...(harden === undefined ? {} : { harden }),
      });
      return {
        status: "created",
        sessionId: created.sessionId,
        debugger: created.debugger,
        runDir: created.runDir,
        stopAtEntry: created.stopAtEntry,
        harden: created.harden,
        startupOutput: created.startup.output.slice(0, 4096),
      };
    },
  },
  {
    id: "debug.command",
    toolName: "debug_command",
    description:
      "Send a command to an active debug session and return its bounded output. gdb: break/watch, continue/step/next/finish, info registers/threads/breakpoints, x/... memory dumps, print, backtrace, disassemble, and python/shell for scripted inspection (the inferior keeps running between calls). MULTI-LINE input is fully supported: batches (including python...end blocks) are routed through a sourced script so every line executes in order — no more first-line-only desync. cdb postmortem: lm, r, k/kv, dv, !analyze -v, .ecxr, s, etc. — the command is appended to the session batch and cdb is re-run against the frozen dump. gdb sessions are dynamic-gated; cdb sessions are not (they inspect data, not a live process). watch/rwatch/awatch commands get an HONEST watchpoint verdict in the response: gdb's acknowledgment is parsed, and when no hardware/software watchpoint was actually created the response says so explicitly — never build on a silent failure. A wedged run is recoverable with debug_kill (the session survives).",
    parameters: {
      type: "object",
      properties: {
        sessionId: { type: "string" },
        command: { type: "string", maxLength: 2048 },
        timeoutSeconds: { type: "integer", minimum: 5, maximum: 300, description: "How long to wait for the debugger output (default 30)" },
      },
      required: ["sessionId", "command"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error", "refused"] },
        sessionId: { type: "string" },
        output: { type: "string" },
        seconds: { type: "number" },
        timedOut: { type: "boolean" },
        error: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "debugger-bridge",
    timeoutMs: 360_000,
    execute: async (rawArgs, services) => {
      const { sessionId, command, timeoutSeconds } = rawArgs as { sessionId: string; command: string; timeoutSeconds?: number };
      // gdb sessions (and any unknown session) drive a live inferior on the
      // armed plane; only cdb postmortem sessions inspect a frozen dump and
      // never execute the sample, so they alone skip the dynamic gate.
      if (activeDebugSessionKind(sessionId) !== "cdb") {
        if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("debug.command", services.workspace);
      }
      const result = await sendDebugCommand(sessionId, command, timeoutSeconds);
      const watch = /^\s*(r?w?a?watch|awatch|rwatch)\b/.test(command)
        ? parseWatchpointResult(result.output)
        : null;
      return {
        status: result.ok ? "ok" : "error",
        sessionId,
        output: result.output,
        seconds: result.seconds,
        ...(result.timedOut === undefined ? {} : { timedOut: result.timedOut }),
        ...(result.error === undefined ? {} : { error: result.error }),
        ...(watch === null
          ? {}
          : {
              watchpoint: {
                confirmed: !watch.degraded,
                hardware: watch.hardware,
                number: watch.watchpointNumber,
                note: watch.note,
              },
            }),
      };
    },
  },
  {
    id: "debug.kill",
    toolName: "debug_kill",
    description:
      "Kill the inferior of a gdb debug session WITHOUT closing the session: the wedged `continue` from a hung run gets terminated, gdb stays alive with every breakpoint intact, and the next `run` starts fresh. Use this instead of debug.session.close when only the RUN is stuck, not the session. cdb/x64dbg sessions have no persistent live inferior — they report that honestly.",
    parameters: {
      type: "object",
      properties: {
        sessionId: { type: "string", description: "gdb session id from debug_session_create" },
      },
      required: ["sessionId"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error", "refused"] },
        sessionId: { type: "string" },
        output: { type: "string" },
        seconds: { type: "number" },
        error: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status", "sessionId"],
    },
    provider: "debugger-bridge",
    timeoutMs: 60_000,
    execute: async (rawArgs, services) => {
      const { sessionId } = rawArgs as { sessionId: string };
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("debug.kill", services.workspace);
      const result = await killDebugInferior(sessionId);
      return {
        status: result.ok ? "ok" : "error",
        sessionId,
        output: result.output,
        seconds: result.seconds,
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "debug.break",
    toolName: "debug_break",
    description:
      "Set a CONDITIONAL breakpoint whose condition dereferences a pointer-to-string — the thing raw gdb syntax gets wrong (strcmp on an untyped register aborts the condition; $_streq needs casts). Give an address (or symbol) plus the register that carries the string pointer at that site and the expected text: the operation builds the correct breakpoint command (null-checked strcmp/strstr with an explicit char* cast), sends it to the session, and returns the breakpoint number. mode 'contains' uses substring matching. Typical use: break where CreateFileA is called with a specific filename, or where the validator reads the serial — point the register at the argument that carries it (x64: rcx/rdx/r8/r9).",
    parameters: {
      type: "object",
      properties: {
        sessionId: { type: "string", description: "gdb session id from debug_session_create" },
        address: { type: "string", description: "Breakpoint address (hex like 0x140001234) — runtime address in a live session" },
        symbol: { type: "string", description: "Symbol/function name alternative to address (e.g. the API name when breaking on an import)" },
        register: { type: "string", description: "Register holding the pointer to the string at that site (rcx, rdx, r8, r9 on x64)" },
        text: { type: "string", description: "The string the pointer must point to" },
        mode: { type: "string", enum: ["equals", "contains"], description: "String match mode (default equals)" },
      },
      required: ["sessionId", "register", "text"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["ok", "error", "refused"] },
        sessionId: { type: "string" },
        command: { type: "string" },
        explanation: { type: "string" },
        output: { type: "string" },
        error: { type: "string" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "debugger-bridge",
    timeoutMs: 120_000,
    execute: async (rawArgs, services) => {
      const { sessionId, address, symbol, register, text, mode } = rawArgs as {
        sessionId: string;
        address?: string;
        symbol?: string;
        register: string;
        text: string;
        mode?: "equals" | "contains";
      };
      if (address === undefined && symbol === undefined) {
        throw new Error("pass address or symbol (the breakpoint location)");
      }
      if (activeDebugSessionKind(sessionId) !== "gdb") {
        throw new Error(`debug_break string conditions need a gdb session (got ${activeDebugSessionKind(sessionId) ?? "unknown session"}) — cdb postmortem cannot take live breakpoints`);
      }
      if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("debug.break", services.workspace);
      const built = buildStringBreakpoint({
        ...(address === undefined ? {} : { address }),
        ...(symbol === undefined ? {} : { symbol }),
        register,
        text,
        ...(mode === undefined ? {} : { mode }),
      });
      const result = await sendDebugCommand(sessionId, built.command, 30);
      return {
        status: result.ok ? "ok" : "error",
        sessionId,
        command: built.command,
        explanation: built.explanation,
        output: result.output,
        ...(result.error === undefined ? {} : { error: result.error }),
      };
    },
  },
  {
    id: "debug.session.close",
    toolName: "debug_session_close",
    description:
      "Close a debugger session: for gdb, kills gdb and the sample (process tree); for cdb, the batch already exited so only the transcript is archived. Either way the full command/output transcript is stored as an artifact. gdb sessions are dynamic-gated; cdb sessions are not.",
    parameters: {
      type: "object",
      properties: {
        sessionId: { type: "string" },
      },
      required: ["sessionId"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["closed", "refused"] },
        sessionId: { type: "string" },
        target: { type: "string" },
        runDir: { type: "string" },
        commandsExecuted: { type: "integer" },
        artifactId: { type: "string" },
        artifactBytes: { type: "integer" },
        reason: { type: "string" },
        requirements: { type: "array", items: { type: "string" } },
      },
      required: ["status"],
    },
    provider: "debugger-bridge",
    timeoutMs: 60_000,
    execute: async (rawArgs, services) => {
      const { sessionId } = rawArgs as { sessionId: string };
      if (activeDebugSessionKind(sessionId) !== "cdb") {
        if ((await resolveDynamicTarget(services.workspace)) !== "local") return await refuseDynamic("debug.session.close", services.workspace);
      }
      const closed = await closeDebugSession(sessionId);
      const artifact = await storeArtifact(
        services.workspace,
        JSON.stringify(
          { sessionId: closed.sessionId, debugger: activeDebugSessionKind(sessionId) ?? "unknown", target: closed.target, runDir: closed.runDir, transcript: closed.transcript },
          null,
          2,
        ),
        {
          mediaType: "application/json",
          sourceOperation: "debug.session.close",
          description: `Debug transcript: ${closed.target} (${closed.commandsExecuted} commands)`,
        },
      );
      return {
        status: "closed",
        sessionId,
        target: closed.target,
        runDir: closed.runDir,
        commandsExecuted: closed.commandsExecuted,
        artifactId: artifact.id,
        artifactBytes: artifact.bytes,
      };
    },
  },
];
