/**
 * Intent chains — composite jobs that encode multi-step RE workflows as one
 * call. unpack.chain: packer verdict → pe-sieve unpack → dump sanitize →
 * LIEF rebuild → re-triage of the rebuilt image. dynamic.recon: bounded
 * execution → frida probe → unpack → FLOSS over dumps → correlate. Each
 * step reuses the primitive providers (nothing new executes here); the
 * chain adds sequencing, failure tolerance, and a single fused report.
 */
import { flossDumpDirectory } from "./floss.js";
import { correlateEvidence } from "./correlate.js";
import { probeFridaAvailability, runFridaProbe } from "./frida.js";
import { rebuildPe } from "./perebuild.js";
import { triageBinary } from "./triage.js";
import { unpackStatic } from "./unpack-static.js";
import { unpackSample } from "./dynamic.js";
import type { Workspace } from "./workspace.js";

export const UNPACK_CHAIN_TIMEOUT_SECONDS = 600;

export interface UnpackChainResult {
  target: "local";
  stages: Array<{ stage: string; status: "ok" | "skipped" | "failed"; detail: string }>;
  dumpDir: string | null;
  rebuiltPath: string | null;
  rebuiltSha256: string | null;
  postTriage: {
    packed: boolean | null;
    importCount: number | null;
    stringsCount: number | null;
    iocCount: number | null;
  } | null;
  next: string[];
}

/**
 * unpack.chain: the packed-sample workflow. Runs the sample on the armed
 * local plane, dumps the unpacked image with pe-sieve, rebuilds a PE from
 * the dump with LIEF, and re-triages the rebuilt image — one call instead
 * of four. Steps degrade individually (recorded in stages) without killing
 * the chain.
 */
export async function runUnpackChain(
  workspace: Workspace,
  userPath: string,
  options: { runSeconds?: number; entryExport?: string; signal?: AbortSignal } = {},
): Promise<UnpackChainResult> {
  const stages: UnpackChainResult["stages"] = [];
  const next: string[] = [];

  const pre = await triageBinary(workspace, userPath, { ...(options.signal === undefined ? {} : { signal: options.signal }) });
  stages.push({
    stage: "pre-triage",
    status: "ok",
    detail: `packed=${pre.verdict.packed}${pre.verdict.packed ? ` (${pre.verdict.packedWhy[0] ?? ""})` : ""}, risk=${pre.verdict.riskLevel}`,
  });
  if (!pre.verdict.packed) {
    next.push("the sample does not look packed — the chain still ran; the 'rebuilt' image mirrors the in-memory module");
  }

  // ---- UPX fast-path: static decompression, seconds, no execution ----------
  // When upx accepts the sample the dynamic stages are skipped entirely —
  // the statically decompressed image IS the unpacked payload.
  let postTriage: UnpackChainResult["postTriage"] = null;
  let upxPath: string | null = null;
  if (pre.verdict.packed) {
    try {
      const staticUnpack = await unpackStatic(workspace, userPath, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (staticUnpack.packed && staticUnpack.outputPath !== null) {
        upxPath = staticUnpack.outputPath;
        stages.push({
          stage: "UPX static unpack",
          status: "ok",
          detail: `decompressed statically (${staticUnpack.outputBytes} bytes) — dynamic stages skipped, the sample was never executed`,
        });
      } else {
        stages.push({
          stage: "UPX static unpack",
          status: "skipped",
          detail: staticUnpack.notes[0] ?? "upx did not accept the sample",
        });
      }
    } catch (error) {
      stages.push({ stage: "UPX static unpack", status: "skipped", detail: error instanceof Error ? error.message : String(error) });
    }
  } else {
    stages.push({ stage: "UPX static unpack", status: "skipped", detail: "not packed" });
  }

  if (upxPath !== null) {
    // The statically unpacked image goes straight to re-triage; LIEF rebuild
    // is unnecessary (upx -d restores a valid PE).
    try {
      const post = await triageBinary(workspace, upxPath, { ...(options.signal === undefined ? {} : { signal: options.signal }) });
      const iocCount = post.strings === null ? 0
        : post.strings.iocs.urls.length + post.strings.iocs.ips.length + post.strings.iocs.registry.length + post.strings.iocs.pdbPaths.length + post.strings.iocs.uncPaths.length;
      postTriage = {
        packed: post.verdict.packed,
        importCount: post.imports === null ? 0 : post.imports.functionCount,
        stringsCount: post.strings === null ? 0 : post.strings.count,
        iocCount,
      };
      stages.push({
        stage: "post-triage",
        status: "ok",
        detail: `statically unpacked image: ${postTriage.stringsCount} strings, ${postTriage.importCount} imports, ${iocCount} IOC(s)`,
      });
      return {
        target: "local",
        stages,
        dumpDir: null,
        rebuiltPath: upxPath,
        rebuiltSha256: null,
        postTriage,
        next: [
          `the statically unpacked image is ${upxPath} — run binary_find / strings_extract_deep / ida_decompile against it; the original sample was never executed`,
        ],
      };
    } catch (error) {
      stages.push({ stage: "post-triage", status: "failed", detail: error instanceof Error ? error.message : String(error) });
    }
  }

  let dumpFile: string | null = null;
  let rebuiltPath: string | null = null;
  let rebuiltSha256: string | null = null;

  try {
    const unpacked = await unpackSample(workspace, userPath, {
      ...(options.runSeconds === undefined ? {} : { runSeconds: options.runSeconds }),
      ...(options.entryExport === undefined ? {} : { entryExport: options.entryExport }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const dumped = unpacked.dumpedFiles.find((file) => /\.exe$|\.dll$/i.test(file.path)) ?? unpacked.dumpedFiles[0];
    dumpFile = dumped === undefined ? null : `${unpacked.dumpDir}/${dumped.path}`.replace(/\\/g, "/");
    stages.push({
      stage: "pe-sieve unpack",
      status: dumpFile === null ? "failed" : "ok",
      detail: dumpFile === null
        ? "pe-sieve dumped no module (the sample may have exited before the scan; raise runSeconds)"
        : `${unpacked.dumpedFiles.length} file(s) dumped, sanitizer patched ${unpacked.sanitizedHeaders.patched} header(s)`,
    });
  } catch (error) {
    stages.push({ stage: "pe-sieve unpack", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  if (dumpFile !== null) {
    try {
      const rebuilt = await rebuildPe(workspace, dumpFile, {
        originalPath: userPath,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      rebuiltPath = rebuilt.rebuiltPath;
      rebuiltSha256 = rebuilt.sha256;
      stages.push({
        stage: "LIEF rebuild",
        status: "ok",
        detail: `${rebuilt.bytes} bytes, ${rebuilt.report?.repairs.length ?? 0} repair(s)`,
      });
    } catch (error) {
      stages.push({ stage: "LIEF rebuild", status: "failed", detail: error instanceof Error ? error.message : String(error) });
    }
  } else {
    stages.push({ stage: "LIEF rebuild", status: "skipped", detail: "no dump to rebuild" });
  }

  if (rebuiltPath !== null) {
    try {
      const post = await triageBinary(workspace, rebuiltPath, { ...(options.signal === undefined ? {} : { signal: options.signal }) });
      const iocCount = post.strings === null ? 0
        : post.strings.iocs.urls.length + post.strings.iocs.ips.length + post.strings.iocs.registry.length + post.strings.iocs.pdbPaths.length + post.strings.iocs.uncPaths.length;
      postTriage = {
        packed: post.verdict.packed,
        importCount: post.imports === null ? 0 : post.imports.functionCount,
        stringsCount: post.strings === null ? 0 : post.strings.count,
        iocCount,
      };
      stages.push({
        stage: "post-triage",
        status: "ok",
        detail: `rebuilt image: ${postTriage.stringsCount} strings, ${postTriage.importCount} imports, ${iocCount} IOC(s)`,
      });
      next.push("run binary_find / strings_extract_deep / ida_decompile against the rebuilt image — the unpacked payload is now statically reachable");
    } catch (error) {
      stages.push({ stage: "post-triage", status: "failed", detail: error instanceof Error ? error.message : String(error) });
    }
  } else {
    stages.push({ stage: "post-triage", status: "skipped", detail: "no rebuilt image" });
  }

  return {
    target: "local",
    stages,
    dumpDir: dumpFile === null ? null : dumpFile.split("/").slice(0, -1).join("/"),
    rebuiltPath,
    rebuiltSha256,
    postTriage,
    next,
  };
}

export const RECON_DEFAULT_PROBE_SECONDS = 8;
export const RECON_MAX_PROBE_SECONDS = 60;

export interface DynamicReconResult {
  target: "local";
  stages: Array<{ stage: string; status: "ok" | "skipped" | "failed"; detail: string }>;
  correlation: unknown | null;
  next: string[];
}

/**
 * dynamic.recon: the behavioral workflow. Bounded frida probe (API calls,
 * network, registry) → pe-sieve unpack → FLOSS deep strings over the dumps →
 * correlate everything against the static sample anchors. One call instead
 * of five; every stage degrades individually.
 */
export async function runDynamicRecon(
  workspace: Workspace,
  userPath: string,
  options: { probeSeconds?: number; entryExport?: string; signal?: AbortSignal } = {},
): Promise<DynamicReconResult> {
  const stages: DynamicReconResult["stages"] = [];
  const next: string[] = [];
  const probeSeconds = Math.min(RECON_MAX_PROBE_SECONDS, Math.max(2, options.probeSeconds ?? RECON_DEFAULT_PROBE_SECONDS));

  let fridaLogPath: string | null = null;
  try {
    const available = await probeFridaAvailability();
    if (!available.available) {
      stages.push({ stage: "frida probe", status: "skipped", detail: "frida is not available on this host" });
    } else {
      const probe = await runFridaProbe(workspace, userPath, {
        probeSeconds,
        ...(options.entryExport === undefined ? {} : { entryExport: options.entryExport }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      fridaLogPath = probe.callLogPath;
      stages.push({
        stage: "frida probe",
        status: probe.callLogPath === null ? "failed" : "ok",
        detail: probe.callLogPath === null
          ? `probe failed: ${probe.attachFailed ?? "no call log was produced"}`
          : `${probe.callEvents.length} API call(s) logged to ${probe.callLogPath}`,
      });
    }
  } catch (error) {
    stages.push({ stage: "frida probe", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  let dumpDir: string | null = null;
  try {
    const unpacked = await unpackSample(workspace, userPath, {
      runSeconds: probeSeconds,
      ...(options.entryExport === undefined ? {} : { entryExport: options.entryExport }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    dumpDir = unpacked.dumpDir;
    stages.push({
      stage: "pe-sieve unpack",
      status: "ok",
      detail: `${unpacked.dumpedFiles.length} file(s) dumped`,
    });
  } catch (error) {
    stages.push({ stage: "pe-sieve unpack", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  if (dumpDir !== null) {
    try {
      const floss = await flossDumpDirectory(workspace, dumpDir, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      stages.push({
        stage: "FLOSS deep strings",
        status: "ok",
        detail: `deep string report ${floss.cacheHit ? "reused from cache" : "produced"} (${floss.artifactId})`,
      });
    } catch (error) {
      stages.push({ stage: "FLOSS deep strings", status: "failed", detail: error instanceof Error ? error.message : String(error) });
    }
  } else {
    stages.push({ stage: "FLOSS deep strings", status: "skipped", detail: "no dumps to process" });
  }

  let correlation: unknown | null = null;
  try {
    correlation = await correlateEvidence(workspace, {
      ...(fridaLogPath === null ? {} : { fridaLogPath }),
      ...(dumpDir === null ? {} : { dumpDirPath: dumpDir }),
      samplePath: userPath,
    });
    stages.push({ stage: "correlate", status: "ok", detail: "static anchors cross-referenced against dynamic observations" });
    const confirmed = (correlation as { staticDynamic?: { confirmedIocs: unknown[] } }).staticDynamic?.confirmedIocs ?? [];
    if (confirmed.length > 0) {
      next.push(`${confirmed.length} static IOC(s) confirmed by dynamic observation — record them with report_findings`);
    }
  } catch (error) {
    stages.push({ stage: "correlate", status: "failed", detail: error instanceof Error ? error.message : String(error) });
  }

  next.push("inspect correlation.networkEndpoints and fileActivity for behavior; record conclusions with report_findings");
  return { target: "local", stages, correlation, next };
}
