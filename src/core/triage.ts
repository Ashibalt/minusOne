/**
 * binary.triage — the fused first-look report: one call produces what an
 * agent would otherwise hand-glue from six operations. Native planes
 * (format, sections, imports, exports, resources, IOC string mining) run
 * in-process; Detect It Easy and binwalk run inline sharing their own
 * operation cache keys (a later packer_detect / embedded_scan serves from
 * the same artifacts); capa is cache-only by default because it is slow.
 *
 * The moat is the encoded triage expertise: import-API risk categories,
 * packed/packer heuristics, .NET detection, IOC extraction (URLs, IPs,
 * registry paths, PDB paths, UNC shares), and contextual next steps.
 * Every sub-plane degrades gracefully: a missing backend or a failed
 * parse is recorded, never fatal to the report.
 */
import { cacheKeyDigest, findArtifactByCacheKey, readArtifactFull, storeArtifact } from "./artifacts.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { inspectBinary } from "./binary.js";
import { runBinwalkScan } from "./binwalk.js";
import { runCapaAnalysis, summarizeCapaReport } from "./capa.js";
import { runDieDetection, summarizeDieReport } from "./die.js";
import { parsePeTables } from "./peimports.js";
import type { PeTables } from "./peimports.js";
import { parsePeResources } from "./peresources.js";
import { verifySignature } from "./signatures.js";
import { extractStrings } from "./strings.js";
import type { BinaryInfo } from "./types.js";
import type { Workspace } from "./workspace.js";

export const TRIAGE_STRINGS_LIMIT = 20_000;
export const TRIAGE_MAX_IOCS = 32;
export const TRIAGE_MAX_EXPORTS = 128;
export const TRIAGE_MAX_SIGNAME_CHARS = 160;

/** Default string-plane window; overridable via TriageOptions (no ceiling). */
export const TRIAGE_DEFAULT_SCAN_BYTES = 32 * 1024 * 1024;

/** Classic triage API-risk categories; presence maps to a risk level. */
const API_RISK: Array<{ category: string; level: "high" | "medium"; apis: string[] }> = [
  {
    category: "process-injection",
    level: "high",
    apis: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtMapViewOfSection", "QueueUserAPC", "SetWindowsHookEx", "RtlCreateUserThread"],
  },
  {
    category: "process-execution",
    level: "high",
    apis: ["CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcessAsUserW", "ShellExecuteExW"],
  },
  {
    category: "anti-analysis",
    level: "high",
    apis: ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread", "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter", "IsWow64Process"],
  },
  {
    category: "credential-theft",
    level: "high",
    apis: ["GetAsyncKeyState", "GetForegroundWindow", "GetKeyState", "CryptUnprotectData"],
  },
  {
    category: "network",
    level: "medium",
    apis: ["InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect", "send", "recv"],
  },
  {
    category: "persistence",
    level: "medium",
    apis: ["RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"],
  },
  {
    category: "crypto",
    level: "medium",
    apis: ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptCreateHash", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey"],
  },
];

const PACKER_SECTION_NAMES = /^(upx\d?|\.aspack|\.adata|themida|vmp\d?|petite|\.nsp\d|pebundle)$/i;
const HIGH_ENTROPY_THRESHOLD = 7.0;
const PACKED_ENTROPY_THRESHOLD = 7.5;
/** Standard MSVC/GCC/MinGW section names — their presence argues AGAINST packing. */
const STANDARD_SECTION_NAMES = /^(\.text|\.data|\.rdata|\.rsrc|\.reloc|\.bss|\.idata|\.edata|\.tls|\.pdata|\.xdata|\.didat|\.debug|\.CRT|\.tls|_RDATA)$/i;

/**
 * Packer heuristics with the Unity.dll lesson baked in: a large LTCG/MSVC
 * build carries .text entropy ~6.5 (normal compiled code), and DIE's bare
 * entropy trigger misfires on it. STRONG packer evidence (packer-named
 * sections, uninitialized executable sections) always wins; WEAK entropy
 * evidence is suppressed when every section name is standard — unless it
 * crosses the hard threshold (7.5+ entropy in .text-like sections is not
 * compiler output).
 */
function packedVerdict(
  binary: BinaryInfo,
  tables: PeTables | null,
  diePacked: boolean | null,
  sectionEntropies: TriageSection[],
  signatureValid: boolean | null,
): { packed: boolean; why: string[] } {
  const why: string[] = [];
  const strongEvidence: string[] = [];
  let entropyEvidence: string[] = [];

  if (tables !== null) {
    for (const section of tables.sections) {
      if (PACKER_SECTION_NAMES.test(section.name)) strongEvidence.push(`section table shows packer layout (${section.name})`);
      if (section.rawSize === 0 && section.virtualSize > 0 && (section.characteristics & 0x20000000) !== 0) {
        strongEvidence.push(`executable section ${section.name} has raw size 0 but virtual size 0x${section.virtualSize.toString(16)} (uninitialized packer section)`);
      }
    }
  }

  if (binary.entropy >= PACKED_ENTROPY_THRESHOLD) entropyEvidence.push(`whole-file entropy ${binary.entropy} >= ${PACKED_ENTROPY_THRESHOLD}`);
  if (diePacked === true) entropyEvidence.push("Detect It Easy entropy analysis reports the file as packed");
  const highEntropySections = sectionEntropies.filter((section) => (section.entropy ?? 0) >= PACKED_ENTROPY_THRESHOLD);
  const hardHighEntropy = sectionEntropies.filter((section) => (section.entropy ?? 0) >= PACKED_ENTROPY_THRESHOLD && (section.executable || section.rawSize > 0x1000));
  for (const section of highEntropySections.slice(0, 3)) {
    entropyEvidence.push(`section ${section.name} entropy ${section.entropy} >= ${PACKED_ENTROPY_THRESHOLD}`);
  }

  const allStandardSections = tables !== null && tables.sections.length > 0 && tables.sections.every((section) => STANDARD_SECTION_NAMES.test(section.name));
  if (allStandardSections && entropyEvidence.length > 0 && hardHighEntropy.length === 0) {
    // Suppress weak evidence on a standard layout: MSVC/LTCG builds trip
    // DIE's entropy trigger at .text ~6.5 without being packed in any sense.
    entropyEvidence = [`entropy hints (${entropyEvidence.join("; ")}) SUPPRESSED: every section name is standard compiler layout with no hard-threshold section — likely a false positive on an optimized build`];
  }

  why.push(...strongEvidence, ...entropyEvidence);

  // The strongest counter-evidence of all: a VALID Authenticode signature.
  // A signed file whose digest matches cannot also be packed (packing
  // rewrites the whole image), so the packed verdict is downgraded with
  // the reason stated.
  if (signatureValid === true && strongEvidence.length === 0 && why.length > 0) {
    const suppressed = why;
    return {
      packed: false,
      why: [`packed hints suppressed: the file carries a VALID Authenticode signature (digest+chain verified) — a packed image would not. Suppressed hints: ${suppressed.join("; ")}`],
    };
  }
  return { packed: why.length > 0, why };
}

export interface TriageOptions {
  /** Run capa inline when its artifact is not cached (slow: minutes). */
  includeCapabilities?: boolean;
  /** String-plane scan window (default 32MB; raise for large images, no ceiling). */
  maxScanBytes?: number;
  signal?: AbortSignal;
}

export interface TriageSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number | null;
  executable: boolean;
  writable: boolean;
}

export interface TriageImportRisk {
  level: "high" | "medium" | "low";
  categories: Array<{ category: string; level: "high" | "medium"; apis: Array<{ name: string; dll: string }> }>;
}

export interface TriageIocs {
  urls: string[];
  ips: string[];
  registry: string[];
  pdbPaths: string[];
  uncPaths: string[];
}

export interface TriageResult {
  path: string;
  sampleId: string;
  sha256: string;
  size: number;
  entropy: number;
  format: { kind: string; architecture: string; bits: number | null };
  verdict: {
    packed: boolean;
    packedWhy: string[];
    dotnet: boolean;
    riskLevel: "high" | "medium" | "low";
    notable: string[];
    /**
     * Honest-completeness guard (REMnux epistemology): static analysis of a
     * packed/.NET sample is INCOMPLETE by construction — the report says so
     * instead of implying false negatives ("no imports" ≠ "no behavior").
     */
    analysisIncomplete: boolean;
    incompleteWhy: string[];
    /**
     * Every claim here is labeled: OBSERVED (present in the file as data or
     * code matched by a rule) vs CAPABLE (code that would do it if run) —
     * artifact-vs-behavior separation the agent must not blur.
     */
    evidenceNotes: string[];
  };
  sections: TriageSection[];
  /**
   * Degradation-safe planes: ALWAYS objects (never null — hosts validate
   * output schemas). Empty + a `degraded` note when the plane does not
   * apply (non-PE) or its backend is unavailable.
   */
  imports: {
    dllCount: number;
    functionCount: number;
    dlls: string[];
    risk: TriageImportRisk;
  };
  exports: { count: number; names: string[] };
  resources: {
    types: Array<{ typeName: string | null; entryCount: number }>;
    versionInfo: Record<string, string> | null;
  };
  strings: { count: number; iocs: TriageIocs };
  packer: { filetypes: string[]; detections: unknown[]; entropyStatus: string | null; entropyRecords: unknown[]; available: boolean };
  embedded: { signatureCount: number; signatures: Array<{ offset: string; description: string }>; available: boolean };
  capabilities: { ruleCount: number; rules: unknown[]; available: boolean };
  planes: { consulted: string[]; degraded: Array<{ plane: string; reason: string }> };
  next: string[];
  fullReport: { artifactId: string; bytes: number; pageWith: string };
}

function collectMatches(text: string, regex: RegExp, cap: number): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(regex)) {
    const value = match[0];
    if (value === undefined) continue;
    if (!found.includes(value)) found.push(value);
    if (found.length >= cap) break;
  }
  return found;
}

export function mineIocs(values: string[]): TriageIocs {
  const text = values.join("\n");
  return {
    urls: collectMatches(text, /\b(?:https?|ftp):\/\/[^\s"'<>\\]{4,}/g, TRIAGE_MAX_IOCS),
    ips: collectMatches(text, /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, TRIAGE_MAX_IOCS)
      .filter((ip) => ip !== "0.0.0.0" && ip !== "255.255.255.255" && ip !== "127.0.0.1"),
    registry: collectMatches(text, /\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"]{4,}/gi, TRIAGE_MAX_IOCS),
    pdbPaths: collectMatches(text, /\b[A-Za-z]:\\[^\s"]+\.pdb\b/gi, TRIAGE_MAX_IOCS),
    uncPaths: collectMatches(text, /\\\\[A-Za-z0-9_.-]+\\[^\s"]{2,}/g, TRIAGE_MAX_IOCS),
  };
}

export function classifyImportRisk(imports: Array<{ dll: string; name: string }>): TriageImportRisk {
  const categories: Array<{ category: string; level: "high" | "medium"; apis: Array<{ name: string; dll: string }> }> = [];
  let highest: "high" | "medium" | "low" = "low";
  for (const group of API_RISK) {
    const apis: Array<{ name: string; dll: string }> = [];
    for (const entry of imports) {
      if (group.apis.includes(entry.name) && !apis.some((api) => api.name === entry.name)) {
        apis.push({ name: entry.name, dll: entry.dll });
      }
    }
    if (apis.length > 0) {
      categories.push({ category: group.category, level: group.level, apis });
      if (group.level === "high") highest = "high";
      else if (highest === "low") highest = "medium";
    }
  }
  return { level: highest, categories };
}

function sectionEntropy(dieEntropyRecords: Array<{ name?: unknown; entropy?: unknown }> | undefined, sectionName: string): number | null {
  for (const record of dieEntropyRecords ?? []) {
    if (typeof record.name === "string" && record.name === sectionName && typeof record.entropy === "number") {
      return record.entropy;
    }
  }
  return null;
}

/** Cache key of packer.detect — triage shares it so both ops feed one artifact. */
function dieCacheKey(sha256: string): string {
  return cacheKeyDigest({
    sample: sha256,
    operation: "packer.detect",
    options: {},
    image: resolveDockerImage(process.env.MINUSONE_DIE_IMAGE, DEFAULT_IMAGES.die),
    local: process.env.MINUSONE_DIE_BIN ?? null,
    schema: 1,
  });
}

function binwalkCacheKey(sha256: string): string {
  return cacheKeyDigest({
    sample: sha256,
    operation: "embedded.scan",
    image: resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk),
    local: process.env.MINUSONE_BINWALK_BIN ?? null,
    schema: 1,
  });
}

function capaCacheKey(sha256: string): string {
  return cacheKeyDigest({
    sample: sha256,
    operation: "capabilities.detect",
    image: resolveDockerImage(process.env.MINUSONE_CAPA_IMAGE, DEFAULT_IMAGES.capa),
    local: process.env.MINUSONE_CAPA_BIN ?? null,
    rules: process.env.MINUSONE_CAPA_RULES ?? "bundled",
  });
}

export async function triageBinary(workspace: Workspace, userPath: string, options: TriageOptions = {}): Promise<TriageResult> {
  const consulted: string[] = [];
  const degraded: Array<{ plane: string; reason: string }> = [];

  // ---- native planes ------------------------------------------------------
  const binary = await inspectBinary(workspace, userPath);
  consulted.push("binary");
  const tables = binary.format.kind === "pe" ? await parsePeTables(workspace, userPath) : null;
  if (tables !== null) consulted.push("pe-tables");
  else if (binary.format.kind !== "pe") degraded.push({ plane: "pe-tables", reason: `requires a PE file (detected format: ${binary.format.kind})` });

  const stringsExtraction = await extractStrings(workspace, userPath, {
    limit: TRIAGE_STRINGS_LIMIT,
    maxScanBytes: Math.max(1024, Math.floor(options.maxScanBytes ?? TRIAGE_DEFAULT_SCAN_BYTES)),
  });
  consulted.push("strings");
  const iocs = mineIocs(stringsExtraction.strings.map((entry) => entry.value));

  let resources: Awaited<ReturnType<typeof parsePeResources>> | null = null;
  if (binary.format.kind === "pe") {
    try {
      resources = await parsePeResources(workspace, userPath);
      consulted.push("resources");
    } catch (error) {
      degraded.push({ plane: "resources", reason: `resource parse failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }

  // ---- Detect It Easy (inline; shares the packer.detect cache) -------------
  let dieSummary: ReturnType<typeof summarizeDieReport> | null = null;
  try {
    const cached = await findArtifactByCacheKey(workspace, dieCacheKey(binary.sha256));
    if (cached !== null) {
      dieSummary = summarizeDieReport(JSON.parse(await readArtifactFull(workspace, cached.id)) as { detections?: unknown; entropy?: unknown });
      consulted.push("packer (cached)");
    } else {
      const result = await runDieDetection(workspace, userPath, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (result.command.exitCode === 0 && !result.command.timedOut && result.report !== undefined) {
        await storeArtifact(workspace, JSON.stringify(result.report, null, 2), {
          mediaType: "application/json",
          sourceOperation: "packer.detect",
          description: `Detect It Easy identification (${result.backend} backend)`,
          sampleId: binary.sampleId,
          cacheKey: dieCacheKey(binary.sha256),
          backend: result.backend,
        });
        dieSummary = summarizeDieReport(result.report);
        consulted.push("packer");
      } else {
        degraded.push({ plane: "packer", reason: `diec exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}` });
      }
    }
  } catch (error) {
    degraded.push({ plane: "packer", reason: error instanceof Error ? error.message : String(error) });
  }

  // ---- binwalk embedded scan (inline; shares the embedded.scan cache) ------
  let embedded: TriageResult["embedded"] | null = null;
  try {
    const cached = await findArtifactByCacheKey(workspace, binwalkCacheKey(binary.sha256));
    if (cached !== null) {
      const parsed = JSON.parse(await readArtifactFull(workspace, cached.id)) as { signatures: Array<{ offset: string; description: string }>; truncated: boolean };
      embedded = { signatureCount: parsed.signatures.length, signatures: parsed.signatures.slice(0, 20), available: true };
      consulted.push("embedded (cached)");
    } else {
      const result = await runBinwalkScan(workspace, userPath, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (result.command.exitCode === 0 && !result.command.timedOut) {
        await storeArtifact(workspace, JSON.stringify({ signatures: result.signatures, truncated: result.truncated }, null, 2), {
          mediaType: "application/json",
          sourceOperation: "embedded.scan",
          description: `binwalk signature scan (${result.backend} backend, scan-only)`,
          sampleId: binary.sampleId,
          cacheKey: binwalkCacheKey(binary.sha256),
          backend: result.backend,
        });
        embedded = {
          signatureCount: result.signatures.length,
          signatures: result.signatures.slice(0, 20).map((signature) => ({
            offset: signature.offset,
            description: signature.description.slice(0, TRIAGE_MAX_SIGNAME_CHARS),
          })),
          available: true,
        };
        consulted.push("embedded");
      } else {
        degraded.push({ plane: "embedded", reason: `binwalk exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}` });
      }
    }
  } catch (error) {
    degraded.push({ plane: "embedded", reason: error instanceof Error ? error.message : String(error) });
  }

  // ---- capa (cache-only unless opted in) ------------------------------------
  let capabilities: TriageResult["capabilities"] | null = null;
  try {
    const cached = await findArtifactByCacheKey(workspace, capaCacheKey(binary.sha256));
    if (cached !== null) {
      const summary = summarizeCapaReport(JSON.parse(await readArtifactFull(workspace, cached.id)));
      capabilities = { ruleCount: summary.ruleCount, rules: summary.rules, available: true };
      consulted.push("capabilities (cached)");
    } else if (options.includeCapabilities === true) {
      const result = await runCapaAnalysis(workspace, userPath, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (result.command.exitCode === 0 && !result.command.timedOut && result.report !== undefined) {
        await storeArtifact(workspace, JSON.stringify(result.report, null, 2), {
          mediaType: "application/json",
          sourceOperation: "capabilities.detect",
          description: `capa capability detection (${result.backend} backend)`,
          sampleId: binary.sampleId,
          cacheKey: capaCacheKey(binary.sha256),
          backend: result.backend,
        });
        const summary = summarizeCapaReport(result.report);
        capabilities = { ruleCount: summary.ruleCount, rules: summary.rules, available: true };
        consulted.push("capabilities");
      } else {
        degraded.push({ plane: "capabilities", reason: `capa exited with code ${result.command.exitCode ?? -1}${result.command.timedOut ? " (timed out)" : ""}` });
      }
    } else {
      degraded.push({ plane: "capabilities", reason: "not cached; run capabilities_detect first (or pass includeCapabilities: true — capa takes minutes)" });
    }
  } catch (error) {
    degraded.push({ plane: "capabilities", reason: error instanceof Error ? error.message : String(error) });
  }

  // ---- fusion ----------------------------------------------------------------
  const entropyRecords = (dieSummary?.entropyRecords ?? []) as Array<{ name?: unknown; entropy?: unknown }>;
  const sections: TriageSection[] = (tables?.sections ?? []).map((section) => ({
    name: section.name,
    virtualSize: section.virtualSize,
    rawSize: section.rawSize,
    entropy: sectionEntropy(entropyRecords, section.name),
    executable: (section.characteristics & 0x20000000) !== 0,
    writable: (section.characteristics & 0x80000000) !== 0,
  }));

  const imports = tables === null ? null : {
    dllCount: tables.importDlls.length,
    functionCount: tables.imports.length,
    dlls: tables.importDlls.slice(0, 64),
    risk: classifyImportRisk(tables.imports),
  };
  const dotnet = tables?.importDlls.some((dll) => dll.toLowerCase() === "mscoree.dll") ?? false;

  // Signature cross-check (Windows native): a VALID Authenticode signature
  // is decisive counter-evidence against "packed" — the Unity.dll lesson.
  let signatureValid: boolean | null = null;
  let signatureNote: string | null = null;
  try {
    const signature = await verifySignature(workspace, userPath);
    signatureValid = signature.valid;
    if (signature.valid) signatureNote = `valid Authenticode signature (${signature.signerCommonName ?? signature.signer ?? "unknown signer"})`;
    else if (signature.signaturePresent) signatureNote = `signature present, OS verdict: ${signature.status ?? "unknown"}`;
  } catch {
    // Signature plane is optional: absence never blocks triage.
  }

  const packed = packedVerdict(binary, tables, dieSummary === null ? null : dieSummary.packed, sections, signatureValid);

  const notable: string[] = [];
  if (signatureNote !== null) notable.push(signatureNote);
  if (dotnet) notable.push(".NET assembly (imports mscoree.dll) — decompile with a .NET-aware tool");
  if (binary.entropy >= HIGH_ENTROPY_THRESHOLD) notable.push(`whole-file entropy ${binary.entropy} (>= ${HIGH_ENTROPY_THRESHOLD}) — compressed or encrypted content likely`);
  if (tables !== null && tables.exports.length > 0) notable.push(`exports ${tables.exports.length} function(s)${tables.exportDll !== null ? ` as ${tables.exportDll}` : ""}`);
  if (imports !== null && imports.risk.level === "high") notable.push("high-risk import categories present (see imports.risk)");
  if (resources?.versionInfo != null) {
    const info = resources.versionInfo.strings;
    const signature = [info.CompanyName, info.ProductName, info.FileDescription].filter(Boolean).join(" / ");
    if (signature !== "") notable.push(`version info: ${signature}`);
  }
  const iocCount = iocs.urls.length + iocs.ips.length + iocs.registry.length + iocs.pdbPaths.length + iocs.uncPaths.length;
  if (iocCount > 0) notable.push(`${iocCount} IOC-like string(s) mined (URLs/IPs/registry/PDB/UNC)`);

  // ---- evidence discipline: what this report can and cannot claim -----------
  const incompleteWhy: string[] = [];
  if (packed.packed) {
    incompleteWhy.push("packed sample: the visible sections are compressed — static strings/imports describe the PACKER, not the payload; unpack (unpack_static / dynamic_unpack / unpack_chain) before behavior claims");
  }
  if (dotnet) {
    incompleteWhy.push(".NET assembly: native import analysis sees the mscoree stub only — behavior lives in managed metadata not parsed here");
  }
  if (imports !== null && imports.functionCount === 0 && binary.format.kind === "pe" && !packed.packed) {
    incompleteWhy.push("a PE with zero imports likely resolves APIs dynamically (GetProcAddress/hash-walking) — import-based behavior inference does not apply");
  }
  const evidenceNotes: string[] = [
    "all string/IOC findings are OBSERVED-as-data only: a URL in the binary is evidence of presence, not of network behavior — confirm with trace_source / dynamic_recon",
  ];
  if (imports !== null && imports.risk.level !== "low") {
    evidenceNotes.push("import categories are CAPABILITY evidence (code that could call them exists), not behavior evidence — capa (capabilities_detect) and dynamics confirm what actually runs");
  }
  if (capabilities !== null && capabilities.ruleCount > 0) {
    evidenceNotes.push("capa matches are static CAPABILITY findings (behavior_capable), not observed behavior (artifact vs behavior distinction)");
  }
  if (iocCount === 0 && !packed.packed) {
    evidenceNotes.push("no IOC-like strings found in the scanned window — this is an absence of evidence, NOT evidence of absence (obfuscated strings need strings_extract_deep)");
  }
  if (signatureNote !== null) {
    evidenceNotes.push(`Authenticode: ${signatureNote} (signature_verify for the full report)`);
  }

  // ---- contextual next steps --------------------------------------------------
  const next: string[] = [];
  if (packed.packed) {
    next.push("the sample looks packed — run dynamic_unpack (armed local plane) to dump the unpacked image, then binary_find / dumps_floss on the dump");
  }
  if (imports !== null && imports.risk.level !== "low") {
    next.push(`imports show ${imports.risk.categories.map((category) => category.category).join(", ")} — map them to behavior with capabilities_detect, then to code with binary_find (kind "api")`);
  }
  if (capabilities === null) {
    next.push("run capabilities_detect for ATT&CK-mapped capabilities (capa)");
  }
  if (iocCount > 0) {
    next.push("IOC strings found — extract the full list with strings_extract and hunt across the estate with rules_scan");
  }
  if (stringsExtraction.strings.length === 0 && binary.format.kind !== "unknown") {
    next.push("no plaintext strings — obfuscated sample: try strings_extract_deep (FLOSS emulates decoders) after unpacking");
  }
  if (embedded !== null && embedded.signatureCount > 0) {
    next.push(`binwalk sees ${embedded.signatureCount} embedded signature(s) — carve them with embedded_extract`);
  }
  next.push("enumerate functions with disassembly_functions, then decompile the interesting ones with function_decompile");

  const report: Omit<TriageResult, "fullReport"> = {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    size: binary.size,
    entropy: binary.entropy,
    format: { kind: binary.format.kind, architecture: binary.format.architecture, bits: binary.format.bits },
    verdict: {
      packed: packed.packed,
      packedWhy: packed.why,
      dotnet,
      riskLevel: imports === null ? "low" : imports.risk.level,
      notable,
      analysisIncomplete: incompleteWhy.length > 0,
      incompleteWhy,
      evidenceNotes,
    },
    sections,
    imports: imports === null
      ? { dllCount: 0, functionCount: 0, dlls: [], risk: { level: "low", categories: [] } }
      : imports,
    exports: tables === null
      ? { count: 0, names: [] }
      : { count: tables.exports.length, names: tables.exports.slice(0, TRIAGE_MAX_EXPORTS).map((entry) => entry.name) },
    resources: resources === null
      ? { types: [], versionInfo: null }
      : {
          types: resources.types.map((type) => ({ typeName: type.typeName, entryCount: type.entryCount })),
          versionInfo: resources.versionInfo === null ? null : resources.versionInfo.strings,
        },
    strings: { count: stringsExtraction.strings.length, iocs },
    // Always objects (null breaks dsh output validation when a backend is
    // down): `available: false` + planes.degraded carries the reason.
    packer: dieSummary === null
      ? { filetypes: [], detections: [], entropyStatus: null, entropyRecords: [], available: false }
      : {
          filetypes: dieSummary.filetypes,
          detections: dieSummary.detections.slice(0, 8),
          entropyStatus: dieSummary.entropyStatus,
          entropyRecords: dieSummary.entropyRecords.slice(0, 32),
          available: true,
        },
    embedded: embedded === null
      ? { signatureCount: 0, signatures: [], available: false }
      : { ...embedded, available: true },
    capabilities: capabilities === null
      ? { ruleCount: 0, rules: [], available: false }
      : { ...capabilities, available: true },
    planes: { consulted, degraded },
    next,
  };

  const triageKey = cacheKeyDigest({
    sample: binary.sha256,
    operation: "binary.triage",
    includeCapabilities: options.includeCapabilities === true,
    dieImage: resolveDockerImage(process.env.MINUSONE_DIE_IMAGE, DEFAULT_IMAGES.die),
    binwalkImage: resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk),
    capaImage: resolveDockerImage(process.env.MINUSONE_CAPA_IMAGE, DEFAULT_IMAGES.capa),
    schema: 1,
  });
  const artifact = await storeArtifact(workspace, JSON.stringify(report, null, 2), {
    mediaType: "application/json",
    sourceOperation: "binary.triage",
    description: "Fused triage report (format, sections, imports, exports, resources, IOCs, packer, embedded, capabilities)",
    sampleId: binary.sampleId,
    cacheKey: triageKey,
  });

  return { ...report, fullReport: { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" } };
}
