/**
 * config.extract — heuristic malware-configuration extraction. Family
 * parsers (CAPE/MWCP/rat_king_parser) are the deep path; this is the
 * zero-dependency layer that already beats an hour of manual strings
 * reading: the sample's decoded strings (FLOSS when available, plain
 * strings otherwise) plus imports are run through field heuristics that
 * know what RAT/loader configs look like — C2 endpoints (host:port,
 * scheme URLs), campaign/build IDs, mutexes, registry persistence keys,
 * PDB paths, base64 blobs — and every candidate carries the evidence
 * trail (where it was found, which decoder address produced it) plus a
 * confidence label, so nothing is presented as fact without its source.
 * Family detection runs a signature catalogue; a match narrows the
 * report's framing but the field heuristics stay family-agnostic.
 */
import { inspectBinary } from "./binary.js";
import { parsePeTables } from "./peimports.js";
import { extractStrings } from "./strings.js";
import { runFlossExtraction } from "./floss.js";
import type { Workspace } from "./workspace.js";

export const CONFIG_MAX_FIELDS = 128;
export const CONFIG_MAX_STRING_SOURCE = 50_000;

export interface ConfigField {
  key: string;
  value: string;
  /** Where the value came from: static strings, FLOSS decoder, imports. */
  evidence: string;
  /** high = structural match in decoded strings; medium = pattern match;
   *  low = weak pattern that needs analyst confirmation. */
  confidence: "high" | "medium" | "low";
}

export interface ConfigFamily {
  family: string;
  matchedOn: string;
}

export interface ConfigExtractResult {
  path: string;
  sampleId: string;
  sha256: string;
  families: ConfigFamily[];
  fields: ConfigField[];
  fieldCount: number;
  /** Extraction completeness: FLOSS (decoded strings) sees obfuscated
   *  configs; plain-strings mode misses what packers/crypters hide. */
  extractionDepth: "floss" | "static-strings";
  notes: string[];
  next: string[];
}

interface FamilyContext {
  stringText: string;
  imports: Set<string>;
  sections: Array<{ name: string }>;
}

/** Family signatures: section layouts + marker strings. */
const FAMILY_SIGNATURES: Array<{ family: string; markers: string[]; sectionHint?: RegExp }> = [
  { family: "AsyncRAT", markers: ["asyncrat", "installedpath"] },
  { family: "QuasarRAT", markers: ["quasar"] },
  { family: "XWorm", markers: ["xworm"] },
  { family: "Remcos", markers: ["remcos"] },
  { family: "njRAT", markers: ["njrat", "njq8"] },
  { family: "Warzone/AveMaria", markers: ["warzone", "avemaria"] },
  { family: "UPX-packed loader", markers: [], sectionHint: /^upx/i },
];

const HOSTPORT = /\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,16}|(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)):(\d{2,5})\b/g;
const URL_PATTERN = /\b(?:https?|ftp|ws|wss|tcp):\/\/[^\s"'<>\\]{4,}/gi;
const MUTEX = /\b(?:Global\\|Local\\)?(?:MTX|Mutex|Mtx|SEM)[A-Za-z0-9_]{2,64}\b/g;
const REG_PERSISTENCE = /\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\(?:Software|System)\\[^\s"]{4,}/gi;
const CAMPAIGN_ID = /\b(?:Campaign|CampaignID|BuildID|Version|InstallID|BotID|HWID|Group)[=: ]{1,3}([A-Za-z0-9_-]{2,32})\b/g;
const PDB = /\b[A-Za-z]:\\[^\s"]+\.pdb\b/gi;
const BASE64_BLOB = /\b[A-Za-z0-9+/]{24,}={0,2}\b/g;
const KEY_HINT = /\b(?:key|aes|rc4|xor|password|pass|token|secret)[=: ]{1,3}([A-Za-z0-9!@#$%^&*()_+\-]{4,64})\b/gi;

function pushField(fields: ConfigField[], field: ConfigField): void {
  if (fields.length >= CONFIG_MAX_FIELDS) return;
  if (fields.some((existing) => existing.key === field.key && existing.value === field.value)) return;
  fields.push(field);
}

/** Base64 that decodes to mostly-printable text (a payload string, not
 *  random bytes that happen to be base64-alphabet). */
export function decodeBase64Candidate(value: string): string | null {
  try {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    if (decoded.length < 6) return null;
    const printable = [...decoded].filter((char) => char.charCodeAt(0) >= 0x20 && char.charCodeAt(0) <= 0x7e).length;
    return printable / decoded.length > 0.9 ? decoded : null;
  } catch {
    return null;
  }
}

interface StringSource {
  value: string;
  evidence: string;
  confidence: "high" | "medium" | "low";
}

interface FlossReportShape {
  decoded_strings?: Array<{ string?: unknown; decoding_routine?: unknown }>;
  static_strings?: Array<{ string?: unknown }>;
}

export async function extractConfig(
  workspace: Workspace,
  userPath: string,
  options: { useFloss?: boolean; timeoutSeconds?: number; signal?: AbortSignal } = {},
): Promise<ConfigExtractResult> {
  const binary = await inspectBinary(workspace, userPath);
  const notes: string[] = [];
  const next: string[] = [];

  // ---- string sources: FLOSS decoded strings first, static fallback -------
  let sources: StringSource[] = [];
  let depth: ConfigExtractResult["extractionDepth"] = "static-strings";

  if (options.useFloss !== false) {
    try {
      const floss = await runFlossExtraction(workspace, userPath, {
        ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      const report = floss.report as FlossReportShape | undefined | null;
      for (const entry of report?.decoded_strings ?? []) {
        if (typeof entry.string === "string") {
          const routine = typeof entry.decoding_routine === "string" ? entry.decoding_routine : "";
          sources.push({
            value: entry.string,
            evidence: `FLOSS decoded${routine !== "" ? ` (decoder at ${routine})` : ""}`,
            confidence: "high",
          });
        }
      }
      for (const entry of report?.static_strings ?? []) {
        if (typeof entry.string === "string") {
          sources.push({ value: entry.string, evidence: "FLOSS static strings", confidence: "medium" });
        }
      }
      if (sources.length > 0) depth = "floss";
    } catch (error) {
      notes.push(`FLOSS unavailable (${error instanceof Error ? error.message : String(error)}) — falling back to plain static strings; obfuscated config fields will be missed`);
    }
  }
  if (sources.length === 0) {
    const extraction = await extractStrings(workspace, userPath, { limit: CONFIG_MAX_STRING_SOURCE, maxScanBytes: 512 * 1024 * 1024 });
    sources = extraction.strings.map((entry) => ({
      value: entry.value,
      evidence: `static strings @ offset ${entry.offset}`,
      confidence: "medium",
    }));
    if (sources.length === 0) {
      notes.push("no strings extracted — the sample may be fully packed; run unpack_chain first");
    }
  }

  const stringText = sources.map((source) => source.value).join("\n");
  const lowered = stringText.toLowerCase();
  const tables = binary.format.kind === "pe" ? await parsePeTables(workspace, userPath) : null;
  const imports = new Set<string>((tables?.imports ?? []).map((entry) => entry.name.toLowerCase()));
  const sections = (tables?.sections ?? []).map((section) => ({ name: section.name }));

  // ---- family detection --------------------------------------------------------
  const families: ConfigFamily[] = [];
  const context: FamilyContext = { stringText: lowered, imports, sections };
  for (const signature of FAMILY_SIGNATURES) {
    if (signature.sectionHint !== undefined && sections.some((section) => signature.sectionHint?.test(section.name))) {
      families.push({ family: signature.family, matchedOn: "section layout" });
      continue;
    }
    const marker = signature.markers.find((candidate) => lowered.includes(candidate));
    if (marker !== undefined) {
      families.push({ family: signature.family, matchedOn: `marker string "${marker}"` });
    }
  }
  if (families.length === 0) {
    next.push("no family signature matched — the field heuristics below are family-agnostic; a CAPE/MWCP parser run adds family-specific fields");
  }

  // ---- field heuristics ---------------------------------------------------------
  const fields: ConfigField[] = [];
  const seen = new Set<string>();
  const addUnique = (key: string, value: string, evidence: string, confidence: ConfigField["confidence"]): void => {
    const dedupe = `${key}:${value}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);
    pushField(fields, { key, value, evidence, confidence });
  };

  for (const source of sources) {
    const value = source.value;

    for (const match of value.matchAll(HOSTPORT)) {
      const host = match[1];
      const port = Number(match[2]);
      if (host === undefined || match[2] === undefined || port <= 0 || port >= 65536) continue;
      addUnique("c2", `${host}:${port}`, source.evidence, source.confidence);
    }
    for (const match of value.matchAll(URL_PATTERN)) {
      if (match[0] !== undefined) addUnique("url", match[0], source.evidence, source.confidence);
    }
    for (const match of value.matchAll(MUTEX)) {
      if (match[0] !== undefined) addUnique("mutex", match[0], source.evidence, "medium");
    }
    for (const match of value.matchAll(REG_PERSISTENCE)) {
      if (match[0] !== undefined) addUnique("persistence.registry", match[0], source.evidence, "medium");
    }
    for (const match of value.matchAll(CAMPAIGN_ID)) {
      if (match[1] !== undefined) addUnique("campaignId", match[1], source.evidence, "low");
    }
    for (const match of value.matchAll(PDB)) {
      if (match[0] !== undefined) addUnique("pdbPath", match[0], source.evidence, "high");
    }
    for (const match of value.matchAll(KEY_HINT)) {
      if (match[1] !== undefined) addUnique("possibleKey", match[1], source.evidence, "low");
    }
    for (const match of value.matchAll(BASE64_BLOB)) {
      const blob = match[0];
      if (blob === undefined) continue;
      const decoded = decodeBase64Candidate(blob);
      if (decoded !== null) {
        addUnique("base64Decoded", decoded.slice(0, 256), `${source.evidence} (base64-decoded)`, "medium");
      }
    }
  }

  // ---- evidence discipline: the config is a hypothesis, not a verdict -------
  notes.push("every field carries its evidence source and confidence — C2 candidates in particular are OBSERVED-as-data, not confirmed behavior; verify with trace_source (needle: the C2 host)");
  if (depth === "static-strings") {
    notes.push("extraction ran on PLAIN strings only: obfuscated configs (the norm for RATs) need the FLOSS plane — fix the backend or the field list is partial by construction");
  }
  if (fields.length > 0) {
    next.push("record the confirmed fields with report_findings and hunt them across the estate with rules_scan");
  }

  return {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    families,
    fields,
    fieldCount: fields.length,
    extractionDepth: depth,
    notes,
    next,
  };
}
