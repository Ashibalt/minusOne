/**
 * Dossier extractors — the assembled layer of the campaign store. Every
 * task result lands in the dossier twice: RAW (full operation output, in
 * the CAS by pointer) and ASSEMBLED (a deterministic per-family structured
 * form, inline) — the difference between "a pile of tool output" and "data
 * the agent can reason over without re-parsing chaos".
 *
 * Extractors are TOLERANT: they pull the fields they know and skip the
 * rest, never throw, and never invent data. An operation family without a
 * smart extractor still gets the generic form (top-level keys + a bounded
 * preview) — structure exists for all 70+ operations.
 */

const GENERIC_PREVIEW_CHARS = 4000;
const STRINGS_HITS_CAP = 50;
const SECTIONS_CAP = 40;

type AnyRecord = Record<string, unknown>;

function asRecord(value: unknown): AnyRecord | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as AnyRecord) : null;
}

function pick(source: AnyRecord, keys: string[]): AnyRecord {
  const out: AnyRecord = {};
  for (const key of keys) {
    if (source[key] !== undefined) out[key] = source[key];
  }
  return out;
}

function pickArray(source: unknown, mapper: (entry: AnyRecord) => AnyRecord, cap: number): AnyRecord[] {
  if (!Array.isArray(source)) return [];
  const out: AnyRecord[] = [];
  for (const entry of source.slice(0, cap)) {
    const record = asRecord(entry);
    if (record !== null) out.push(mapper(record));
  }
  return out;
}

/** binary_triage → verdict/entropy/iocs/imports-by-risk/sections. */
function extractTriage(raw: AnyRecord): AnyRecord {
  const verdict = asRecord(raw.verdict) ?? {};
  const imports = asRecord(raw.imports) ?? {};
  const risk = asRecord(imports.risk) ?? {};
  const strings = asRecord(raw.strings) ?? {};
  return {
    path: raw.path,
    sha256: raw.sha256,
    size: raw.size,
    entropy: raw.entropy,
    format: raw.format,
    verdict: pick(verdict, ["packed", "packedWhy", "dotnet", "riskLevel", "notable", "analysisIncomplete", "incompleteWhy"]),
    sections: pickArray(raw.sections, (section) => pick(section, ["name", "virtualSize", "rawSize", "entropy", "executable"]), SECTIONS_CAP),
    imports: {
      dllCount: imports.dllCount,
      functionCount: imports.functionCount,
      risk: {
        level: risk.level,
        categories: pickArray(risk.categories, (category) => ({
          category: category.category,
          level: category.level,
          apiCount: Array.isArray(category.apis) ? category.apis.length : 0,
        }), 20),
      },
    },
    strings: { count: strings.count, iocs: strings.iocs },
    next: Array.isArray(raw.next) ? raw.next.slice(0, 5) : [],
    fullReport: raw.fullReport,
  };
}

/** strings_find (any mode) → mode, hit count, bounded hit previews. */
function extractStringsFind(raw: AnyRecord): AnyRecord {
  return {
    mode: raw.mode,
    needle: raw.needle,
    hitsCount: Array.isArray(raw.hits) ? raw.hits.length : raw.hitsCount,
    truncated: raw.truncated,
    hits: pickArray(raw.hits, (hit) => pick(hit, ["plane", "offset", "section", "rva", "va", "text", "symbol", "functionName"]), STRINGS_HITS_CAP),
  };
}

/** ida_decompile / function_decompile(_range) → per-function pseudocode + callers. */
function extractDecompile(raw: AnyRecord): AnyRecord {
  const functions = Array.isArray(raw.decompiled) ? raw.decompiled : raw.functions;
  return {
    backend: raw.backend,
    functions: pickArray(functions, (fn) => ({
      name: fn.name ?? fn.target ?? null,
      va: fn.start ?? fn.entryPoint ?? null,
      pseudocode: fn.pseudocode ?? fn.pseudocodePreview ?? fn.decompiledCode ?? null,
      truncated: fn.truncated ?? false,
      callers: Array.isArray(fn.callers) ? fn.callers.slice(0, 10) : [],
    }), 64),
    fullReport: raw.fullReport,
  };
}

/** unpack_static / unpack_chain → packed verdict + output artifact identity. */
function extractUnpack(raw: AnyRecord): AnyRecord {
  return pick(raw, ["backend", "packed", "outputPath", "outputSha256", "outputBytes", "ratio", "notes", "stages", "rebuilt", "dumpDir"]);
}

/** config_extract → harvested fields with evidence. */
function extractConfig(raw: AnyRecord): AnyRecord {
  return {
    extractionDepth: raw.extractionDepth,
    family: raw.family,
    fields: pickArray(raw.fields, (field) => pick(field, ["key", "value", "confidence", "evidence"]), 100),
  };
}

/** signature_verify → signed/valid/signer/verdict. */
function extractSignature(raw: AnyRecord): AnyRecord {
  return pick(raw, ["signaturePresent", "valid", "status", "signer", "signerCommonName", "verdict"]);
}

/** emu.run → status, registers, memory regions (bounded), notes. */
function extractEmuRun(raw: AnyRecord): AnyRecord {
  return {
    status: raw.status,
    error: raw.error,
    registers: raw.registers,
    memory: pickArray(raw.memory, (region) => ({
      address: region.address,
      writtenBytes: region.writtenBytes,
      bytesHex: typeof region.bytesHex === "string" ? region.bytesHex.slice(0, 2048) : region.bytesHex,
    }), 16),
    notes: raw.notes,
  };
}

/** emu.chain → stepsCompleted + per-step registers/memory digests. */
function extractEmuChain(raw: AnyRecord): AnyRecord {
  return {
    status: raw.status,
    stepsCompleted: raw.stepsCompleted,
    steps: pickArray(raw.steps, (step) => ({
      step: step.step,
      status: step.status,
      error: step.error,
      registers: step.registers,
      memory: pickArray(step.memory, (region) => ({
        address: region.address,
        writtenBytes: region.writtenBytes,
        bytesHex: typeof region.bytesHex === "string" ? region.bytesHex.slice(0, 512) : region.bytesHex,
      }), 8),
    }), 16),
    stepsArtifact: raw.stepsArtifact,
  };
}

/** emu.diff → the oracle verdict: match + first diverging byte. */
function extractEmuDiff(raw: AnyRecord): AnyRecord {
  return pick(raw, ["status", "match", "comparedBytes", "divergenceCount", "firstDivergence", "divergenceOffsets", "lengthMismatch", "referenceOutputHex", "candidateOutputHex"]);
}

/** Every other operation: top-level keys + a bounded JSON preview. */
function extractGeneric(raw: unknown): AnyRecord {
  const record = asRecord(raw);
  const preview = JSON.stringify(raw ?? null).slice(0, GENERIC_PREVIEW_CHARS);
  if (record === null) return { preview };
  return { keys: Object.keys(record), preview };
}

const EXTRACTORS: Record<string, (raw: AnyRecord) => AnyRecord> = {
  binary_triage: extractTriage,
  strings_find: extractStringsFind,
  ida_decompile: extractDecompile,
  function_decompile: extractDecompile,
  function_decompile_range: extractDecompile,
  unpack_static: extractUnpack,
  unpack_chain: extractUnpack,
  config_extract: extractConfig,
  signature_verify: extractSignature,
  emu_run: extractEmuRun,
  emu_chain: extractEmuChain,
  emu_diff: extractEmuDiff,
};

/**
 * The assembled form of an operation result. Never throws: a family with
 * no smart extractor gets the generic form; a broken result shape degrades
 * to whatever fields could be picked.
 */
export function extractDossierResult(toolName: string, raw: unknown): unknown {
  const extractor = EXTRACTORS[toolName];
  if (extractor === undefined) return extractGeneric(raw);
  const record = asRecord(raw);
  if (record === null) return extractGeneric(raw);
  try {
    return extractor(record);
  } catch {
    return extractGeneric(raw);
  }
}
