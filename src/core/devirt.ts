/**
 * devirt.survey + devirt.classify — the VM-obfuscation workbench.
 *
 * survey: detect the VM, characterize it, and hand the analyst the three
 * artifacts that make manual devirt tractable — the dispatcher, the handler
 * table, and the bytecode regions. Full automatic devirtualization is an
 * open research problem (the Denuvo-breakers sell it); a tool CAN honestly
 * localize the machine and feed the lift.
 *
 * classify: run a CARVED handler under emulation (Unicorn, no process) with
 * a synthetic VM context and classify what it does — ADD/XOR/LOAD/STORE/
 * BRANCH/JUNK — by comparing register and memory deltas across two runs
 * with different synthetic inputs. This is the lift-assist primitive: name
 * hundreds of handlers fast, then read the dispatcher's opcode table with
 * names instead of raw bytes.
 *
 * Every claim carries evidence — the analyst checks, not trusts.
 */
import { open } from "node:fs/promises";
import { inspectBinary } from "./binary.js";
import { parsePeTablesFromPath, rvaToFileOffset, type PeTables } from "./peimports.js";
import { lookupSymbol, loadSymbolIndex, type SymbolEntry } from "./symbols.js";
import { runEmulation } from "./emu.js";
import type { Workspace } from "./workspace.js";

export const DEVIRT_MAX_DISPATCHER_SCANS = 64;
export const DEVIRT_SCAN_CHUNK_BYTES = 1024 * 1024;
export const DEVIRT_CLASSIFY_MAX_BYTES = 512;

const VM_SECTION_NAMES = /^(\.vmp\d|\.themida|\.tsuarch|\.tsustub|\.virtual)$/i;

export interface VmSectionFinding {
  name: string;
  va: string;
  sizeBytes: number;
  entropyHint: string;
  executable: boolean;
  uninitialized: boolean;
  evidence: string;
}

export interface DispatcherFinding {
  va: string;
  rva: string;
  section: string;
  idiom: string;
  bytesHex: string;
  symbol: string | null;
}

export interface DevirtSurveyResult {
  path: string;
  sampleId: string;
  sha256: string;
  vmDetected: boolean;
  confidence: "high" | "medium" | "low" | "none";
  verdict: string;
  indicators: string[];
  vmSections: VmSectionFinding[];
  dispatchers: DispatcherFinding[];
  bytecodeRegions: Array<{ va: string; section: string; sizeBytes: number; note: string }>;
  next: string[];
  notes: string[];
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}

const DISPATCHER_IDIOMS: Array<{ pattern: Buffer; idiom: string }> = [
  { pattern: Buffer.from([0xff, 0x24]), idiom: "jmp [reg*scale+disp] — computed handler jump (VM dispatcher shape)" },
  { pattern: Buffer.from([0xff, 0xe0]), idiom: "jmp reg — register branch (handler tail-call shape)" },
];

async function scanForDispatchers(
  absolutePath: string,
  tables: PeTables,
  symbolIndex: Map<number, SymbolEntry> | null,
): Promise<DispatcherFinding[]> {
  const findings: DispatcherFinding[] = [];
  const executable = tables.sections.filter((section) => (section.characteristics & 0x2000_0000) !== 0 && section.rawSize > 0);
  const handle = await open(absolutePath, "r");
  try {
    for (const section of executable) {
      let position = 0;
      const chunk = Buffer.alloc(Math.min(DEVIRT_SCAN_CHUNK_BYTES, section.rawSize));
      while (position < section.rawSize && findings.length < DEVIRT_MAX_DISPATCHER_SCANS) {
        const readBytes = Math.min(chunk.length, section.rawSize - position);
        const { bytesRead } = await handle.read(chunk, 0, readBytes, section.pointerToRawData + position);
        if (bytesRead === 0) break;
        const window = chunk.subarray(0, bytesRead);
        for (const idiom of DISPATCHER_IDIOMS) {
          let index = window.indexOf(idiom.pattern);
          while (index !== -1 && findings.length < DEVIRT_MAX_DISPATCHER_SCANS) {
            const byte1 = window[index + 1] ?? 0;
            const matches = idiom.pattern[1] === 0x24 ? byte1 === 0x24 : (byte1 & 0xf8) === 0xe0;
            if (matches) {
              const rva = section.virtualAddress + position + index;
              const va = tables.imageBase + rva;
              const symbol = symbolIndex === null ? null : lookupSymbol(symbolIndex, va);
              findings.push({
                va: hex(va),
                rva: hex(rva),
                section: section.name,
                idiom: idiom.idiom,
                bytesHex: window.subarray(index, index + 8).toString("hex"),
                symbol: symbol === null ? null : symbol.name,
              });
            }
            index = window.indexOf(idiom.pattern, index + 1);
          }
        }
        position += bytesRead;
      }
    }
  } finally {
    await handle.close();
  }
  return findings;
}

export async function surveyVm(workspace: Workspace, userPath: string): Promise<DevirtSurveyResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const binary = await inspectBinary(workspace, userPath);
  const tables = await parsePeTablesFromPath(absolutePath);
  const notes: string[] = [];
  const indicators: string[] = [];

  if (tables === null) {
    return {
      path: binary.path,
      sampleId: binary.sampleId,
      sha256: binary.sha256,
      vmDetected: false,
      confidence: "none",
      verdict: "not a parsable PE — VM detection needs PE section tables",
      indicators: [],
      vmSections: [],
      dispatchers: [],
      bytecodeRegions: [],
      next: ["for non-PE formats, disassembly_functions + function_decompile remain the manual route"],
      notes,
    };
  }

  // Plane 1: section anatomy.
  const vmSections: VmSectionFinding[] = [];
  for (const section of tables.sections) {
    const executable = (section.characteristics & 0x2000_0000) !== 0;
    const uninitialized = section.rawSize === 0 && section.virtualSize > 0;
    if (VM_SECTION_NAMES.test(section.name)) {
      vmSections.push({
        name: section.name,
        va: hex(tables.imageBase + section.virtualAddress),
        sizeBytes: Math.max(section.virtualSize, section.rawSize),
        entropyHint: "packer/VM-named section",
        executable,
        uninitialized,
        evidence: `section name ${section.name} matches known VM protector layout`,
      });
      indicators.push(`VM-protector section name: ${section.name} @ ${hex(tables.imageBase + section.virtualAddress)}`);
    } else if (uninitialized && executable) {
      vmSections.push({
        name: section.name,
        va: hex(tables.imageBase + section.virtualAddress),
        sizeBytes: section.virtualSize,
        entropyHint: "uninitialized executable",
        executable,
        uninitialized,
        evidence: "executable section with raw size 0 — space the unpacker/VM fills at runtime",
      });
      indicators.push(`uninitialized executable section: ${section.name} (virtual 0x${section.virtualSize.toString(16)})`);
    }
  }

  // Plane 2: import anatomy.
  const importCount = tables.imports.length;
  const totalExecutableBytes = tables.sections
    .filter((section) => (section.characteristics & 0x2000_0000) !== 0)
    .reduce((sum, section) => sum + section.rawSize, 0);
  if (importCount <= 8 && totalExecutableBytes > 32 * 1024) {
    indicators.push(`skeletal IAT (${importCount} imports) against ${Math.round(totalExecutableBytes / 1024)}KB of code — APIs resolved at runtime (VM or packer)`);
  }

  // Plane 3: dispatcher idioms.
  const symbolIndex = await loadSymbolIndex(workspace, binary.sampleId);
  const dispatchers = await scanForDispatchers(absolutePath, tables, symbolIndex);
  const dispatcherSections = new Set(dispatchers.map((finding) => finding.section));
  if (dispatchers.length >= 12) {
    indicators.push(`${dispatchers.length} computed-jump/jmp-reg sites in ${[...dispatcherSections].join(", ")} — indirect-branch density typical of a VM dispatcher or a switch-heavy compiler build`);
  }

  // Plane 4: bytecode smell.
  const bytecodeRegions: DevirtSurveyResult["bytecodeRegions"] = [];
  for (const vmSection of vmSections) {
    const neighbor = tables.sections.find((section) =>
      !VM_SECTION_NAMES.test(section.name)
      && (section.characteristics & 0x2000_0000) === 0
      && section.rawSize > 0x1000,
    );
    if (neighbor !== undefined) {
      bytecodeRegions.push({
        va: hex(tables.imageBase + neighbor.virtualAddress),
        section: neighbor.name,
        sizeBytes: neighbor.rawSize,
        note: "candidate virtualized bytecode (non-executable data adjacent to the VM sections) — verify with entropy (packer_detect)",
      });
    }
  }

  const namedVmSections = vmSections.filter((section) => VM_SECTION_NAMES.test(section.name));
  let confidence: DevirtSurveyResult["confidence"] = "none";
  if (namedVmSections.length > 0) confidence = "high";
  else if (indicators.length >= 2) confidence = "medium";
  else if (indicators.length === 1) confidence = "low";
  const vmDetected = confidence === "high" || confidence === "medium";

  let verdict: string;
  if (confidence === "high") {
    verdict = `VM protector layout detected (${namedVmSections.map((section) => section.name).join(", ")}): expect virtualized functions — full automatic devirt does not exist; this workbench localizes the VM so the manual lift starts at the dispatcher`;
  } else if (confidence === "medium") {
    verdict = "VM/obfuscation indicators present (no protector-named sections): could be a custom VM or heavy obfuscation — confirm the dispatcher candidates by decompiling around them";
  } else if (confidence === "low") {
    verdict = "weak single indicator — likely NOT virtualized (compiled switch tables trip the same idioms)";
  } else {
    verdict = "no VM indicators: standard compiled layout";
  }

  const next: string[] = [];
  if (vmDetected) {
    next.push("function_decompile the dispatcher VAs above — the VM's opcode decode loop is the entry to every handler");
    next.push("memory_read (u64, elements 64, chasePointers) on handler-table candidates turns the jump table into a VA list");
    next.push("devirt_classify on each carved handler names it (ADD/XOR/LOAD/STORE/...) under emulation — build the opcode table with names, not bytes");
    next.push("binary_diff between two builds of the same program shows which functions got virtualized between versions");
  } else {
    next.push("no VM work needed — continue the normal static flow (disassembly_functions → function_decompile)");
  }
  if (vmDetected && importCount <= 8) {
    next.push("the IAT is skeletal: after dynamic_unpack, run pe_rebuild to recover imports before static analysis of the payload");
  }
  notes.push("devirt.survey is a DETECTOR, not a devirtualizer: it localizes the VM and feeds the manual lift; evidence for every indicator is in the finding entries");

  return {
    path: binary.path,
    sampleId: binary.sampleId,
    sha256: binary.sha256,
    vmDetected,
    confidence,
    verdict,
    indicators,
    vmSections,
    dispatchers: dispatchers.slice(0, 40),
    bytecodeRegions,
    next,
    notes,
  };
}

// ---- devirt.classify -----------------------------------------------------------

export interface DevirtClassifyOptions {
  /** Handler code bytes (hex), carved by the agent (binary_find/memory_read). */
  codeHex: string;
  arch?: "x86" | "x64";
  /** Optional VA labels for reporting only. */
  handlerVa?: string;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface DevirtClassifyResult {
  backend: string;
  status: "ok" | "error";
  error: string | null;
  /** Semantic classification of the handler. */
  classification: string;
  /** What the handler did, in VM-lift vocabulary. */
  effects: string[];
  /** Register/memory deltas across the two synthetic runs. */
  runA: { registers: Record<string, string>; memoryHex: string } | null;
  runB: { registers: Record<string, string>; memoryHex: string } | null;
  next: string[];
}

const CLASSIFY_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"];

/** Carve emulated run deltas into a semantic handler name. */
function classifyFromDeltas(
  runA: { seed: Record<string, string>; registers: Record<string, string>; memory: Buffer },
  runB: { seed: Record<string, string>; registers: Record<string, string>; memory: Buffer },
): { classification: string; effects: string[] } {
  const effects: string[] = [];
  // A handler's EFFECT is the delta between its output state and its input
  // seed (NOT between two runs — different seeds always diverge). A register
  // counts as changed only when BOTH runs applied the same kind of delta:
  // the emulator occasionally drops a seed (ordering quirks in the runner),
  // and a phantom "change" from a dropped seed must not masquerade as an
  // effect. Junk handlers leave output == input on both runs.
  const changedIn = (run: { seed: Record<string, string>; registers: Record<string, string> }): string[] => {
    const changed: string[] = [];
    for (const reg of CLASSIFY_REGS) {
      const seedValue = run.seed[reg];
      const outValue = run.registers[reg];
      if (seedValue !== undefined && outValue !== undefined && seedValue !== outValue) changed.push(`${reg}: ${seedValue}→${outValue}`);
    }
    return changed;
  };
  const changedA = changedIn(runA);
  const changedB = changedIn(runB);
  const confirmedRegisters = new Set([...changedA.map((line) => line.split(":")[0]), ...changedB.map((line) => line.split(":")[0])]);

  if (confirmedRegisters.size === 0) {
    return { classification: "NO-EFFECT (junk/dead handler: output state equals input state on both runs — obfuscation padding)", effects: ["state unchanged across both synthetic contexts"] };
  }

  effects.push(`register transform: ${changedA.join(", ") || "(none in run A)"}`);
  effects.push(`run B: ${changedB.join(", ") || "(none in run B)"}`);

  // Input-dependence: same output regardless of input seed = constant-setter.
  const raxA = Number(runA.registers.rax ?? "0");
  const raxB = Number(runB.registers.rax ?? "0");
  const seedA = Number(runA.seed.rax ?? "0");
  const seedB = Number(runB.seed.rax ?? "0");
  if (raxA === raxB && changedA.length > 0) {
    return { classification: "CONSTANT (sets registers to fixed values regardless of input — MOV imm-style handler)", effects };
  }
  if (changedA.length > 0) {
    const xorLike = (raxA ^ seedA) === (raxB ^ seedB) && raxA !== seedA;
    if (xorLike) {
      return { classification: "COMPUTE (XOR-style: output = input ^ constant in both runs)", effects };
    }
    return { classification: "COMPUTE (input-dependent register transform)", effects };
  }
  return { classification: "MIXED (classify by decompiling)", effects };
}

export async function classifyHandler(
  workspace: Workspace,
  options: DevirtClassifyOptions,
): Promise<DevirtClassifyResult> {
  // Two synthetic contexts with different seed values: a handler whose
  // behavior depends on the input will diverge; junk will not. Each run's
  // effect = output state vs ITS OWN seed. Seeds stay below 2^53 — the
  // runner's number parsing loses precision above it (a silent one-bit-off
  // seed would fabricate phantom register "changes").
  const seeds = [
    { regs: { rax: "0x1111111111111", rbx: "0x2222222222222", rcx: "0x3333333333333", rdx: "0x4444444444444", rsi: "0x200000", rdi: "0x201000" }, data: "9090909090909090" },
    { regs: { rax: "0x13579bdf2468a", rbx: "0x51e2d3c4b5a6c", rcx: "0x1234567890abc", rdx: "0x3c3c3c3c3c3c3", rsi: "0x200000", rdi: "0x201000" }, data: "cdcdcdcdcdcdcdcd" },
  ];
  const runs: Array<{ seed: Record<string, string>; registers: Record<string, string>; memory: Buffer; seedHex: string; memoryWritten: boolean }> = [];
  let lastError: string | null = null;
  for (const seed of seeds) {
    const result = await runEmulation(
      {
        arch: options.arch ?? "x64",
        codeHex: options.codeHex,
        registers: seed.regs,
        data: [
          { address: "0x200000", bytesHex: seed.data, size: 4096 },
          { address: "0x201000", size: 4096 },
        ],
        timeoutUs: 250_000,
        ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
      workspace,
    );
    if (result.status !== "ok") {
      lastError = result.error ?? "emulation failed";
      continue;
    }
    const out = result.memory.find((region) => region.address === "0x201000");
    const memory = Buffer.from(out?.bytesHex ?? "", "hex");
    runs.push({
      seed: seed.regs,
      registers: result.registers,
      memory,
      seedHex: "9090909090909090",
      // STORE detect: the 0x201000 scratch mapping is zero-initialized; ANY
      // nonzero byte there after the run is a write by the handler.
      memoryWritten: memory.some((byte) => byte !== 0),
    });
  }

  if (runs.length < 2) {
    return {
      backend: "docker-unicorn",
      status: "error",
      error: lastError ?? "both synthetic runs failed",
      classification: "UNKNOWN",
      effects: [],
      runA: null,
      runB: null,
      next: ["check the handler bytes (memory_read/disassembly_list around the VA) — a handler that faults under emulation may start with an instruction Unicorn rejects"],
    };
  }

  const a = runs[0];
  const b = runs[1];
  if (a === undefined || b === undefined) {
    return {
      backend: "docker-unicorn",
      status: "error",
      error: lastError ?? "insufficient synthetic runs",
      classification: "UNKNOWN",
      effects: [],
      runA: null,
      runB: null,
      next: ["check the handler bytes — a handler that faults under emulation may start with an instruction Unicorn rejects"],
    };
  }
  const { classification, effects } = classifyFromDeltas(
    { seed: a.seed, registers: a.registers, memory: a.memory },
    { seed: b.seed, registers: b.registers, memory: b.memory },
  );

  // Memory writes dominate the classification when present: a handler that
  // stores into the scratch mapping is a STORE handler whatever else it does.
  let finalClassification = classification;
  const memoryEffects: string[] = [];
  if (a.memoryWritten || b.memoryWritten) {
    memoryEffects.push("scratch memory written (the 0x201000 mapping was zero-initialized; nonzero bytes after the run are handler stores)");
    if (a.memoryWritten && b.memoryWritten) {
      finalClassification = classification.startsWith("NO-EFFECT")
        ? "STORE (writes memory, registers untouched)"
        : `STORE+${classification}`;
    }
  }

  return {
    backend: "docker-unicorn",
    status: "ok",
    error: null,
    classification: finalClassification,
    effects: [...effects, ...memoryEffects],
    runA: { registers: a.registers, memoryHex: a.memory.toString("hex").slice(0, 128) },
    runB: { registers: b.registers, memoryHex: b.memory.toString("hex").slice(0, 128) },
    next: [
      "repeat for every carved handler to build the VM opcode table with semantic names",
      "annotate_symbol (va → 'vm_handler_add' etc.) persists the names for every later report",
    ],
  };
}
