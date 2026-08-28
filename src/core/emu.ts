/**
 * emu.run — the emulation plane. Unicorn (docker, --network none, no
 * process, no syscalls) executes a code snippet — shellcode, a decryptor
 * stub carved from a sample, a config-parser routine — against mapped
 * memory WE control. This is the safe way to "run" untrusted logic: the
 * emulated CPU has no host behind it, nothing to escape from. The
 * canonical workflow: binary_find the decryptor (kind bytes) → carve the
 * bytes → emu.run with the encrypted blob mapped in → read the decrypted
 * output memory. Hex in, hex out; registers and a bounded per-instruction
 * trace come back.
 *
 * The job travels through the MINUSONE_EMU_JOB env var (JSON), so the
 * runner needs no stdin wiring — runBoundedCommand spawns without it.
 */
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { runBoundedCommand } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";
import { storeArtifact } from "./artifacts.js";

export const EMU_DEFAULT_TIMEOUT_SECONDS = 60;
export const EMU_MAX_TIMEOUT_SECONDS = 300;
export const EMU_MAX_CODE_BYTES = 64 * 1024;
export const EMU_MAX_MAPPINGS = 16;
export const EMU_MAX_MAPPING_BYTES = 16 * 1024 * 1024;
export const EMU_MAX_JOB_ENV_BYTES = 512 * 1024;

export interface EmuMapping {
  /** Mapping address, e.g. "0x200000". */
  address: string;
  /** Initial bytes (hex) written into the mapping. */
  bytesHex?: string;
  /** Mapping size in bytes (hex payload is zero-padded to this). */
  size?: number;
}

export interface EmuOptions {
  /** x86 (32-bit) or x64. */
  arch?: "x86" | "x64";
  /** Code bytes (hex) executed at the entry point. */
  codeHex: string;
  /** Base address of the code mapping (default 0x100000). */
  base?: string;
  /** Entry offset inside the code mapping (default 0). */
  entryOffset?: number;
  /** Start address override (defaults to base + entryOffset). */
  runAddress?: string;
  /** Stop address (default: end of the code mapping). */
  until?: string;
  /** Additional data mappings (encrypted blobs, output buffers). */
  data?: EmuMapping[];
  /** Initial register values, e.g. { ecx: "0x10" }. */
  registers?: Record<string, string>;
  /** Emulation timeout in microseconds (default 1s). */
  timeoutUs?: number;
  /** Max instructions (default 10M). */
  count?: number;
  /** Command timeout seconds (default 60). */
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

/** One step of a stateful emulation chain. */
export interface EmuChainStep {
  /** Code bytes (hex) for THIS step, written at the chain's base. */
  codeHex: string;
  /** Start address override for this step (default: base + entryOffset). */
  runAddress?: string;
  /** Entry offset inside the code mapping for this step (default 0). */
  entryOffset?: number;
  /** Stop address for this step (default: end of the code mapping). */
  until?: string;
  /** Register values applied before this step (state carries across steps). */
  registers?: Record<string, string>;
  /** Emulation timeout in microseconds for this step (default 1s). */
  timeoutUs?: number;
  /** Max instructions for this step (default 10M). */
  count?: number;
}

export interface EmuChainOptions {
  arch?: "x86" | "x64";
  /** Base address of the code mapping shared by every step (default 0x100000). */
  base?: string;
  /** Data mappings shared by every step — memory carries across steps. */
  data?: EmuMapping[];
  /** Initial register values, applied before step 1. */
  registers?: Record<string, string>;
  steps: EmuChainStep[];
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface EmuChainStepResult {
  step: number;
  status: "ok" | "error";
  error: string | null;
  entry: string;
  stoppedAt: string | null;
  registers: Record<string, string>;
  memory: EmuMemoryRegion[];
  traceHead: EmuTraceStep[];
  traceTruncated: boolean;
}

export interface EmuChainResult {
  backend: "docker-unicorn";
  status: "ok" | "error";
  error: string | null;
  arch: string;
  stepsCompleted: number;
  steps: EmuChainStepResult[];
  /** Full per-step results (complete trace heads) stored as an artifact. */
  stepsArtifact: { artifactId: string; bytes: number; pageWith: string } | null;
  /** Auto-alignment notes (sizes rounded to 4KB). */
  notes: string[];
  command: CommandResult;
}

export interface EmuTraceStep {
  address: string;
  size: number;
  registers: Record<string, string>;
}

export interface EmuMemoryRegion {
  address: string;
  size: number;
  bytesHex: string;
  writtenBytes: number;
  error?: string;
}

export interface EmuResult {
  backend: "docker-unicorn";
  status: "ok" | "error";
  error: string | null;
  arch: string;
  entry: string;
  stoppedAt: string | null;
  registers: Record<string, string>;
  /** Post-run memory: what the snippet WROTE (decrypted configs etc.). */
  memory: EmuMemoryRegion[];
  /**
   * Per-instruction trace HEAD (bounded preview, inline). The FULL trace is
   * in the traceArtifact — a 150KB instruction dump never belongs in a tool
   * response (context overflow, per field feedback).
   */
  traceHead: EmuTraceStep[];
  traceTruncated: boolean;
  /** Full per-instruction trace stored as an artifact; null when the runner produced none. */
  traceArtifact: { artifactId: string; bytes: number; steps: number; pageWith: string } | null;
  /** Auto-alignment notes (base/size rounded to 4KB). */
  notes: string[];
  command: CommandResult;
}

export async function runEmulation(options: EmuOptions, workspace?: Workspace): Promise<EmuResult> {
  const arch = options.arch ?? "x86";
  const code = Buffer.from(options.codeHex, "hex");
  if (code.length === 0) throw new Error("codeHex is empty or invalid hex");
  if (code.length > EMU_MAX_CODE_BYTES) throw new Error(`codeHex too large (${code.length} bytes; cap ${EMU_MAX_CODE_BYTES})`);

  // Unicorn requires page-aligned (4KB) mapping addresses and sizes; a bare
  // misaligned request dies with UC_ERR_ARG deep in the runner. Auto-align
  // here so the caller never has to think about it: the mapping is grown to
  // the next page boundary (zero padding), and the report says what changed.
  const { data, notes: alignmentNotes } = prepareDataMappings(options.data);
  const parseAddress = (value: string | undefined, label: string): number | undefined => {
    if (value === undefined) return undefined;
    const parsed = Number.parseInt(value, value.toLowerCase().startsWith("0x") ? 16 : 10);
    if (Number.isNaN(parsed)) throw new Error(`cannot parse ${label} ${JSON.stringify(value)}`);
    const aligned = parsed - (parsed % 0x1000);
    if (aligned !== parsed) alignmentNotes.push(`${label} ${value} auto-aligned to 0x${aligned.toString(16)} (Unicorn needs 4KB alignment)`);
    return aligned;
  };

  const job = JSON.stringify({
    arch,
    codeHex: options.codeHex,
    ...(() => {
      const base = parseAddress(options.base, "base");
      return base === undefined ? {} : { base: `0x${base.toString(16)}` };
    })(),
    ...(options.entryOffset === undefined ? {} : { entryOffset: options.entryOffset }),
    ...(options.runAddress === undefined ? {} : { runAddress: options.runAddress }),
    ...(options.until === undefined ? {} : { until: options.until }),
    ...(data.length === 0 ? {} : { data }),
    ...(options.registers === undefined ? {} : { registers: options.registers }),
    ...(options.timeoutUs === undefined ? {} : { timeoutUs: options.timeoutUs }),
    ...(options.count === undefined ? {} : { count: options.count }),
  });
  if (Buffer.byteLength(job) > EMU_MAX_JOB_ENV_BYTES) {
    throw new Error(`emulation job too large for the env transport (${Buffer.byteLength(job)} bytes; cap ${EMU_MAX_JOB_ENV_BYTES}) — shrink the data mappings`);
  }

  const image = resolveDockerImage(process.env.MINUSONE_EMU_IMAGE, DEFAULT_IMAGES.unicorn);
  if (image === null) {
    throw new Error("emulation is disabled: MINUSONE_EMU_IMAGE is explicitly empty. Unset the variable to restore the pinned default image.");
  }

  const timeoutSeconds = Math.min(EMU_MAX_TIMEOUT_SECONDS, Math.max(10, options.timeoutSeconds ?? EMU_DEFAULT_TIMEOUT_SECONDS));
  const command = await runBoundedCommand("docker", [
    "run", "--rm", "--network", "none", "--cpus", "1", "--memory", "512m",
    "--env", `MINUSONE_EMU_JOB=${job}`,
    "--entrypoint", "python", image,
    "/opt/minusone/emu-run.py",
  ], {
    cwd: process.cwd(),
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 16 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  const parsed = parseRunnerOutput(command);

  // The full trace is an artifact, never inline output: a per-instruction
  // register dump overflows any model context (the field complaint). The
  // inline answer carries only the head as a preview.
  let traceArtifact: EmuResult["traceArtifact"] = null;
  const fullTrace = command.stdout.trim() === "" ? null : extractFullTrace(command.stdout);
  if (fullTrace !== null && fullTrace.length > 0 && workspace !== undefined) {
    const artifact = await storeArtifact(workspace, JSON.stringify(fullTrace, null, 2), {
      mediaType: "application/json",
      sourceOperation: "emu.run",
      description: `emulation trace (${fullTrace.length} steps)`,
    });
    traceArtifact = { artifactId: artifact.id, bytes: artifact.bytes, steps: fullTrace.length, pageWith: "artifact_read" };
  }

  return {
    backend: "docker-unicorn",
    status: parsed.status === "ok" ? "ok" : "error",
    error: parsed.error ?? (command.exitCode === 0 ? null : `runner exited ${command.exitCode}`),
    arch: parsed.arch ?? arch,
    entry: parsed.entry ?? "unknown",
    stoppedAt: parsed.stoppedAt ?? null,
    registers: parsed.registers ?? {},
    memory: parsed.memory ?? [],
    traceHead: parsed.traceHead ?? [],
    traceTruncated: parsed.traceTruncated ?? false,
    traceArtifact,
    notes: alignmentNotes,
    command,
  };
}

/** Pull the full traceHead array out of the runner's JSON stdout. */
function extractFullTrace(stdout: string): EmuTraceStep[] | null {
  try {
    const parsed = JSON.parse(stdout.trim()) as { traceHead?: unknown };
    return Array.isArray(parsed.traceHead) ? (parsed.traceHead as EmuTraceStep[]) : null;
  } catch {
    return null;
  }
}

/** Shared mapping preparation: hex validation, size caps, 4KB size alignment. */
function prepareDataMappings(mappings: EmuMapping[] | undefined): { data: EmuMapping[]; notes: string[] } {
  const notes: string[] = [];
  const alignPage = (value: number): number => Math.ceil(value / 0x1000) * 0x1000;
  const data = (mappings ?? []).slice(0, EMU_MAX_MAPPINGS).map((mapping) => {
    if (mapping.bytesHex !== undefined && !/^[0-9a-fA-F]*$/.test(mapping.bytesHex)) {
      throw new Error(`mapping at ${mapping.address}: bytesHex must be hex`);
    }
    const rawSize = mapping.size ?? (mapping.bytesHex !== undefined ? mapping.bytesHex.length / 2 : 4096);
    if (rawSize > EMU_MAX_MAPPING_BYTES) throw new Error(`mapping at ${mapping.address} too large (${rawSize} bytes; cap ${EMU_MAX_MAPPING_BYTES})`);
    const size = alignPage(rawSize);
    if (size !== rawSize) notes.push(`data mapping at ${mapping.address}: size ${rawSize} auto-grown to ${size} (4KB alignment, zero-padded)`);
    return { ...mapping, ...(size === rawSize ? {} : { size }) };
  });
  return { data, notes };
}

export const EMU_MAX_STEPS = 16;
export const EMU_MAX_CANDIDATE_CHARS = 64 * 1024;

export interface EmuDiffOptions {
  arch?: "x86" | "x64";
  /** THEIR function — carved code bytes (hex), emulated under Unicorn. */
  codeHex: string;
  /** Base address of the code mapping (default 0x100000). */
  base?: string;
  /** Start address override for the reference run (default base + entryOffset). */
  runAddress?: string;
  /** Entry offset inside the code mapping (default 0). */
  entryOffset?: number;
  /** Stop address for the reference run (default: end of the code mapping). */
  until?: string;
  /** Input mappings — the candidate sees the ORIGINAL bytes. */
  data?: EmuMapping[];
  /** Initial register values (shared by both sides). */
  registers?: Record<string, string>;
  /**
   * The analyst's reimplementation — python source. Runs in the same
   * sandboxed container with `mem` (address int → original input bytes),
   * `regs` (name → int), `struct`, and whitelisted builtins; must assign
   * `out` to a bytes value.
   */
  candidatePython: string;
  /** The window the reference writes its result to (must be a mapped address). */
  outputAddress: string;
  /** Compare length; default: the mapping size at outputAddress. */
  outputLength?: number;
  timeoutUs?: number;
  count?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface EmuDiffResult {
  backend: "docker-unicorn";
  status: "ok" | "error";
  error: string | null;
  arch: string;
  /** true when the reference output and the candidate output are identical. */
  match: boolean;
  outputAddress: string | null;
  comparedBytes: number;
  referenceBytes: number;
  candidateBytes: number;
  referenceTrailingZerosTrimmed: number;
  lengthMismatch: boolean;
  divergenceCount: number;
  firstDivergence: { offset: number; referenceHex: string; candidateHex: string } | null;
  divergenceOffsets: number[];
  /** Final registers of the reference run (the function's real result state). */
  reference: { status: string; error: string | null; registers: Record<string, string>; stoppedAt: string | null } | null;
  referenceOutputHex: string;
  candidateOutputHex: string;
  notes: string[];
  command: CommandResult;
}

/**
 * emu.chain — stateful multi-step emulation. One docker session, one Uc
 * instance: memory and registers carry across steps. The class it serves:
 * "init → key schedule → encrypt" chains (the universal shape of crypto
 * code) where each function is emulated separately today and the state has
 * to be ferried between runs through files.
 */
export async function runEmulationChain(options: EmuChainOptions, workspace?: Workspace): Promise<EmuChainResult> {
  const arch = options.arch ?? "x86";
  const steps = options.steps ?? [];
  if (steps.length === 0) throw new Error("steps is empty — chain needs at least one step");
  if (steps.length > EMU_MAX_STEPS) throw new Error(`too many steps (${steps.length}; cap ${EMU_MAX_STEPS})`);
  steps.forEach((step, index) => {
    const code = Buffer.from(step.codeHex, "hex");
    if (code.length === 0) throw new Error(`step ${index}: codeHex is empty or invalid hex`);
    if (code.length > EMU_MAX_CODE_BYTES) throw new Error(`step ${index}: codeHex too large (${code.length} bytes; cap ${EMU_MAX_CODE_BYTES})`);
  });

  const { data, notes: alignmentNotes } = prepareDataMappings(options.data);

  const parseAddress = (value: string | undefined, label: string): number | undefined => {
    if (value === undefined) return undefined;
    const parsed = Number.parseInt(value, value.toLowerCase().startsWith("0x") ? 16 : 10);
    if (Number.isNaN(parsed)) throw new Error(`cannot parse ${label} ${JSON.stringify(value)}`);
    const aligned = parsed - (parsed % 0x1000);
    if (aligned !== parsed) alignmentNotes.push(`${label} ${value} auto-aligned to 0x${aligned.toString(16)} (Unicorn needs 4KB alignment)`);
    return aligned;
  };

  const job = JSON.stringify({
    arch,
    ...(() => {
      const base = parseAddress(options.base, "base");
      return base === undefined ? {} : { base: `0x${base.toString(16)}` };
    })(),
    ...(data.length === 0 ? {} : { data }),
    ...(options.registers === undefined ? {} : { registers: options.registers }),
    steps: steps.map((step) => ({
      codeHex: step.codeHex,
      ...(step.entryOffset === undefined ? {} : { entryOffset: step.entryOffset }),
      ...(step.runAddress === undefined ? {} : { runAddress: step.runAddress }),
      ...(step.until === undefined ? {} : { until: step.until }),
      ...(step.registers === undefined ? {} : { registers: step.registers }),
      ...(step.timeoutUs === undefined ? {} : { timeoutUs: step.timeoutUs }),
      ...(step.count === undefined ? {} : { count: step.count }),
    })),
  });
  if (Buffer.byteLength(job) > EMU_MAX_JOB_ENV_BYTES) {
    throw new Error(`emulation job too large for the env transport (${Buffer.byteLength(job)} bytes; cap ${EMU_MAX_JOB_ENV_BYTES}) — shrink the data mappings`);
  }

  const image = resolveDockerImage(process.env.MINUSONE_EMU_IMAGE, DEFAULT_IMAGES.unicorn);
  if (image === null) {
    throw new Error("emulation is disabled: MINUSONE_EMU_IMAGE is explicitly empty. Unset the variable to restore the pinned default image.");
  }

  const timeoutSeconds = Math.min(EMU_MAX_TIMEOUT_SECONDS, Math.max(10, options.timeoutSeconds ?? EMU_DEFAULT_TIMEOUT_SECONDS));
  const command = await runBoundedCommand("docker", [
    "run", "--rm", "--network", "none", "--cpus", "1", "--memory", "512m",
    "--env", `MINUSONE_EMU_JOB=${job}`,
    "--entrypoint", "python", image,
    "/opt/minusone/emu-run.py",
  ], {
    cwd: process.cwd(),
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 16 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  const text = command.stdout.trim();
  let parsed: {
    status?: string; error?: string; arch?: string; stepsCompleted?: number;
    steps?: Array<Record<string, unknown>>;
  };
  if (text === "") {
    return {
      backend: "docker-unicorn", status: "error",
      error: command.stderr.split(/\r?\n/).slice(-3).join(" | ") || "runner produced no output",
      arch, stepsCompleted: 0, steps: [], stepsArtifact: null, notes: alignmentNotes, command,
    };
  }
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      backend: "docker-unicorn", status: "error",
      error: `runner output was not JSON: ${text.slice(0, 256)}`,
      arch, stepsCompleted: 0, steps: [], stepsArtifact: null, notes: alignmentNotes, command,
    };
  }

  const rawSteps = Array.isArray(parsed.steps) ? parsed.steps : [];
  // The FULL steps array (complete trace heads) is an artifact; the inline
  // answer keeps the first 8 trace entries per step — enough to spot where
  // a step went wrong without flooding context.
  let stepsArtifact: EmuChainResult["stepsArtifact"] = null;
  if (workspace !== undefined && rawSteps.length > 0) {
    const artifact = await storeArtifact(workspace, JSON.stringify(rawSteps, null, 2), {
      mediaType: "application/json",
      sourceOperation: "emu.chain",
      description: `emulation chain (${rawSteps.length} steps)`,
    });
    stepsArtifact = { artifactId: artifact.id, bytes: artifact.bytes, pageWith: "artifact_read" };
  }
  const stepResults: EmuChainStepResult[] = rawSteps.map((raw, index) => ({
    step: typeof raw.step === "number" ? raw.step : index,
    status: raw.status === "ok" ? "ok" : "error",
    error: raw.error === undefined || raw.error === null ? null : String(raw.error),
    entry: typeof raw.entry === "string" ? raw.entry : "unknown",
    stoppedAt: typeof raw.stoppedAt === "string" ? raw.stoppedAt : null,
    registers: (raw.registers ?? {}) as Record<string, string>,
    memory: (raw.memory ?? []) as EmuMemoryRegion[],
    traceHead: ((raw.traceHead ?? []) as EmuTraceStep[]).slice(0, 8),
    traceTruncated: raw.traceTruncated === true || ((raw.traceHead ?? []) as EmuTraceStep[]).length > 8,
  }));

  return {
    backend: "docker-unicorn",
    status: parsed.status === "ok" ? "ok" : "error",
    error: parsed.error === undefined || parsed.error === null ? (command.exitCode === 0 ? null : `runner exited ${command.exitCode}`) : String(parsed.error),
    arch: parsed.arch ?? arch,
    stepsCompleted: typeof parsed.stepsCompleted === "number" ? parsed.stepsCompleted : stepResults.filter((s) => s.status === "ok").length,
    steps: stepResults,
    stepsArtifact,
    notes: alignmentNotes,
    command,
  };
}

function parseRunnerOutput(command: CommandResult): Partial<EmuResult> {
  const text = command.stdout.trim();
  if (text === "") {
    return { error: command.stderr.split(/\r?\n/).slice(-3).join(" | ") || "runner produced no output" };
  }
  try {
    return JSON.parse(text) as Partial<EmuResult>;
  } catch {
    return { error: `runner output was not JSON: ${text.slice(0, 256)}` };
  }
}

/**
 * emu.diff — the reconstruction oracle. Emulates THEIR function under
 * Unicorn, evaluates the analyst's python reimplementation against the same
 * inputs, and reports the FIRST DIVERGING BYTE. The class it serves: crypto
 * reconstruction (encryptors/parsers/validators) where every component
 * verifies in isolation but the composed result fails — the one-instrument
 * answer to "is my reimplementation byte-identical to theirs?".
 */
export async function runEmulationDiff(options: EmuDiffOptions, workspace?: Workspace): Promise<EmuDiffResult> {
  const arch = options.arch ?? "x86";
  const code = Buffer.from(options.codeHex, "hex");
  if (code.length === 0) throw new Error("codeHex is empty or invalid hex");
  if (code.length > EMU_MAX_CODE_BYTES) throw new Error(`codeHex too large (${code.length} bytes; cap ${EMU_MAX_CODE_BYTES})`);
  if (options.candidatePython.trim().length === 0) throw new Error("candidatePython is empty");
  if (options.candidatePython.length > EMU_MAX_CANDIDATE_CHARS) throw new Error(`candidatePython too large (${options.candidatePython.length} chars; cap ${EMU_MAX_CANDIDATE_CHARS})`);

  const { data, notes: alignmentNotes } = prepareDataMappings(options.data);

  const parseAddress = (value: string | undefined, label: string): number | undefined => {
    if (value === undefined) return undefined;
    const parsed = Number.parseInt(value, value.toLowerCase().startsWith("0x") ? 16 : 10);
    if (Number.isNaN(parsed)) throw new Error(`cannot parse ${label} ${JSON.stringify(value)}`);
    const aligned = parsed - (parsed % 0x1000);
    if (aligned !== parsed) alignmentNotes.push(`${label} ${value} auto-aligned to 0x${aligned.toString(16)} (Unicorn needs 4KB alignment)`);
    return aligned;
  };

  const job = JSON.stringify({
    arch,
    codeHex: options.codeHex,
    ...(() => {
      const base = parseAddress(options.base, "base");
      return base === undefined ? {} : { base: `0x${base.toString(16)}` };
    })(),
    ...(options.entryOffset === undefined ? {} : { entryOffset: options.entryOffset }),
    ...(options.runAddress === undefined ? {} : { runAddress: options.runAddress }),
    ...(options.until === undefined ? {} : { until: options.until }),
    ...(data.length === 0 ? {} : { data }),
    ...(options.registers === undefined ? {} : { registers: options.registers }),
    ...(options.timeoutUs === undefined ? {} : { timeoutUs: options.timeoutUs }),
    ...(options.count === undefined ? {} : { count: options.count }),
    candidate: {
      python: options.candidatePython,
      outputAddress: options.outputAddress,
      ...(options.outputLength === undefined ? {} : { outputLength: options.outputLength }),
    },
  });
  if (Buffer.byteLength(job) > EMU_MAX_JOB_ENV_BYTES) {
    throw new Error(`emulation job too large for the env transport (${Buffer.byteLength(job)} bytes; cap ${EMU_MAX_JOB_ENV_BYTES}) — shrink the data mappings`);
  }

  const image = resolveDockerImage(process.env.MINUSONE_EMU_IMAGE, DEFAULT_IMAGES.unicorn);
  if (image === null) {
    throw new Error("emulation is disabled: MINUSONE_EMU_IMAGE is explicitly empty. Unset the variable to restore the pinned default image.");
  }

  const timeoutSeconds = Math.min(EMU_MAX_TIMEOUT_SECONDS, Math.max(10, options.timeoutSeconds ?? EMU_DEFAULT_TIMEOUT_SECONDS));
  const command = await runBoundedCommand("docker", [
    "run", "--rm", "--network", "none", "--cpus", "1", "--memory", "512m",
    "--env", `MINUSONE_EMU_JOB=${job}`,
    "--entrypoint", "python", image,
    "/opt/minusone/emu-run.py",
  ], {
    cwd: process.cwd(),
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 16 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  const text = command.stdout.trim();
  const emptyResult = (error: string): EmuDiffResult => ({
    backend: "docker-unicorn", status: "error", error, arch,
    match: false, outputAddress: null, comparedBytes: 0, referenceBytes: 0, candidateBytes: 0,
    referenceTrailingZerosTrimmed: 0, lengthMismatch: false, divergenceCount: 0,
    firstDivergence: null, divergenceOffsets: [], reference: null,
    referenceOutputHex: "", candidateOutputHex: "", notes: alignmentNotes, command,
  });
  if (text === "") {
    return emptyResult(command.stderr.split(/\r?\n/).slice(-3).join(" | ") || "runner produced no output");
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return emptyResult(`runner output was not JSON: ${text.slice(0, 256)}`);
  }
  if (parsed.status !== "ok") {
    return emptyResult(typeof parsed.error === "string" ? parsed.error : `runner exited ${command.exitCode}`);
  }

  return {
    backend: "docker-unicorn",
    status: "ok",
    error: null,
    arch: typeof parsed.arch === "string" ? parsed.arch : arch,
    match: parsed.match === true,
    outputAddress: typeof parsed.outputAddress === "string" ? parsed.outputAddress : null,
    comparedBytes: typeof parsed.comparedBytes === "number" ? parsed.comparedBytes : 0,
    referenceBytes: typeof parsed.referenceBytes === "number" ? parsed.referenceBytes : 0,
    candidateBytes: typeof parsed.candidateBytes === "number" ? parsed.candidateBytes : 0,
    referenceTrailingZerosTrimmed: typeof parsed.referenceTrailingZerosTrimmed === "number" ? parsed.referenceTrailingZerosTrimmed : 0,
    lengthMismatch: parsed.lengthMismatch === true,
    divergenceCount: typeof parsed.divergenceCount === "number" ? parsed.divergenceCount : 0,
    firstDivergence: (parsed.firstDivergence ?? null) as EmuDiffResult["firstDivergence"],
    divergenceOffsets: (parsed.divergenceOffsets ?? []) as number[],
    reference: (parsed.reference ?? null) as EmuDiffResult["reference"],
    referenceOutputHex: typeof parsed.referenceOutputHex === "string" ? parsed.referenceOutputHex : "",
    candidateOutputHex: typeof parsed.candidateOutputHex === "string" ? parsed.candidateOutputHex : "",
    notes: alignmentNotes,
    command,
  };
}
