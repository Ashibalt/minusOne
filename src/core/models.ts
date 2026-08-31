/**
 * Model-ranking plane: a Python sidecar hosting CLAP (assembly↔text
 * zero-shot crypto-ID) and BinSeek (pseudocode↔query retrieval). The
 * contract is RANKER, NOT ORACLE:
 *
 *   * every response is a ranked list WITH scores — never one verdict;
 *   * model errors degrade to a structured refusal for that ONE request
 *     (the pipeline continues; verification pairs are attached so the
 *     agent can confirm deterministically);
 *   * the whole plane is opt-in: `.minusone/config.json` models:"on"
 *     (`minusone models on`) or MINUSONE_MODELS=1 for one-shot; without
 *     Python/torch or with the plane off, ranking operations report
 *     "unavailable" and nothing else breaks.
 *
 * The sidecar process is spawned lazily on first use and kept alive for
 * the session (model load is the expensive part, ~seconds).
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runBoundedCommand } from "./command.js";
import { readWorkspaceConfig } from "./config.js";
import type { Workspace } from "./workspace.js";

export const MODELS_REQUEST_TIMEOUT_MS = 120_000;
export const MODELS_BOOT_TIMEOUT_MS = 120_000;
/** `import torch` initializes CUDA and can take tens of seconds cold. */
const MODELS_PROBE_TIMEOUT_MS = 90_000;
const SIDECAR_MAX_ASM_CHARS = 60_000;
const SIDECAR_MAX_SNIPPETS = 32;
const SIDECAR_MAX_PROMPTS = 32;

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(moduleDirectory, "../..");

export interface RankedCandidate {
  prompt?: string;
  ref?: string;
  name?: string;
  score: number;
}

export interface RankResult {
  status: "ok" | "error" | "unavailable";
  model: string;
  device?: string;
  ranked?: RankedCandidate[];
  note?: string;
  error?: string;
}

/** Resolve the python interpreter (prefer a native Windows python with torch). */
export function resolveModelsPython(): string | null {
  const explicit = process.env.MINUSONE_MODELS_PYTHON;
  if (explicit !== undefined && explicit !== "" && existsSync(explicit)) return explicit;
  return "python";
}

/** The sidecar script ships with the package. */
export function resolveSidecarPath(): string {
  const explicit = process.env.MINUSONE_MODELS_SIDECAR;
  if (explicit !== undefined && explicit !== "") return explicit;
  return path.join(packageRoot, "tools", "models", "sidecar.py");
}

/** Models directory: clap-asm/, clap-text/, BinSeek-Embedding/. */
export function resolveModelsDir(): string {
  const explicit = process.env.MINUSONE_MODELS_DIR;
  if (explicit !== undefined && explicit !== "") return explicit;
  return path.join(packageRoot, "models");
}

export async function resolveModelsEnabled(workspace: Workspace): Promise<boolean> {
  const env = process.env.MINUSONE_MODELS;
  if (env !== undefined) return env === "1";
  const config = await readWorkspaceConfig(workspace);
  return config.models === "on";
}

interface SidecarProcess {
  child: ChildProcessWithoutNullStreams;
  ready: boolean;
  bootError: string | null;
  pending: Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>;
  nextId: number;
}

let sidecar: SidecarProcess | null = null;

async function bootSidecar(): Promise<SidecarProcess> {
  const python = resolveModelsPython();
  if (python === null) {
    throw new Error("no python interpreter found for the models sidecar; set MINUSONE_MODELS_PYTHON");
  }
  // The dependency probe protects the DEFAULT sidecar only: an explicit
  // MINUSONE_MODELS_SIDECAR override means the caller owns the environment
  // (the same override contract as images and bins), probe included.
  if (process.env.MINUSONE_MODELS_SIDECAR === undefined || process.env.MINUSONE_MODELS_SIDECAR === "") {
    const probe = await runBoundedCommand(python, ["-c", "import torch, transformers"], {
      timeoutMs: MODELS_PROBE_TIMEOUT_MS,
      maxOutputBytes: 16 * 1024,
    }).catch((error: unknown) => null);
    if (probe === null || probe.exitCode !== 0) {
      throw new Error(
        `the models sidecar needs python with torch+transformers+sentence-transformers (resolved python: ${python}); ` +
          `install with: python -m pip install torch transformers sentence-transformers`,
      );
    }
  }
  const child = spawn(python, [resolveSidecarPath()], {
    cwd: packageRoot,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, MINUSONE_MODELS_DIR: resolveModelsDir() },
  }) as ChildProcessWithoutNullStreams;
  // Record the pid so `minusOne models off` can unload a sidecar that
  // belongs to a DIFFERENT process (the MCP server) — the 1.8 GB VRAM leak
  // the owner measured came from exactly that orphan.
  const pidFile = path.join(packageRoot, ".minusone", "run", "models-sidecar.pid");
  void mkdir(path.dirname(pidFile), { recursive: true }).then(() =>
    writeFile(pidFile, String(child.pid), "utf8").catch(() => undefined),
  );
  child.once("close", () => {
    void rm(pidFile, { force: true }).catch(() => undefined);
  });
  const state: SidecarProcess = {
    child,
    ready: false,
    bootError: null,
    pending: new Map(),
    nextId: 1,
  };
  let buffer = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
    buffer += chunk;
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (line !== "") handleSidecarLine(state, line);
      index = buffer.indexOf("\n");
    }
  });
  child.stderr.setEncoding("utf8").on("data", () => {
    // Python warnings (tqdm, transformers notices) go to stderr; ignore.
  });
  child.once("close", (code) => {
    state.ready = false;
    for (const entry of state.pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new Error(`the models sidecar exited (code ${code})`));
    }
    state.pending.clear();
    if (sidecar === state) sidecar = null;
  });
  // Wait for the ready line.
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("the models sidecar did not become ready in time (torch import can be slow on first run)"));
    }, MODELS_BOOT_TIMEOUT_MS);
    const check = setInterval(() => {
      if (state.ready) {
        clearInterval(check);
        clearTimeout(timer);
        resolve();
      } else if (state.bootError !== null) {
        clearInterval(check);
        clearTimeout(timer);
        reject(new Error(state.bootError));
      }
    }, 100);
  });
  return state;
}

function handleSidecarLine(state: SidecarProcess, line: string): void {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return; // Non-JSON noise on stdout — ignore.
  }
  if (parsed.status === "ready" && state.pending.size === 0) {
    state.ready = true;
    return;
  }
  // Match by id when present.
  const id = typeof parsed.id === "number" ? parsed.id : null;
  if (id !== null && state.pending.has(id)) {
    const entry = state.pending.get(id) as { resolve: (value: unknown) => void; timer: NodeJS.Timeout };
    state.pending.delete(id);
    clearTimeout(entry.timer);
    entry.resolve(parsed);
  }
}

async function callSidecar(command: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (sidecar === null || sidecar.ready !== true) {
    sidecar = await bootSidecar();
  }
  const state = sidecar;
  const id = state.nextId;
  state.nextId += 1;
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const timer = setTimeout(() => {
      state.pending.delete(id);
      reject(new Error(`sidecar command ${command} timed out after ${MODELS_REQUEST_TIMEOUT_MS / 1000}s`));
    }, MODELS_REQUEST_TIMEOUT_MS);
    state.pending.set(id, { resolve: (value) => resolve(value as Record<string, unknown>), reject, timer });
    state.child.stdin.write(`${JSON.stringify({ id, command, ...payload })}\n`);
  });
}

export async function shutdownModels(): Promise<void> {
  if (sidecar === null) return;
  try {
    await callSidecar("shutdown", {});
  } catch {
    // Best effort.
  }
  sidecar.child.kill();
  sidecar = null;
}

/** Where the live sidecar records its pid (see bootSidecar). */
function modelsPidFile(): string {
  return path.join(packageRoot, ".minusone", "run", "models-sidecar.pid");
}

/**
 * Read-only sidecar state probe for `doctor` hygiene: is a sidecar process
 * alive right now (by the recorded pid), without touching it. The pid file
 * lives in the PACKAGE .minusone/run — the sidecar is host-global, not
 * per-workspace.
 */
export async function probeExternalModelsSidecar(): Promise<{ running: boolean; pid: number | null; detail: string }> {
  const pidFile = modelsPidFile();
  let pidText: string;
  try {
    pidText = (await readFile(pidFile, "utf8")).trim();
  } catch {
    return { running: false, pid: null, detail: "no models sidecar is running" };
  }
  const pid = Number.parseInt(pidText, 10);
  if (!Number.isFinite(pid) || pid <= 0) {
    return { running: false, pid: null, detail: "stale sidecar pid file (unparseable)" };
  }
  try {
    process.kill(pid, 0);
  } catch {
    return { running: false, pid, detail: "sidecar already exited (stale pid file)" };
  }
  return { running: true, pid, detail: `models sidecar RUNNING (pid ${pid}) — holds VRAM/RAM until idle-exit or 'minusone models off'` };
}

/**
 * Unload a sidecar that belongs to ANOTHER process (typically the running
 * MCP server) — the CLI `minusOne models off` path. Kills by the recorded
 * pid; a missing pid file simply means no sidecar is alive. Returns what
 * happened so the CLI can report honestly.
 */
export async function killExternalModelsSidecar(): Promise<{ killed: boolean; pid: number | null; detail: string }> {
  const pidFile = modelsPidFile();
  let pidText: string;
  try {
    pidText = (await readFile(pidFile, "utf8")).trim();
  } catch {
    return { killed: false, pid: null, detail: "no models sidecar is running" };
  }
  const pid = Number.parseInt(pidText, 10);
  if (!Number.isFinite(pid) || pid <= 0) {
    await rm(pidFile, { force: true }).catch(() => undefined);
    return { killed: false, pid: null, detail: "stale sidecar pid file removed" };
  }
  // Locale-independent liveness probe: signal 0 throws ESRCH for a dead pid
  // (taskkill/tasklist output is localized CP866 mojibake on RU hosts).
  try {
    process.kill(pid, 0);
  } catch {
    await rm(pidFile, { force: true }).catch(() => undefined);
    return { killed: false, pid, detail: "sidecar already exited" };
  }
  const kill = await runBoundedCommand("taskkill", ["/PID", String(pid), "/T", "/F"], {
    timeoutMs: 15_000,
    maxOutputBytes: 64 * 1024,
  }).catch(() => null);
  await rm(pidFile, { force: true }).catch(() => undefined);
  if (kill === null || kill.exitCode !== 0) {
    return { killed: false, pid, detail: `taskkill failed (exit ${kill?.exitCode ?? "spawn-error"})` };
  }
  return { killed: true, pid, detail: "models sidecar unloaded" };
}

export interface RankAssemblyOptions {
  assembly: string;
  prompts: string[];
}

/** CLAP zero-shot: rank natural-language descriptions against an assembly listing. */
export async function rankAssembly(workspace: Workspace, options: RankAssemblyOptions): Promise<RankResult> {
  if (!(await resolveModelsEnabled(workspace))) {
    return unavailable("models are disabled for this workspace (minusone models on, or MINUSONE_MODELS=1)");
  }
  const assembly = options.assembly.slice(0, SIDECAR_MAX_ASM_CHARS);
  const prompts = options.prompts.slice(0, SIDECAR_MAX_PROMPTS);
  if (assembly.trim() === "" || prompts.length === 0) {
    return { status: "error", model: "clap", error: "assembly and at least one prompt are required" };
  }
  try {
    const response = await callSidecar("rank_assembly", { assembly, prompts });
    if (response.status !== "ok") {
      return { status: "error", model: "clap", error: String(response.error ?? "unknown sidecar error") };
    }
    return {
      status: "ok",
      model: "clap",
      ...(typeof response.device === "string" ? { device: response.device } : {}),
      ranked: Array.isArray(response.ranked) ? (response.ranked as RankedCandidate[]) : [],
      ...(typeof response.note === "string" ? { note: response.note } : {}),
    };
  } catch (error) {
    return { status: "error", model: "clap", error: error instanceof Error ? error.message : String(error) };
  }
}

export interface PseudocodeSnippet {
  ref: string;
  name?: string;
  code: string;
}

export interface RankPseudocodeOptions {
  query: string;
  snippets: PseudocodeSnippet[];
}

/** BinSeek embedding retrieval: rank pseudocode snippets against a query. */
export async function rankPseudocode(workspace: Workspace, options: RankPseudocodeOptions): Promise<RankResult> {
  if (!(await resolveModelsEnabled(workspace))) {
    return unavailable("models are disabled for this workspace (minusone models on, or MINUSONE_MODELS=1)");
  }
  const snippets = options.snippets.slice(0, SIDECAR_MAX_SNIPPETS).map((entry) => ({
    ref: entry.ref,
    ...(entry.name === undefined ? {} : { name: entry.name }),
    code: entry.code.slice(0, SIDECAR_MAX_ASM_CHARS),
  }));
  if (options.query.trim() === "" || snippets.length === 0) {
    return { status: "error", model: "binseek", error: "query and at least one snippet are required" };
  }
  try {
    const response = await callSidecar("rank_pseudocode", { query: options.query, snippets });
    if (response.status !== "ok") {
      return { status: "error", model: "binseek", error: String(response.error ?? "unknown sidecar error") };
    }
    return {
      status: "ok",
      model: "binseek",
      ...(typeof response.device === "string" ? { device: response.device } : {}),
      ranked: Array.isArray(response.ranked) ? (response.ranked as RankedCandidate[]) : [],
      ...(typeof response.note === "string" ? { note: response.note } : {}),
    };
  } catch (error) {
    return { status: "error", model: "binseek", error: error instanceof Error ? error.message : String(error) };
  }
}

export interface EmbedResult {
  status: "ok" | "error" | "unavailable";
  embeddings?: number[][];
  error?: string;
}

/**
 * Raw normalized BinSeek embeddings — the primitive behind the campaign
 * knowledge index (persistent vector store). Same toggle contract as the
 * ranking ops: disabled plane → status=unavailable, never a silent spend.
 */
export async function embedTexts(workspace: Workspace, texts: string[]): Promise<EmbedResult> {
  if (!(await resolveModelsEnabled(workspace))) {
    return { status: "unavailable", error: "models are disabled for this workspace (minusone models on, or MINUSONE_MODELS=1)" };
  }
  if (texts.length === 0) return { status: "error", error: "texts is required" };
  try {
    const response = await callSidecar("embed", { texts: texts.slice(0, 64) });
    if (response.status !== "ok" || !Array.isArray(response.embeddings)) {
      return { status: "error", error: String(response.error ?? "sidecar returned no embeddings") };
    }
    return { status: "ok", embeddings: response.embeddings as number[][] };
  } catch (error) {
    return { status: "error", error: error instanceof Error ? error.message : String(error) };
  }
}

function unavailable(reason: string): RankResult {
  return {
    status: "unavailable",
    model: "clap/binseek",
    error: reason,
    note: "ranking is an accelerator, not a dependency: the rest of the pipeline works without it",
  };
}

/**
 * Deterministic verification pairs for model verdicts — the "not an
 * oracle" half of the contract. When CLAP says "SHA-256", the response
 * carries the byte constants a SHA-256 implementation must contain so the
 * agent can confirm with binary_find in seconds. A claim WITHOUT its
 * verification pair is explicitly marked unverifiable.
 */
export const CRYPTO_CONSTANTS: Record<string, Array<{ name: string; hex: string; description: string }>> = {
  "sha-256": [
    { name: "K[0]", hex: "982f8a42", description: "first SHA-256 round constant (0x428a2f98 little-endian)" },
    { name: "K[1]", hex: "91c47ba9", description: "0xB3917AA7 little-endian" },
  ],
  "sha-1": [
    { name: "K2", hex: "9982825a", description: "SHA-1 round constant 0x5A827999 little-endian" },
  ],
  "md5": [
    { name: "T[1]", hex: "78a46ad7", description: "MD5 T[1] = 0xD76AA478 little-endian" },
  ],
  tea: [{ name: "delta", hex: "b979379e", description: "TEA/XTEA delta constant 0x9E3779B9 little-endian" }],
  xtea: [{ name: "delta", hex: "b979379e", description: "XTEA delta 0x9E3779B9 little-endian" }],
  chacha20: [{ name: "sigma", hex: "61707861", description: "\"expa\" — first ChaCha constant word (little-endian ascii)" }],
  salsa20: [{ name: "sigma", hex: "61707861", description: "\"expa\" — first Salsa20 sigma constant" }],
  rc4: [],
  aes: [
    { name: "sbox[0..3]", hex: "637c777b", description: "AES S-box start 63 7c 77 7b" },
  ],
  crc32: [{ name: "poly", hex: "83b7ed20", description: "CRC32 reflected polynomial 0xEDB88320 little-endian" }],
};

/** Clean up a model verdict so it can be looked up in the constant table. */
export function normalizeVerdict(prompt: string): string | null {
  const folded = prompt.toLowerCase();
  for (const key of Object.keys(CRYPTO_CONSTANTS)) {
    if (folded.includes(key) || folded.includes(key.replace("-", ""))) return key;
  }
  return null;
}

/** Attach verification pairs to a ranked verdict list. */
export function attachVerification(ranked: RankedCandidate[]): RankedCandidate[] {
  return ranked.map((candidate) => {
    const verdict = candidate.prompt === undefined ? null : normalizeVerdict(candidate.prompt);
    if (verdict === null) return candidate;
    const pairs = CRYPTO_CONSTANTS[verdict] ?? [];
    return {
      ...candidate,
      verifyWith:
        pairs.length > 0
          ? pairs.map((pair) => ({ needle: `binary_find kind=bytes needle=${pair.hex}`, description: pair.description }))
          : "no deterministic constant pair registered for this verdict — treat as a hypothesis only",
    };
  });
}
