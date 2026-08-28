/**
 * The symbolic plane: angr (docker, --network none) answers the crackme
 * question directly — "which inputs reach the VALID branch" — by concolic
 * exploration of the sample loaded as DATA (never executed on the host);
 * claripy simplifies MBA expressions that flatten decompilers. This is the
 * first minusOne tool class that does not OBSERVE the code but SOLVES it.
 *
 * Transport: the job travels as a temp JSON file mounted read-only (large
 * jobs would overflow the env-var route the emu plane uses).
 */
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export const SYMBOLIC_DEFAULT_TIMEOUT_SECONDS = 300;
export const SYMBOLIC_MAX_TIMEOUT_SECONDS = 1800;
const SYMBOLIC_MAX_EXPR_CHARS = 4000;
const SYMBOLIC_MAX_VARS = 8;
const SYMBOLIC_MAX_ARGS = 8;
const SYMBOLIC_MAX_AVOID = 16;

export interface SymbolicSolveOptions {
  /** Address (hex/decimal) or symbol name that means "input accepted". */
  target: string;
  /** Addresses/symbols that mean "input rejected" (prune the search). */
  avoid?: string[];
  /** Model the input as N symbolic stdin bytes instead of argv. */
  stdinLen?: number;
  /** argv entries; the literal "SYMBOL" becomes a symbolic string. */
  args?: string[];
  maxStates?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface SymbolicSolution {
  how: string;
  argv?: string;
  stdin?: string;
  stdinHex?: string;
  atAddress?: string;
  rax?: string;
  eax?: string;
  argvError?: string;
  stdinError?: string;
}

export interface SymbolicSolveResult {
  backend: "docker-angr";
  status: "ok" | "error";
  target: string | null;
  avoid: string[];
  foundCount: number;
  avoidedCount: number;
  deadendedCount: number;
  solutions: SymbolicSolution[];
  notes: string[];
  errors?: string[];
  error?: string;
  command: CommandResult;
}

export interface SymbolicSimplifyOptions {
  /** Expression to simplify, e.g. "(x ^ y) + 2*(x & y)". */
  expression: string;
  /** Free variables of the expression. */
  vars: string[];
  /** Bit width (default 32). */
  bits?: number;
  /** Guessed simpler form — PROVEN equal or not (z3 ForAll). */
  candidate?: string;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface SymbolicSimplifyResult {
  backend: "docker-claripy";
  status: "ok" | "error";
  original: string;
  simplified: string;
  bits: number;
  vars: string[];
  candidate?: string;
  candidateEquivalent?: boolean;
  equivalenceChecked?: boolean;
  equivalent?: boolean;
  notes: string[];
  error?: string;
  command: CommandResult;
}

function parseAddresses(entries: string[]): string[] {
  return entries
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "")
    .slice(0, SYMBOLIC_MAX_AVOID);
}

async function runSymbolicJob(
  workspace: Workspace,
  userPath: string | undefined,
  job: Record<string, unknown>,
  options: { timeoutSeconds?: number; signal?: AbortSignal },
): Promise<{ parsed: Record<string, unknown>; command: CommandResult }> {
  const image = resolveDockerImage(process.env.MINUSONE_SYMBOLIC_IMAGE, DEFAULT_IMAGES.symbolic);
  if (image === null) {
    throw new Error("symbolic execution is disabled: MINUSONE_SYMBOLIC_IMAGE is explicitly empty. Unset the variable to restore the pinned default image.");
  }
  const timeoutSeconds = Math.min(
    SYMBOLIC_MAX_TIMEOUT_SECONDS,
    Math.max(30, options.timeoutSeconds ?? SYMBOLIC_DEFAULT_TIMEOUT_SECONDS),
  );
  const jobDir = path.join(workspace.root, ".minusone", "run", `symbolic-${Date.now().toString(36)}`);
  await mkdir(jobDir, { recursive: true });
  const jobPath = path.join(jobDir, "job.json");
  await writeFile(jobPath, JSON.stringify(job), "utf8");
  try {
    const args = [
      "run", "--rm", "--network", "none", "--interactive",
      "--cpus", "2", "--memory", "3g",
      ...(userPath !== undefined
        ? ["--volume", dockerVolume(await workspace.resolveFile(userPath), "/sample", "ro")]
        : []),
      "--volume", dockerVolume(jobDir, "/job", "ro"),
      "--entrypoint", "python", image,
      "/opt/minusone/symbolic-run.py",
    ];
    const command = await runBoundedCommand("docker", args, {
      cwd: workspace.root,
      timeoutMs: timeoutSeconds * 1000,
      maxOutputBytes: 8 * 1024 * 1024,
      stdinData: JSON.stringify(job),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const text = command.stdout.trim();
    let parsed: Record<string, unknown>;
    try {
      parsed = text === "" ? { status: "error", error: `runner produced no output (exit ${command.exitCode}); stderr: ${command.stderr.slice(0, 400)}` } : JSON.parse(text) as Record<string, unknown>;
    } catch {
      parsed = { status: "error", error: `runner output was not JSON: ${text.slice(0, 300)}` };
    }
    return { parsed, command };
  } finally {
    await rm(jobDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

export async function symbolicSolve(
  workspace: Workspace,
  userPath: string,
  options: SymbolicSolveOptions,
): Promise<SymbolicSolveResult> {
  const args = (options.args ?? []).slice(0, SYMBOLIC_MAX_ARGS).map(String);
  const avoid = parseAddresses(options.avoid ?? []);
  const stdinLen = Math.min(Math.max(options.stdinLen ?? 0, 0), 64);
  if (options.target.trim() === "") {
    throw new Error("target is required — the address (or symbol) that means the input is accepted");
  }
  const job = {
    mode: "solve",
    binary: "/sample",
    target: options.target,
    ...(avoid.length > 0 ? { avoid } : {}),
    ...(stdinLen > 0 ? { stdinLen } : {}),
    ...(args.length > 0 ? { args } : {}),
    maxStates: Math.min(Math.max(options.maxStates ?? 2000, 10), 20000),
  };
  const { parsed, command } = await runSymbolicJob(workspace, userPath, job, {
    ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return {
    backend: "docker-angr",
    status: parsed.status === "ok" ? "ok" : "error",
    target: typeof parsed.target === "string" ? parsed.target : null,
    avoid: Array.isArray(parsed.avoid) ? (parsed.avoid as string[]) : avoid,
    foundCount: typeof parsed.foundCount === "number" ? parsed.foundCount : 0,
    avoidedCount: typeof parsed.avoidedCount === "number" ? parsed.avoidedCount : 0,
    deadendedCount: typeof parsed.deadendedCount === "number" ? parsed.deadendedCount : 0,
    solutions: Array.isArray(parsed.solutions) ? (parsed.solutions as SymbolicSolution[]) : [],
    notes: Array.isArray(parsed.notes) ? (parsed.notes as string[]) : [],
    ...(Array.isArray(parsed.errors) ? { errors: parsed.errors as string[] } : {}),
    ...(typeof parsed.error === "string" ? { error: parsed.error } : {}),
    command,
  };
}

export async function symbolicSimplify(
  workspace: Workspace,
  options: SymbolicSimplifyOptions,
): Promise<SymbolicSimplifyResult> {
  const expression = options.expression.slice(0, SYMBOLIC_MAX_EXPR_CHARS);
  const vars = options.vars.slice(0, SYMBOLIC_MAX_VARS).map(String).filter((name) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
  if (expression.trim() === "") throw new Error("expression is required");
  if (vars.length === 0) throw new Error("vars is required — the free variables of the expression");
  const candidate = options.candidate === undefined ? undefined : options.candidate.slice(0, SYMBOLIC_MAX_EXPR_CHARS);
  const job = {
    mode: "simplify",
    expression,
    vars,
    bits: Math.min(Math.max(options.bits ?? 32, 8), 64),
    ...(candidate === undefined || candidate.trim() === "" ? {} : { candidate }),
  };
  const { parsed, command } = await runSymbolicJob(workspace, undefined, job, {
    ...(options.timeoutSeconds === undefined ? {} : { timeoutSeconds: options.timeoutSeconds }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return {
    backend: "docker-claripy",
    status: parsed.status === "ok" ? "ok" : "error",
    original: typeof parsed.original === "string" ? parsed.original : expression,
    simplified: typeof parsed.simplified === "string" ? parsed.simplified : "",
    bits: typeof parsed.bits === "number" ? parsed.bits : 32,
    vars: Array.isArray(parsed.vars) ? (parsed.vars as string[]) : vars,
    ...(typeof parsed.candidate === "string" ? { candidate: parsed.candidate } : {}),
    ...(typeof parsed.candidateEquivalent === "boolean" ? { candidateEquivalent: parsed.candidateEquivalent } : {}),
    ...(typeof parsed.equivalenceChecked === "boolean" ? { equivalenceChecked: parsed.equivalenceChecked } : {}),
    ...(typeof parsed.equivalent === "boolean" ? { equivalent: parsed.equivalent } : {}),
    notes: Array.isArray(parsed.notes) ? (parsed.notes as string[]) : [],
    ...(typeof parsed.error === "string" ? { error: parsed.error } : {}),
    command,
  };
}
