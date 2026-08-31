/**
 * Campaign state — the v2 architecture's stateful layer. The MCP server
 * stays stateless; the campaign lives on disk under `.minusone/campaign/`
 * with a fixed schema:
 *
 *   plan.json   — the goal + task list (a LIVING document: the agent edits
 *                 it and re-runs; the executor skips finished tasks)
 *   notes.md    — investigation notes (hypotheses, dead ends, addresses)
 *   dossier/    — assembled task results, one JSON per completed task
 *   index/      — the embedding index (empty unless models are enabled)
 *
 * One active campaign per workspace. Everything is written atomically
 * (tmp file + rename) so a crash or an agent-context compaction mid-write
 * never leaves a torn plan behind.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Workspace } from "./workspace.js";

export const PLAN_VERSION = 1;
export const MAX_PLAN_TASKS = 64;
const TASK_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export type OnFailure = "skip" | "stop" | "ask";

export interface PlanTask {
  /** Unique slug, e.g. "unpack" — used in dependsOn and dossier file names. */
  id: string;
  /** The operation tool name, e.g. "binary_triage" (what the agent calls over MCP). */
  operation: string;
  args: Record<string, unknown>;
  dependsOn: string[];
  /**
   * Alternatives tried in order when the primary operation errors:
   * an explicit list of tool names, or `true` for the built-in alternate
   * map. A SUCCESS with an empty result never triggers fallback — only a
   * status=error does.
   */
  fallback?: string[] | true;
  /** What the chain does when the task (and its fallbacks) failed: continue (skip), halt (stop), or hand control back to the agent (ask). Default skip. */
  onFailure: OnFailure;
}

export interface GoalArtifact {
  /** The dossier must contain an entry for this task. */
  task: string;
  kind: "exists";
}

export interface CampaignPlan {
  version: 1;
  /** The goal contract, free text: what this campaign must produce. */
  goal: string;
  goalArtifacts: GoalArtifact[];
  tasks: PlanTask[];
  updatedAt: number;
}

export class PlanValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlanValidationError";
  }
}

function campaignDir(workspace: Workspace): string {
  return path.join(workspace.root, ".minusone", "campaign");
}

export function planPath(workspace: Workspace): string {
  return path.join(campaignDir(workspace), "plan.json");
}

export function notesPath(workspace: Workspace): string {
  return path.join(campaignDir(workspace), "notes.md");
}

export function dossierDir(workspace: Workspace): string {
  return path.join(campaignDir(workspace), "dossier");
}

export function campaignIndexDir(workspace: Workspace): string {
  return path.join(campaignDir(workspace), "index");
}

/** Lazy-create the campaign tree; safe to call before every write. */
export async function ensureCampaignDir(workspace: Workspace): Promise<void> {
  await mkdir(dossierDir(workspace), { recursive: true });
  await mkdir(campaignIndexDir(workspace), { recursive: true });
}

/** Atomic file write: full content to a sibling tmp file, then rename. */
export async function atomicWriteFile(filePath: string, content: string): Promise<void> {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now().toString(36)}`;
  await writeFile(tmp, content, "utf8");
  try {
    await rename(tmp, filePath);
  } catch (error) {
    await rm(tmp, { force: true });
    throw error;
  }
}

/**
 * Validate a parsed plan object. `knownOperations` is the set of valid
 * tool names (the operations table) — passed in so this module never
 * imports the table (the table imports this module).
 */
export function validatePlan(raw: unknown, knownOperations: ReadonlySet<string>): CampaignPlan {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new PlanValidationError("plan must be a JSON object");
  }
  const plan = raw as Record<string, unknown>;
  if (plan.version !== PLAN_VERSION) {
    throw new PlanValidationError(`plan.version must be ${PLAN_VERSION} (got ${JSON.stringify(plan.version)})`);
  }
  if (typeof plan.goal !== "string" || plan.goal.trim() === "") {
    throw new PlanValidationError("plan.goal is required — the goal contract the executor checks against");
  }
  if (!Array.isArray(plan.tasks) || plan.tasks.length === 0) {
    throw new PlanValidationError("plan.tasks must be a non-empty array");
  }
  if (plan.tasks.length > MAX_PLAN_TASKS) {
    throw new PlanValidationError(`plan.tasks too large (${plan.tasks.length}; max ${MAX_PLAN_TASKS})`);
  }

  const ids = new Set<string>();
  const tasks: PlanTask[] = [];
  for (let index = 0; index < plan.tasks.length; index += 1) {
    const entry = plan.tasks[index] as Record<string, unknown>;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new PlanValidationError(`task ${index} must be an object`);
    }
    if (typeof entry.id !== "string" || !TASK_ID_PATTERN.test(entry.id)) {
      throw new PlanValidationError(`task ${index}: id must match ${TASK_ID_PATTERN} (got ${JSON.stringify(entry.id)})`);
    }
    if (ids.has(entry.id)) {
      throw new PlanValidationError(`duplicate task id ${JSON.stringify(entry.id)}`);
    }
    ids.add(entry.id);
    if (typeof entry.operation !== "string" || !knownOperations.has(entry.operation)) {
      throw new PlanValidationError(
        `task ${JSON.stringify(entry.id)}: unknown operation ${JSON.stringify(entry.operation)} — valid: ${[...knownOperations].sort().join(", ")}`,
      );
    }
    if (typeof entry.args !== "object" || entry.args === null || Array.isArray(entry.args)) {
      throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: args must be an object`);
    }
    const dependsOn = entry.dependsOn === undefined ? [] : entry.dependsOn;
    if (!Array.isArray(dependsOn) || dependsOn.some((dep) => typeof dep !== "string")) {
      throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: dependsOn must be an array of task ids`);
    }
    if ((dependsOn as string[]).includes(entry.id)) {
      throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: cannot depend on itself`);
    }
    const fallback = entry.fallback;
    if (fallback !== undefined && fallback !== true) {
      if (!Array.isArray(fallback) || fallback.length === 0 || fallback.some((op) => typeof op !== "string")) {
        throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: fallback must be true or a non-empty array of operation names`);
      }
      for (const op of fallback as string[]) {
        if (!knownOperations.has(op)) {
          throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: unknown fallback operation ${JSON.stringify(op)}`);
        }
      }
    }
    const onFailure = entry.onFailure === undefined ? "skip" : entry.onFailure;
    if (onFailure !== "skip" && onFailure !== "stop" && onFailure !== "ask") {
      throw new PlanValidationError(`task ${JSON.stringify(entry.id)}: onFailure must be skip|stop|ask (got ${JSON.stringify(entry.onFailure)})`);
    }
    tasks.push({
      id: entry.id,
      operation: entry.operation,
      args: entry.args as Record<string, unknown>,
      dependsOn: dependsOn as string[],
      ...(fallback === undefined ? {} : { fallback: fallback as string[] | true }),
      onFailure,
    });
  }

  for (const task of tasks) {
    for (const dep of task.dependsOn) {
      if (!ids.has(dep)) {
        throw new PlanValidationError(`task ${JSON.stringify(task.id)}: dependsOn references unknown task ${JSON.stringify(dep)}`);
      }
    }
  }
  assertAcyclic(tasks);

  const goalArtifacts: GoalArtifact[] = [];
  if (plan.goalArtifacts !== undefined) {
    if (!Array.isArray(plan.goalArtifacts)) {
      throw new PlanValidationError("plan.goalArtifacts must be an array of {task, kind}");
    }
    for (const entry of plan.goalArtifacts as Array<Record<string, unknown>>) {
      if (typeof entry !== "object" || entry === null || typeof entry.task !== "string" || entry.kind !== "exists") {
        throw new PlanValidationError(`goalArtifacts entries must be {task, kind: "exists"} (got ${JSON.stringify(entry)})`);
      }
      if (!ids.has(entry.task)) {
        throw new PlanValidationError(`goalArtifacts references unknown task ${JSON.stringify(entry.task)}`);
      }
      goalArtifacts.push({ task: entry.task, kind: "exists" });
    }
  }

  return {
    version: PLAN_VERSION,
    goal: plan.goal,
    goalArtifacts,
    tasks,
    updatedAt: typeof plan.updatedAt === "number" ? plan.updatedAt : 0,
  };
}

/** Kahn's algorithm — throws on any dependency cycle. */
function assertAcyclic(tasks: PlanTask[]): void {
  const indegree = new Map<string, number>(tasks.map((task) => [task.id, task.dependsOn.length]));
  const dependents = new Map<string, string[]>();
  for (const task of tasks) {
    for (const dep of task.dependsOn) {
      dependents.set(dep, [...(dependents.get(dep) ?? []), task.id]);
    }
  }
  const queue = tasks.filter((task) => task.dependsOn.length === 0).map((task) => task.id);
  let visited = 0;
  while (queue.length > 0) {
    const current = queue.shift() as string;
    visited += 1;
    for (const next of dependents.get(current) ?? []) {
      const remaining = (indegree.get(next) as number) - 1;
      indegree.set(next, remaining);
      if (remaining === 0) queue.push(next);
    }
  }
  if (visited !== tasks.length) {
    const stuck = tasks.filter((task) => (indegree.get(task.id) as number) > 0).map((task) => task.id);
    throw new PlanValidationError(`dependsOn cycle detected involving: ${stuck.join(", ")}`);
  }
}

/** Tasks ready to run: all dependencies completed, not completed themselves. */
export function readyTasks(plan: CampaignPlan, completed: ReadonlySet<string>): PlanTask[] {
  return plan.tasks.filter((task) => !completed.has(task.id) && (task.dependsOn ?? []).every((dep) => completed.has(dep)));
}

/** Read and validate campaign/plan.json; null when no campaign exists yet. */
export async function readPlan(workspace: Workspace, knownOperations: ReadonlySet<string>): Promise<CampaignPlan | null> {
  let raw: string;
  try {
    raw = await readFile(planPath(workspace), "utf8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new PlanValidationError(`plan.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return validatePlan(parsed, knownOperations);
}

/** Validate and atomically write campaign/plan.json. */
export async function writePlan(workspace: Workspace, plan: unknown, knownOperations: ReadonlySet<string>): Promise<CampaignPlan> {
  const validated = validatePlan(plan, knownOperations);
  const stamped: CampaignPlan = { ...validated, updatedAt: Date.now() };
  await ensureCampaignDir(workspace);
  await atomicWriteFile(planPath(workspace), JSON.stringify(stamped, null, 2));
  return stamped;
}

// ---- dossier (assembled task results, the resume checkpoint) ---------------

export interface DossierAttempt {
  operation: string;
  status: "ok" | "error";
  error?: string;
  durationMs: number;
}

export interface DossierEntry {
  task: string;
  operation: string;
  status: "ok" | "error";
  completedAt: string;
  attempts: DossierAttempt[];
  /** The ASSEMBLED form (per-family extractor; generic bounded preview for the rest). */
  assembled: unknown;
  /** CAS id of the RAW operation result (null on failure). */
  rawArtifact: string | null;
}

export interface DossierIndexLine {
  file: string;
  task: string;
  operation: string;
  status: "ok" | "error";
  completedAt: string;
}

function timestampForName(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}-${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`;
}

/** `<yyyymmdd-HHMMSS>_<taskid>_<op>[_error].json` — per the v2 naming contract. */
export function dossierEntryName(taskId: string, operation: string, status: "ok" | "error", date = new Date()): string {
  const suffix = status === "error" ? "_error" : "";
  return `${timestampForName(date)}_${taskId}_${operation}${suffix}.json`;
}

const MAX_DOSSIER_RESULT_CHARS = 5 * 1024 * 1024;

/**
 * Persist a task result IMMEDIATELY (the resume checkpoint: a re-run of
 * plan_run skips tasks that already carry an ok entry). Stores the
 * ASSEMBLED form inline (per-family extractor) and the RAW result in the
 * CAS by pointer; appends one line to dossier/index.jsonl so listings
 * never need a directory scan.
 */
export async function writeDossierEntry(workspace: Workspace, entry: {
  task: string;
  operation: string;
  status: "ok" | "error";
  completedAt: string;
  attempts: DossierAttempt[];
  result: unknown;
}): Promise<string> {
  await ensureCampaignDir(workspace);
  const { extractDossierResult } = await import("./dossier.js");
  const assembled = entry.status === "ok" ? extractDossierResult(entry.operation, entry.result) : null;
  let rawArtifact: string | null = null;
  if (entry.status === "ok" && entry.result !== undefined && entry.result !== null) {
    let rawJson = JSON.stringify(entry.result);
    if (rawJson.length > MAX_DOSSIER_RESULT_CHARS) {
      rawJson = JSON.stringify({ truncated: true, chars: rawJson.length });
    }
    const { storeArtifact } = await import("./artifacts.js");
    const artifact = await storeArtifact(workspace, rawJson, {
      mediaType: "application/json",
      sourceOperation: "plan.run",
      description: `raw result: ${entry.task} via ${entry.operation}`,
    });
    rawArtifact = artifact.id;
  }
  const stored: DossierEntry = {
    task: entry.task,
    operation: entry.operation,
    status: entry.status,
    completedAt: entry.completedAt,
    attempts: entry.attempts,
    assembled,
    rawArtifact,
  };
  let name = dossierEntryName(entry.task, entry.operation, entry.status);
  // Same-second retries of one task collide on the timestamped name — bump
  // a numeric suffix instead of overwriting the earlier attempt.
  for (let attempt = 2; existsSync(path.join(dossierDir(workspace), name)); attempt += 1) {
    name = dossierEntryName(entry.task, entry.operation, entry.status).replace(/\.json$/, `_r${attempt}.json`);
  }
  await atomicWriteFile(path.join(dossierDir(workspace), name), JSON.stringify(stored, null, 2));
  const line: DossierIndexLine = {
    file: name,
    task: entry.task,
    operation: entry.operation,
    status: entry.status,
    completedAt: entry.completedAt,
  };
  const { appendFile } = await import("node:fs/promises");
  await appendFile(path.join(dossierDir(workspace), "index.jsonl"), `${JSON.stringify(line)}\n`, "utf8");
  return name;
}

/** Every dossier index line, oldest first; empty when no dossier exists. */
export async function listDossierIndex(workspace: Workspace): Promise<DossierIndexLine[]> {
  let raw: string;
  try {
    raw = await readFile(path.join(dossierDir(workspace), "index.jsonl"), "utf8");
  } catch {
    return [];
  }
  const lines: DossierIndexLine[] = [];
  for (const text of raw.split(/\r?\n/)) {
    if (text.trim() === "") continue;
    try {
      lines.push(JSON.parse(text) as DossierIndexLine);
    } catch {
      // A torn trailing line (killed mid-append) is skipped, not fatal.
    }
  }
  return lines;
}

/** Task ids whose LATEST dossier entry is a success — the resume skip-set. */
export function completedTaskIds(index: DossierIndexLine[]): Set<string> {
  const latest = new Map<string, "ok" | "error">();
  for (const line of index) latest.set(line.task, line.status);
  const completed = new Set<string>();
  for (const [task, status] of latest) {
    if (status === "ok") completed.add(task);
  }
  return completed;
}
