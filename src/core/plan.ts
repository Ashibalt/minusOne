/**
 * The plan executor — the v2 orchestration core. Runs a CampaignPlan
 * against the operations table:
 *
 * - READY-SET: tasks whose dependsOn are all completed run in parallel
 *   (concurrency cap; docker-backed ops are memory-hungry).
 * - EXCLUSIVITY: the dynamic plane (sample execution, frida, debuggers,
 *   TTD, console) never runs two tasks at once — one live instance, one
 *   instrument, the doctrine rule enforced by the executor itself.
 * - FALLBACK: a task that errors tries its fallback operations in order
 *   (explicit list, or the built-in alternate map with fallback:true).
 *   A success with an EMPTY result never triggers fallback — only a
 *   status=error or a thrown error does. `refused`/`unavailable` fail the
 *   task WITHOUT fallback (a policy state, not an operation failure).
 * - CHECKPOINT: every settled task lands in the dossier immediately; a
 *   re-run of plan_run skips tasks whose latest dossier entry is a success.
 *   Editing plan.json and re-running is THE resume mechanism — progress
 *   is never lost unless the model deletes it.
 * - onFailure: skip (continue), stop (halt), ask (halt with needs-decision
 *   and hand control back to the agent).
 */
import type {
  CampaignPlan,
  DossierAttempt,
  DossierIndexLine,
  PlanTask,
} from "./campaign.js";
import {
  completedTaskIds,
  dossierDir,
  listDossierIndex,
  readyTasks,
  writeDossierEntry,
} from "./campaign.js";
import type { JobSubmitSpec, OperationServices, SemanticOperation } from "./operations.js";
import type { Workspace } from "./workspace.js";

/** Dynamic-plane operation id prefixes — at most ONE of these runs at a time. */
const DYNAMIC_ID_PATTERN = /^(dynamic\.|trace\.|debug\.|console\.|sample\.execute|unpack\.chain|frida\.script|process\.kill)/;

/** Built-in alternate map for fallback:true (tool-level, sample-agnostic). */
const BUILTIN_FALLBACKS: Record<string, string[]> = {
  unpack_static: ["unpack_chain"],
  function_decompile: ["function_decompile_range"],
  ida_decompile: ["function_decompile"],
};

const DEFAULT_CONCURRENCY = 2;
const MAX_CONCURRENCY = 8;

export interface TaskFailure {
  id: string;
  error: string;
  attempts: DossierAttempt[];
}

export interface PlanReport {
  status: "completed" | "stopped" | "needs-decision" | "aborted";
  goal: string;
  /** Tasks completed in THIS run. */
  completed: string[];
  /** Tasks skipped because the dossier already held an ok entry (resume). */
  resumedFromDossier: string[];
  failed: TaskFailure[];
  /** Tasks whose dependencies failed or were never reached this run. */
  blocked: string[];
  goalArtifacts: { present: string[]; missing: string[] };
  /** For needs-decision: the task the agent must fix or drop, then re-run. */
  decisionNeeded?: { task: string; error: string };
  dossierDir: string;
  notes: string[];
}

interface InlineJobHandle {
  done: Promise<{ status: "completed" | "killed" | "failed"; detail?: string; output?: string }>;
  cancel: (reason?: string) => void;
  label: string;
}

/** A job registry the executor owns: nested job-based operations (floss,
 * ttd, ghidra...) get awaited inline instead of disappearing into the host
 * registry the executor cannot poll. */
function createInlineJobRegistry() {
  const handles = new Map<string, InlineJobHandle>();
  let counter = 0;
  const registry = {
    start(spec: JobSubmitSpec): string {
      counter += 1;
      const id = `plan-inline-${counter}`;
      const handle = spec.run();
      handles.set(id, { done: handle.done, cancel: handle.cancel, label: spec.label });
      return id;
    },
  };
  return { registry, handles };
}

function isJobHandle(result: unknown): result is { jobId: string; status: "running" } {
  return (
    typeof result === "object" &&
    result !== null &&
    (result as Record<string, unknown>).status === "running" &&
    typeof (result as Record<string, unknown>).jobId === "string"
  );
}

type Outcome = { kind: "ok"; result: unknown } | { kind: "error"; error: string; fallbackAllowed: boolean };

async function executeOperation(
  operation: SemanticOperation,
  args: Record<string, unknown>,
  workspace: Workspace,
  inlineJobs: ReturnType<typeof createInlineJobRegistry>,
  signal: AbortSignal,
): Promise<Outcome> {
  let result: unknown;
  try {
    result = await operation.execute(args, {
      workspace,
      jobs: inlineJobs.registry,
      signal,
    });
  } catch (error) {
    return { kind: "error", error: error instanceof Error ? error.message : String(error), fallbackAllowed: true };
  }

  if (isJobHandle(result)) {
    const handle = inlineJobs.handles.get(result.jobId);
    if (handle === undefined) {
      return { kind: "error", error: `operation returned job id ${result.jobId} unknown to the inline registry`, fallbackAllowed: true };
    }
    const outcome = await handle.done;
    if (outcome.status !== "completed") {
      return { kind: "error", error: `job ${result.jobId} ${outcome.status}: ${outcome.detail ?? "no detail"}`, fallbackAllowed: true };
    }
    try {
      result = outcome.output === undefined ? {} : JSON.parse(outcome.output);
    } catch {
      result = { raw: outcome.output ?? "" };
    }
  }

  const status = typeof result === "object" && result !== null ? (result as Record<string, unknown>).status : undefined;
  if (status === "error") {
    const message = typeof (result as Record<string, unknown>).error === "string"
      ? (result as Record<string, unknown>).error as string
      : "operation reported status=error";
    return { kind: "error", error: message, fallbackAllowed: true };
  }
  if (status === "refused" || status === "unavailable") {
    const message = typeof (result as Record<string, unknown>).error === "string"
      ? (result as Record<string, unknown>).error as string
      : `operation reported status=${status}`;
    return { kind: "error", error: message, fallbackAllowed: false };
  }
  return { kind: "ok", result };
}

function fallbackChain(task: PlanTask): string[] {
  if (task.fallback === true) return BUILTIN_FALLBACKS[task.operation] ?? [];
  if (Array.isArray(task.fallback)) return task.fallback;
  return [];
}

export interface RunPlanOptions {
  concurrency?: number;
  signal?: AbortSignal;
}

export async function runPlan(
  workspace: Workspace,
  plan: CampaignPlan,
  operations: ReadonlyMap<string, SemanticOperation>,
  options: RunPlanOptions = {},
): Promise<PlanReport> {
  const envConcurrency = Number.parseInt(process.env.MINUSONE_PLAN_CONCURRENCY ?? "", 10);
  const concurrency = Math.min(
    MAX_CONCURRENCY,
    Math.max(1, options.concurrency ?? (Number.isNaN(envConcurrency) ? DEFAULT_CONCURRENCY : envConcurrency)),
  );
  const report: PlanReport = {
    status: "completed",
    goal: plan.goal,
    completed: [],
    resumedFromDossier: [],
    failed: [],
    blocked: [],
    goalArtifacts: { present: [], missing: [] },
    dossierDir: dossierDir(workspace),
    notes: [],
  };

  const index = await listDossierIndex(workspace);
  const settled = completedTaskIds(index); // ok-settled, skip on resume
  report.resumedFromDossier = [...settled].filter((id) => plan.tasks.some((task) => task.id === id));
  const failedIds = new Set<string>();
  const aborted = options.signal;
  let dynamicRunning = false;
  let halted: "stop" | "ask" | null = null;

  async function runTask(task: PlanTask): Promise<void> {
    const attempts: DossierAttempt[] = [];
    const inlineJobs = createInlineJobRegistry();
    const chain = [task.operation, ...fallbackChain(task)];
    let outcome: Outcome = { kind: "error", error: "no attempts made", fallbackAllowed: true };
    for (const operationName of chain) {
      if (halted !== null || aborted?.aborted) break;
      const operation = operations.get(operationName);
      if (operation === undefined) {
        outcome = { kind: "error", error: `operation ${operationName} not in the table (validation should have caught this)`, fallbackAllowed: false };
        break;
      }
      const started = Date.now();
      outcome = await executeOperation(operation, task.args, workspace, inlineJobs, aborted ?? new AbortController().signal);
      const durationMs = Date.now() - started;
      if (outcome.kind === "ok") {
        attempts.push({ operation: operationName, status: "ok", durationMs });
        break;
      }
      attempts.push({ operation: operationName, status: "error", error: outcome.error, durationMs });
      if (!outcome.fallbackAllowed) break;
    }
    for (const handle of inlineJobs.handles.values()) {
      // A completed op leaves no live jobs; anything still here is a stray — cancel it.
      handle.cancel("task settled");
    }

    if (outcome.kind === "ok") {
      await writeDossierEntry(workspace, {
        task: task.id,
        operation: attempts[attempts.length - 1]?.operation ?? task.operation,
        status: "ok",
        completedAt: new Date().toISOString(),
        attempts,
        result: outcome.result,
      });
      settled.add(task.id);
      report.completed.push(task.id);
      return;
    }

    const error = outcome.error;
    await writeDossierEntry(workspace, {
      task: task.id,
      operation: task.operation,
      status: "error",
      completedAt: new Date().toISOString(),
      attempts,
      result: null,
    });
    failedIds.add(task.id);
    report.failed.push({ id: task.id, error, attempts });
    if (task.onFailure === "stop") halted = "stop";
    if (task.onFailure === "ask") halted = "ask";
  }

  const running = new Set<Promise<void>>();
  /** Tasks currently executing: settled only covers FINISHED tasks, so
   * without this the ready-set would relaunch a still-running task on the
   * next loop iteration (two instances, one dossier file). */
  const inFlight = new Set<string>();
  /** Dynamic-plane classification goes by the operation's dotted ID
   * ("dynamic.unpack"), never by the tool name ("dynamic_unpack"). */
  const isDynamic = (task: PlanTask): boolean => {
    const primaryId = operations.get(task.operation)?.id ?? task.operation;
    if (DYNAMIC_ID_PATTERN.test(primaryId)) return true;
    return fallbackChain(task).some((name) => DYNAMIC_ID_PATTERN.test(operations.get(name)?.id ?? name));
  };

  while (halted === null && !aborted?.aborted) {
    const ready = readyTasks(plan, settled).filter((task) => {
      if (inFlight.has(task.id)) return false;
      // Dependents of failed tasks are blocked this run — the agent edits
      // the plan (drop or re-instrument) and re-runs; the executor never
      // feeds a task input that does not exist.
      return !task.dependsOn.some((dep) => failedIds.has(dep)) && !failedIds.has(task.id);
    });
    for (const task of readyTasks(plan, settled)) {
      if (task.dependsOn.some((dep) => failedIds.has(dep)) && !report.blocked.includes(task.id)) {
        report.blocked.push(task.id);
      }
    }

    let startedAny = false;
    for (const task of ready) {
      if (halted !== null || aborted?.aborted) break;
      if (running.size >= concurrency) break;
      const dynamic = isDynamic(task);
      if (dynamic && dynamicRunning) continue;
      if (dynamic) dynamicRunning = true;
      inFlight.add(task.id);
      const promise = runTask(task).finally(() => {
        running.delete(promise);
        inFlight.delete(task.id);
        if (dynamic) dynamicRunning = false;
      });
      running.add(promise);
      startedAny = true;
    }

    if (running.size > 0) {
      await Promise.race(running);
      continue;
    }
    if (!startedAny) break;
  }

  await Promise.allSettled(running);

  // Dependents never reached because a dependency failed upstream.
  for (const task of plan.tasks) {
    if (!settled.has(task.id) && !failedIds.has(task.id) && !report.blocked.includes(task.id)) {
      report.blocked.push(task.id);
    }
  }

  const finalIndex: DossierIndexLine[] = await listDossierIndex(workspace);
  const finalSettled = completedTaskIds(finalIndex);
  for (const artifact of plan.goalArtifacts ?? []) {
    if (finalSettled.has(artifact.task)) report.goalArtifacts.present.push(artifact.task);
    else report.goalArtifacts.missing.push(artifact.task);
  }

  if (aborted?.aborted) {
    report.status = "aborted";
  } else if (halted === "stop") {
    report.status = "stopped";
  } else if (halted === "ask") {
    report.status = "needs-decision";
    const last = report.failed[report.failed.length - 1];
    if (last !== undefined) report.decisionNeeded = { task: last.id, error: last.error };
    report.notes.push("edit plan.json (fix or drop the failed task) and re-run plan_run — completed tasks are skipped from the dossier");
  }
  return report;
}
