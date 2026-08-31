// Phase 1 (v2): the plan executor — parallel ready-set, dependency order,
// fallback chains, the empty-result-is-not-a-failure rule, refused without
// fallback, onFailure modes, dossier checkpoint + resume, blocked tasks,
// goal artifacts, dynamic-plane exclusivity. Mock operations throughout;
// one integration test drives the REAL operations table through plan_run.

import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { listDossierIndex, readPlan, writePlan } from "../dist/core/campaign.js";
import { runPlan } from "../dist/core/plan.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const KNOWN_OPS = new Set(operations.map((operation) => operation.toolName));

function mockOp(toolName, id, impl) {
  return {
    id,
    toolName,
    description: "mock",
    parameters: {},
    outputSchema: {},
    provider: "mock",
    execute: impl,
  };
}

function mockTable(defs) {
  const calls = [];
  const map = new Map();
  for (const [toolName, impl] of Object.entries(defs)) {
    map.set(toolName, mockOp(toolName, toolName.replace(/_/g, "."), async (args, services) => {
      calls.push({ operation: toolName, args });
      return impl(args, services);
    }));
  }
  return { map, calls };
}

async function freshWorkspace(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-plan-"));
  context.after(() => rmRoot(root));
  return Workspace.create(root);
}

function planWith(tasks, extra = {}) {
  return { version: 1, goal: "test goal", ...extra, tasks };
}

test("executor: independent tasks run and complete; dependency order is enforced", async (context) => {
  const workspace = await freshWorkspace(context);
  const { map, calls } = mockTable({
    op_a: async () => ({ status: "ok", a: 1 }),
    op_b: async () => ({ status: "ok", b: 1 }),
    op_c: async () => ({ status: "ok", c: 1 }),
  });
  const report = await runPlan(workspace, planWith([
    { id: "a", operation: "op_a", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "b", operation: "op_b", args: {}, dependsOn: ["a"], onFailure: "skip" },
    { id: "c", operation: "op_c", args: {}, dependsOn: ["b"], onFailure: "skip" },
    { id: "free", operation: "op_a", args: { free: true }, dependsOn: [], onFailure: "skip" },
  ]), map);
  assert.equal(report.status, "completed");
  assert.deepEqual([...report.completed].sort(), ["a", "b", "c", "free"]);
  const order = calls.filter((call) => !call.args.free).map((call) => call.operation);
  assert.deepEqual(order, ["op_a", "op_b", "op_c"], "chain ran in dependency order");
  const index = await listDossierIndex(workspace);
  assert.equal(index.filter((line) => line.status === "ok").length, 4, "every settled task landed in the dossier");
});

test("executor: fallback chain tried on error; the winning op is recorded in attempts", async (context) => {
  const workspace = await freshWorkspace(context);
  const { map, calls } = mockTable({
    primary_op: async () => ({ status: "error", error: "primary exploded" }),
    rescue_op: async () => ({ status: "ok", rescued: true }),
  });
  const report = await runPlan(workspace, planWith([
    { id: "t", operation: "primary_op", args: {}, dependsOn: [], fallback: ["rescue_op"], onFailure: "skip" },
  ]), map);
  assert.equal(report.status, "completed");
  assert.deepEqual(report.completed, ["t"]);
  assert.deepEqual(calls.map((call) => call.operation), ["primary_op", "rescue_op"], "fallback tried after the primary error");
  const index = await listDossierIndex(workspace);
  assert.equal(index[0].operation, "rescue_op", "the dossier records the operation that actually succeeded");
});

test("executor: an EMPTY successful result never triggers fallback", async (context) => {
  const workspace = await freshWorkspace(context);
  const { map, calls } = mockTable({
    probe_op: async () => ({ packed: false }), // "not UPX" is a RESULT
    rescue_op: async () => ({ status: "ok" }),
  });
  const report = await runPlan(workspace, planWith([
    { id: "t", operation: "probe_op", args: {}, dependsOn: [], fallback: ["rescue_op"], onFailure: "skip" },
  ]), map);
  assert.deepEqual(report.completed, ["t"]);
  assert.deepEqual(calls.map((call) => call.operation), ["probe_op"], "no fallback on an empty-but-ok result");
});

test("executor: refused fails the task WITHOUT fallback (policy state, not an op failure)", async (context) => {
  const workspace = await freshWorkspace(context);
  const { map, calls } = mockTable({
    gated_op: async () => ({ status: "refused", error: "dynamic plane unarmed" }),
    rescue_op: async () => ({ status: "ok" }),
  });
  const report = await runPlan(workspace, planWith([
    { id: "t", operation: "gated_op", args: {}, dependsOn: [], fallback: ["rescue_op"], onFailure: "skip" },
  ]), map);
  assert.equal(report.failed.length, 1);
  assert.match(report.failed[0].error, /unarmed/);
  assert.deepEqual(calls.map((call) => call.operation), ["gated_op"], "fallback not attempted after a refusal");
});

test("executor: onFailure stop halts the chain; skip continues; ask yields needs-decision", async (context) => {
  const failFirst = async () => ({ status: "error", error: "boom" });
  // skip: the independent sibling still runs.
  {
    const workspace = await freshWorkspace(context);
    const { map, calls } = mockTable({ fail_op: failFirst, ok_op: async () => ({ status: "ok" }) });
    const report = await runPlan(workspace, planWith([
      { id: "bad", operation: "fail_op", args: {}, dependsOn: [], onFailure: "skip" },
      { id: "good", operation: "ok_op", args: {}, dependsOn: [], onFailure: "skip" },
    ]), map);
    assert.equal(report.status, "completed");
    assert.deepEqual(report.completed, ["good"], "skip: the sibling completed");
    assert.deepEqual(report.failed.map((failure) => failure.id), ["bad"]);
    assert.ok(calls.some((call) => call.operation === "ok_op"));
  }
  // stop: nothing NEW starts after the failure — but a task ALREADY running
  // in parallel completes legitimately (stop halts the chain, not the
  // in-flight work).
  {
    const workspace = await freshWorkspace(context);
    const { map, calls } = mockTable({ fail_op: failFirst, ok_op: async () => ({ status: "ok" }) });
    const report = await runPlan(workspace, planWith([
      { id: "bad", operation: "fail_op", args: {}, dependsOn: [], onFailure: "stop" },
      { id: "after", operation: "ok_op", args: { marker: "after" }, dependsOn: ["bad"], onFailure: "skip" },
      { id: "free", operation: "ok_op", args: { marker: "free" }, dependsOn: [], onFailure: "skip" },
    ]), map);
    assert.equal(report.status, "stopped");
    assert.deepEqual(calls.filter((call) => call.args.marker === "after"), [], "stop: the dependent never started");
    assert.ok(report.blocked.includes("after"), "the dependent is reported blocked");
    assert.ok(calls.some((call) => call.operation === "fail_op"), "the failing task ran");
  }
  // ask: needs-decision with the failed task named.
  {
    const workspace = await freshWorkspace(context);
    const { map } = mockTable({ fail_op: failFirst });
    const report = await runPlan(workspace, planWith([
      { id: "bad", operation: "fail_op", args: {}, dependsOn: [], onFailure: "ask" },
    ]), map);
    assert.equal(report.status, "needs-decision");
    assert.equal(report.decisionNeeded.task, "bad");
    assert.match(report.decisionNeeded.error, /boom/);
    assert.ok(report.notes.some((note) => /re-run plan_run/.test(note)), "the report says how to resume");
  }
});

test("executor: resume skips dossier-completed tasks; blocked dependents are named", async (context) => {
  const workspace = await freshWorkspace(context);
  const failFirst = async () => ({ status: "error", error: "boom" });
  // First run: A ok, B fails, C (depends on B) blocked.
  const first = mockTable({ ok_op: async () => ({ status: "ok" }), fail_op: failFirst });
  const plan = planWith([
    { id: "a", operation: "ok_op", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "b", operation: "fail_op", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "c", operation: "ok_op", args: {}, dependsOn: ["b"], onFailure: "skip" },
  ], { goalArtifacts: [{ task: "a", kind: "exists" }, { task: "b", kind: "exists" }] });
  const report1 = await runPlan(workspace, plan, first.map);
  assert.deepEqual(report1.completed, ["a"]);
  assert.deepEqual(report1.failed.map((failure) => failure.id), ["b"]);
  assert.deepEqual(report1.blocked, ["c"], "the dependent of a failed task is blocked, not run");
  assert.deepEqual(report1.goalArtifacts.present, ["a"]);
  assert.deepEqual(report1.goalArtifacts.missing, ["b"]);

  // Second run with B FIXED (the agent edited the plan's operation): A is
  // skipped from the dossier, B runs, C unblocks.
  const second = mockTable({ ok_op: async () => ({ status: "ok" }), fixed_op: async () => ({ status: "ok" }) });
  const plan2 = planWith([
    { id: "a", operation: "ok_op", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "b", operation: "fixed_op", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "c", operation: "ok_op", args: {}, dependsOn: ["b"], onFailure: "skip" },
  ], { goalArtifacts: [{ task: "a", kind: "exists" }, { task: "b", kind: "exists" }] });
  const report2 = await runPlan(workspace, plan2, second.map);
  assert.deepEqual(report2.resumedFromDossier, ["a"], "A resumed from the dossier, never re-ran");
  assert.equal(second.calls.filter((call) => call.operation === "ok_op" && report2.resumedFromDossier.includes("a")).length, 1, "only C used ok_op in run 2");
  assert.deepEqual([...report2.completed].sort(), ["b", "c"]);
  assert.deepEqual(report2.blocked, []);
  assert.deepEqual([...report2.goalArtifacts.present].sort(), ["a", "b"]);
});

test("executor: the dynamic plane never runs two tasks concurrently", async (context) => {
  const workspace = await freshWorkspace(context);
  let dynamicConcurrent = 0;
  let maxDynamicConcurrent = 0;
  const dynamicTask = async () => {
    dynamicConcurrent += 1;
    maxDynamicConcurrent = Math.max(maxDynamicConcurrent, dynamicConcurrent);
    await new Promise((resolve) => setTimeout(resolve, 50));
    dynamicConcurrent -= 1;
    return { status: "ok" };
  };
  const { map } = mockTable({ dyn_a: dynamicTask, dyn_b: dynamicTask });
  // Mock ids with dynamic prefixes so the exclusivity classifier catches them.
  map.set("dyn_a", mockOp("dyn_a", "dynamic.one", async (args, services) => {
    return dynamicTask();
  }));
  map.set("dyn_b", mockOp("dyn_b", "trace.two", async () => dynamicTask()));
  const report = await runPlan(workspace, planWith([
    { id: "d1", operation: "dyn_a", args: {}, dependsOn: [], onFailure: "skip" },
    { id: "d2", operation: "dyn_b", args: {}, dependsOn: [], onFailure: "skip" },
  ]), map, { concurrency: 8 });
  assert.equal(report.completed.length, 2);
  assert.equal(maxDynamicConcurrent, 1, "dynamic tasks serialized even with concurrency 8");
});

test("plan_run operation: validates, persists, and resumes campaign/plan.json (integration)", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-planrun-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  const jobs = [];
  const registry = {
    start(spec) {
      const handle = spec.run();
      jobs.push(handle);
      return `job-${jobs.length}`;
    },
  };
  const planRun = operations.find((operation) => operation.toolName === "plan_run");
  assert.ok(planRun, "plan_run registered in the operations table");

  // Inline plan: strings_find on a fixture + unpack_static on a non-UPX file
  // (an EMPTY result that must NOT trigger the fallback).
  const fixturePath = path.join(root, "fixture.exe");
  const { writeFile } = await import("node:fs/promises");
  await writeFile(fixturePath, Buffer.from("MZ not really a PE but has FINDABLE-STRING-12345 inside"));
  const submitted = await planRun.execute({
    plan: {
      version: 1,
      goal: "integration: strings + unpack probe",
      goalArtifacts: [{ task: "strings", kind: "exists" }],
      tasks: [
        { id: "strings", operation: "strings_find", args: { path: "fixture.exe", mode: "leading-window", needle: "FINDABLE" } },
        { id: "unpack", operation: "unpack_static", args: { path: "fixture.exe" }, dependsOn: ["strings"], fallback: true },
      ],
    },
  }, { workspace, jobs: registry });
  assert.equal(submitted.status, "running", "plan_run submits a background job");
  const outcome = await jobs[0].done;
  assert.equal(outcome.status, "completed", outcome.detail ?? "");
  const report = JSON.parse(outcome.output);
  assert.equal(report.status, "completed");
  assert.deepEqual([...report.completed].sort(), ["strings", "unpack"]);
  assert.deepEqual(report.goalArtifacts.present, ["strings"], "goal artifact found");
  // unpack_static returned packed:false — a RESULT, so fallback:true never fired unpack_chain.
  const index = await listDossierIndex(workspace);
  assert.equal(index.filter((line) => line.task === "unpack")[0].operation, "unpack_static", "no fallback on the empty result");

  // Resume: no plan argument → runs campaign/plan.json, everything skips.
  const resume = await planRun.execute({}, { workspace, jobs: registry });
  assert.equal(resume.status, "running");
  const outcome2 = await jobs[1].done;
  assert.equal(outcome2.status, "completed", outcome2.detail ?? "");
  const report2 = JSON.parse(outcome2.output);
  assert.deepEqual([...report2.resumedFromDossier].sort(), ["strings", "unpack"], "resume skipped every completed task");
  assert.deepEqual(report2.completed, [], "nothing re-ran on resume");

  // campaign_status answers "where am I".
  const statusOp = operations.find((operation) => operation.toolName === "campaign_status");
  const status = await statusOp.execute({}, { workspace });
  assert.equal(status.hasCampaign, true);
  assert.equal(status.goal, "integration: strings + unpack probe");
  assert.deepEqual(status.tasks.map((task) => task.state), ["completed", "completed"]);
  assert.equal(status.dossierEntries.length >= 2, true);
  assert.equal(status.notesPresent, false);

  // Validation: an unknown operation in a plan fails fast with the valid list.
  const bad = await planRun.execute({
    plan: { version: 1, goal: "bad", tasks: [{ id: "x", operation: "not_an_operation", args: {} }] },
  }, { workspace, jobs: registry });
  const badOutcome = await jobs[2].done;
  assert.equal(badOutcome.status, "failed");
  assert.match(badOutcome.detail, /unknown operation/);
  void bad;
});
