// Phase 0 (v2): campaign file-state schema — lazy tree creation, atomic
// writes, plan.json CRUD, and strict plan validation (unknown op, cycles,
// dangling dependsOn, duplicate ids, bad shapes).

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PlanValidationError,
  atomicWriteFile,
  dossierDir,
  ensureCampaignDir,
  planPath,
  readyTasks,
  readPlan,
  validatePlan,
  writePlan,
} from "../dist/core/campaign.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

const KNOWN_OPS = new Set(operations.map((operation) => operation.toolName));

function validPlan() {
  return {
    version: 1,
    goal: "recover the sources from example.dll",
    goalArtifacts: [{ task: "unpack", kind: "exists" }],
    tasks: [
      { id: "triage", operation: "binary_triage", args: { path: "example.dll" } },
      { id: "unpack", operation: "unpack_static", args: { path: "example.dll" }, dependsOn: ["triage"], fallback: ["unpack_chain"] },
      { id: "strings", operation: "strings_find", args: { path: "example.dll", mode: "plain-strings" }, dependsOn: ["unpack"], onFailure: "stop" },
    ],
  };
}

test("campaign: ensureCampaignDir lazy-creates the full tree", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-campaign-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  assert.equal(existsSync(dossierDir(workspace)), false, "no campaign tree before the first write");
  await ensureCampaignDir(workspace);
  assert.equal(existsSync(dossierDir(workspace)), true);
  assert.equal(existsSync(path.join(workspace.root, ".minusone", "campaign", "index")), true);
});

test("campaign: atomicWriteFile leaves no tmp files and replaces content fully", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-atomic-"));
  context.after(() => rmRoot(root));
  const target = path.join(root, "plan.json");
  await atomicWriteFile(target, JSON.stringify({ a: 1 }));
  await atomicWriteFile(target, JSON.stringify({ a: 2, b: 3 }));
  assert.equal(await readFile(target, "utf8"), JSON.stringify({ a: 2, b: 3 }), "second write fully replaced the first");
  const leftovers = (await readdir(root)).filter((name) => name.includes(".tmp-"));
  assert.deepEqual(leftovers, [], `no tmp leftovers: ${leftovers.join(",")}`);
});

test("campaign: writePlan/readPlan round-trips with a stamped updatedAt", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-planrw-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  assert.equal(await readPlan(workspace, KNOWN_OPS), null, "no plan before the campaign starts");
  const stamped = await writePlan(workspace, validPlan(), KNOWN_OPS);
  assert.ok(stamped.updatedAt > 0, "updatedAt stamped on write");
  const readBack = await readPlan(workspace, KNOWN_OPS);
  assert.equal(readBack.goal, "recover the sources from example.dll");
  assert.equal(readBack.tasks.length, 3);
  assert.equal(readBack.tasks[1].onFailure, "skip", "onFailure defaults to skip");
  assert.deepEqual(readBack.tasks[1].fallback, ["unpack_chain"]);
  assert.deepEqual(readBack.goalArtifacts, [{ task: "unpack", kind: "exists" }]);
});

test("campaign: readPlan on a corrupt plan.json reports JSON detail, not a crash", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-plancorrupt-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  await ensureCampaignDir(workspace);
  await writeFile(planPath(workspace), "{not json", "utf8");
  await assert.rejects(() => readPlan(workspace, KNOWN_OPS), PlanValidationError);
});

test("campaign: validation rejects an unknown operation with the valid list", () => {
  const plan = validPlan();
  plan.tasks[0].operation = "definitely_not_an_op";
  assert.throws(() => validatePlan(plan, KNOWN_OPS), (error) => {
    assert.ok(error instanceof PlanValidationError);
    assert.match(error.message, /unknown operation/);
    assert.match(error.message, /binary_triage/, "the error lists valid operations");
    return true;
  });
});

test("campaign: validation rejects dependsOn cycles and dangling references", () => {
  const cyclic = {
    version: 1, goal: "g",
    tasks: [
      { id: "a", operation: "binary_triage", args: {}, dependsOn: ["b"] },
      { id: "b", operation: "binary_triage", args: {}, dependsOn: ["a"] },
    ],
  };
  assert.throws(() => validatePlan(cyclic, KNOWN_OPS), /cycle/);

  const dangling = {
    version: 1, goal: "g",
    tasks: [{ id: "a", operation: "binary_triage", args: {}, dependsOn: ["ghost"] }],
  };
  assert.throws(() => validatePlan(dangling, KNOWN_OPS), /unknown task "ghost"/);

  const selfDep = {
    version: 1, goal: "g",
    tasks: [{ id: "a", operation: "binary_triage", args: {}, dependsOn: ["a"] }],
  };
  assert.throws(() => validatePlan(selfDep, KNOWN_OPS), /itself/);
});

test("campaign: validation rejects duplicate ids, bad shapes, and bad onFailure", () => {
  const dup = {
    version: 1, goal: "g",
    tasks: [
      { id: "a", operation: "binary_triage", args: {} },
      { id: "a", operation: "strings_find", args: {} },
    ],
  };
  assert.throws(() => validatePlan(dup, KNOWN_OPS), /duplicate task id/);

  assert.throws(() => validatePlan({ version: 1, goal: "g", tasks: [] }, KNOWN_OPS), /non-empty/);
  assert.throws(() => validatePlan({ version: 2, goal: "g", tasks: [{ id: "a", operation: "binary_triage", args: {} }] }, KNOWN_OPS), /version/);
  assert.throws(() => validatePlan({ version: 1, tasks: [{ id: "a", operation: "binary_triage", args: {} }] }, KNOWN_OPS), /goal/);

  const badOnFailure = {
    version: 1, goal: "g",
    tasks: [{ id: "a", operation: "binary_triage", args: {}, onFailure: "explode" }],
  };
  assert.throws(() => validatePlan(badOnFailure, KNOWN_OPS), /onFailure/);

  const badFallback = {
    version: 1, goal: "g",
    tasks: [{ id: "a", operation: "binary_triage", args: {}, fallback: ["not_an_op"] }],
  };
  assert.throws(() => validatePlan(badFallback, KNOWN_OPS), /unknown fallback operation/);

  const badGoalArtifact = {
    ...validPlan(),
    goalArtifacts: [{ task: "ghost", kind: "exists" }],
  };
  assert.throws(() => validatePlan(badGoalArtifact, KNOWN_OPS), /goalArtifacts references unknown task/);
});

test("campaign: readyTasks returns exactly the dependency-satisfied unfinished tasks", () => {
  const plan = validatePlan(validPlan(), KNOWN_OPS);
  assert.deepEqual(readyTasks(plan, new Set()).map((task) => task.id), ["triage"], "only the root task is ready at the start");
  assert.deepEqual(readyTasks(plan, new Set(["triage"])).map((task) => task.id), ["unpack"]);
  assert.deepEqual(readyTasks(plan, new Set(["triage", "unpack"])).map((task) => task.id), ["strings"]);
  assert.deepEqual(readyTasks(plan, new Set(["triage", "unpack", "strings"])), [], "finished campaign has no ready tasks");
  assert.deepEqual(readyTasks(plan, new Set(["strings"])).map((task) => task.id), ["triage"], "completion without dependencies does not unlock dependents");
});
