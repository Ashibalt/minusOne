import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  runVolatilityPlugins,
  summarizeVolatilityTable,
  validateVolatilityPlugins,
  VOLATILITY_PLUGINS,
} from "../dist/core/volatility.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";

function probe(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: "ignore", windowsHide: true });
    child.once("error", () => resolve(false));
    child.once("close", (exitCode) => resolve(exitCode === 0));
  });
}

test("summarizeVolatilityTable flattens tree rows and bounds the table", () => {
  const tree = [
    { PID: 4, ImageFileName: "System", __children: [] },
    {
      PID: 448,
      ImageFileName: "smss.exe",
      __children: [{ PID: 528, ImageFileName: "csrss.exe", Notes: "child", __children: [] }],
    },
  ];
  const full = summarizeVolatilityTable(tree, "windows.pstree", 10);
  assert.equal(full.rowCountTotal, 3, "children are flattened into the table");
  assert.deepEqual(full.columns, ["PID", "ImageFileName", "Notes"], "columns are the union across rows, without __children");
  assert.equal(full.rows[2].PID, 528);
  assert.equal(full.rows[2].Notes, "child");
  assert.equal(full.truncated, false);

  const capped = summarizeVolatilityTable(tree, "windows.pstree", 2);
  assert.equal(capped.rows.length, 2);
  assert.equal(capped.rowCountTotal, 3);
  assert.equal(capped.truncated, true);

  // Multi-plugin invocations wrap tables by plugin name.
  const wrapped = summarizeVolatilityTable(
    { "windows.info": [{ Variable: "NtMajorVersion", Value: "5", __children: [] }] },
    "windows.info",
    10,
  );
  assert.equal(wrapped.rowCountTotal, 1);
  assert.equal(wrapped.rows[0].Variable, "NtMajorVersion");
  assert.deepEqual(summarizeVolatilityTable({ "windows.info": [] }, "windows.pslist", 10).rows, []);
  assert.deepEqual(summarizeVolatilityTable(null, "windows.info", 10).rows, []);
});

test("validateVolatilityPlugins defaults, dedupes in whitelist order, and rejects unknowns", () => {
  assert.deepEqual(validateVolatilityPlugins(undefined), ["windows.info"]);
  assert.deepEqual(validateVolatilityPlugins([]), ["windows.info"]);
  assert.deepEqual(
    validateVolatilityPlugins(["windows.malfind", "windows.info", "windows.malfind"]),
    ["windows.info", "windows.malfind"],
  );
  assert.throws(() => validateVolatilityPlugins(["bogus.plugin"]), /unknown volatility plugin/);
  assert.throws(
    () => validateVolatilityPlugins(Array.from({ length: 9 }, (_, i) => VOLATILITY_PLUGINS[i])),
    /at most 8/,
  );
});

test("runVolatilityPlugins fails loudly when every backend is disabled", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-vol-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "capture.img"), "not-a-real-capture");
  const workspace = await Workspace.create(root);

  const previousImage = process.env.MINUSONE_VOLATILITY_IMAGE;
  const previousBin = process.env.MINUSONE_VOLATILITY_BIN;
  process.env.MINUSONE_VOLATILITY_IMAGE = "";
  delete process.env.MINUSONE_VOLATILITY_BIN;
  context.after(() => {
    delete process.env.MINUSONE_VOLATILITY_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_VOLATILITY_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_VOLATILITY_BIN = previousBin;
  });

  await assert.rejects(
    () => runVolatilityPlugins(workspace, "capture.img", { plugins: ["windows.info"] }),
    /volatility3 is disabled/,
  );
});

test("memory.volatility job settles as failed when every backend is disabled", async (context) => {
  const operation = operations.find((entry) => entry.id === "memory.volatility");
  assert.ok(operation, "memory.volatility operation exists");
  assert.equal(operation.toolName, "memory_volatility");

  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-vol-op-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, "capture.img"), "not-a-real-capture");
  const workspace = await Workspace.create(root);

  const previousImage = process.env.MINUSONE_VOLATILITY_IMAGE;
  const previousBin = process.env.MINUSONE_VOLATILITY_BIN;
  process.env.MINUSONE_VOLATILITY_IMAGE = "";
  delete process.env.MINUSONE_VOLATILITY_BIN;
  context.after(() => {
    delete process.env.MINUSONE_VOLATILITY_IMAGE;
    if (previousImage !== undefined) process.env.MINUSONE_VOLATILITY_IMAGE = previousImage;
    if (previousBin !== undefined) process.env.MINUSONE_VOLATILITY_BIN = previousBin;
  });

  let started = null;
  const jobs = {
    start(spec) {
      started = spec;
      return "vol-1";
    },
  };
  const submitted = await operation.execute({ path: "capture.img" }, { workspace, jobs });
  assert.equal(submitted.jobId, "vol-1");
  assert.equal(submitted.status, "running");
  const settled = await started.run().done;
  assert.equal(settled.status, "failed");
  assert.match(settled.detail, /disabled/);

  // Unknown plugins are rejected before any job is started.
  await assert.rejects(
    () => operation.execute({ path: "capture.img", plugins: ["windows.bogus"] }, { workspace, jobs }),
    /unknown volatility plugin/,
  );
});

test("memory image: offline volatility3 run over the foundation XP corpus", { timeout: 900_000 }, async (context) => {
  const repository = path.resolve(".");
  const dataset = path.join(repository, ".minusone", "datasets", "win-xp-laptop-2005-06-25.img");
  const dockerUp = await probe("docker", ["info"]);
  const imagePresent = await probe("docker", ["image", "inspect", "minusone/volatility3:2.28.0"]);
  const datasetPresent = await stat(dataset).then(() => true, () => false);
  if (!dockerUp || !imagePresent || !datasetPresent) {
    context.skip(
      `needs the docker daemon, minusone/volatility3:2.28.0 (npm run providers:build), and the corpus image (node scripts/fetch-volatility-data.mjs) — docker=${dockerUp} image=${imagePresent} dataset=${datasetPresent}`,
    );
    return;
  }

  const workspace = await Workspace.create(repository);
  const result = await runVolatilityPlugins(workspace, ".minusone/datasets/win-xp-laptop-2005-06-25.img", {
    plugins: ["windows.info", "windows.pslist", "windows.cmdline"],
    maxRows: 400,
    timeoutSeconds: 600,
  });
  assert.equal(result.backend, "docker");

  const byPlugin = Object.fromEntries(result.plugins.map((entry) => [entry.plugin, entry]));
  const info = byPlugin["windows.info"];
  assert.equal(info.ok, true, info.error);
  const majorVersion = info.rows.find((row) => row.Variable === "NtMajorVersion");
  assert.equal(majorVersion?.Value, "5", "the XP capture must identify as Windows NT 5.x");

  const pslist = byPlugin["windows.pslist"];
  assert.equal(pslist.ok, true, pslist.error);
  assert.ok(pslist.rowCountTotal >= 30, `a live XP session has dozens of processes, got ${pslist.rowCountTotal}`);
  assert.ok(pslist.rows.some((row) => row.ImageFileName === "System"));

  const cmdline = byPlugin["windows.cmdline"];
  assert.equal(cmdline.ok, true, cmdline.error);
  const cmdlines = JSON.stringify(cmdline.rows);
  assert.ok(/svchost|lsass|explorer/i.test(cmdlines), "core XP processes must appear in the cmdline table");
});
