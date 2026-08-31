// v2 battle verification: a REAL campaign driven through the REAL MCP
// server over stdio — plan_run as a job, campaign_status, notes ops, and
// the knowledge plane over a deterministic fake sidecar. Not internals:
// the full transport, the way an agent host drives it.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const FAKE_SIDECAR = path.resolve("test/fixtures/fake-sidecar.py");

function stringEnvironment(extra) {
  return Object.fromEntries(
    Object.entries({ ...process.env, ...extra }).filter((entry) => typeof entry[1] === "string"),
  );
}

function parseToolResult(result) {
  assert.ok(Array.isArray(result.content) && result.content.length > 0, "tool returned content");
  const text = result.content[0].text;
  return JSON.parse(text);
}

test("MCP-live campaign: plan → resume → status → notes → knowledge, end to end over stdio", { timeout: 300_000 }, async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-campaign-e2e-"));
  const workspace = path.join(parent, "workspace");
  await mkdir(workspace);
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });

  // A fixture sample with a findable marker, inside the campaign workspace.
  await writeFile(
    path.join(workspace, "sample.exe"),
    Buffer.from("MZ placeholder PE with CAMPAIGN-MARKER-777 and a license serial hint inside"),
  );

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.resolve("dist/mcp/server.js")],
    env: stringEnvironment({
      MINUSONE_WORKSPACE: workspace,
      MINUSONE_MODELS: "1",
      MINUSONE_MODELS_SIDECAR: FAKE_SIDECAR,
      MINUSONE_MODELS_PYTHON: "python",
    }),
    stderr: "pipe",
  });
  const client = new Client({ name: "minusone-campaign-e2e", version: "0.1.0" });
  context.after(async () => {
    await client.close();
  });
  await client.connect(transport);

  // The new operations are visible over the transport.
  const tools = await client.listTools();
  const names = tools.tools.map((tool) => tool.name);
  for (const expected of ["plan_run", "campaign_status", "notes_read", "notes_update", "knowledge_index", "knowledge_query"]) {
    assert.ok(names.includes(expected), `MCP exposes ${expected}`);
  }

  // 1. plan_run with a real plan: strings + unpack probe (empty result, no
  //    fallback) + signature check. Runs as a job — poll job_output.
  const submitted = parseToolResult(await client.callTool({
    name: "plan_run",
    arguments: {
      plan: {
        version: 1,
        goal: "e2e: triage the fixture and probe unpack",
        goalArtifacts: [{ task: "strings", kind: "exists" }],
        tasks: [
          { id: "strings", operation: "strings_find", args: { path: "sample.exe", mode: "leading-window", needle: "CAMPAIGN-MARKER" } },
          { id: "unpack", operation: "unpack_static", args: { path: "sample.exe" }, dependsOn: ["strings"], fallback: true },
          { id: "signature", operation: "signature_verify", args: { path: "sample.exe" }, dependsOn: ["strings"], onFailure: "skip" },
        ],
      },
    },
  }));
  assert.equal(submitted.status, "running", "plan_run submits a job");
  assert.ok(submitted.jobId, "job id returned");

  let report = null;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const polled = parseToolResult(await client.callTool({ name: "job_output", arguments: { job_id: submitted.jobId, wait: true } }));
    if (polled.status === "completed") {
      report = JSON.parse(polled.output);
      break;
    }
    if (polled.status === "failed" || polled.status === "killed") {
      assert.fail(`plan job ${polled.status}: ${polled.detail ?? "no detail"}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.ok(report, "plan job completed");
  assert.equal(report.status, "completed");
  assert.deepEqual([...report.completed].sort(), ["signature", "strings", "unpack"], `all tasks completed: ${JSON.stringify(report.failed)}`);
  assert.deepEqual(report.goalArtifacts.present, ["strings"]);

  // The dossier exists on disk with assembled + raw.
  const status1 = parseToolResult(await client.callTool({ name: "campaign_status", arguments: {} }));
  assert.equal(status1.hasCampaign, true);
  assert.equal(status1.goal, "e2e: triage the fixture and probe unpack");
  assert.deepEqual(status1.tasks.map((task) => task.state), ["completed", "completed", "completed"]);
  assert.ok(status1.dossierEntries.length >= 3, "dossier entries recorded");

  // 2. Resume: same call, no plan — everything skips from the dossier.
  const resumed = parseToolResult(await client.callTool({ name: "plan_run", arguments: {} }));
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const polled = parseToolResult(await client.callTool({ name: "job_output", arguments: { job_id: resumed.jobId, wait: true } }));
    if (polled.status === "completed") {
      const report2 = JSON.parse(polled.output);
      assert.deepEqual([...report2.resumedFromDossier].sort(), ["signature", "strings", "unpack"], "resume skips completed tasks");
      assert.deepEqual(report2.completed, [], "nothing re-ran on resume");
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  // 3. Notes: write findings, read them back.
  await client.callTool({ name: "notes_update", arguments: { action: "hypothesis", text: "the marker is a plaintext string", status: "confirmed" } });
  await client.callTool({ name: "notes_update", arguments: { action: "log", text: "strings_find located CAMPAIGN-MARKER in the fixture" } });
  const notes = parseToolResult(await client.callTool({ name: "notes_read", arguments: {} }));
  assert.equal(notes.exists, true);
  assert.match(notes.markdown, /plaintext string/);
  assert.equal(notes.summary.hypotheses.confirmed, 1);

  // 4. Knowledge plane: index the dossier, then query it.
  const indexJob = parseToolResult(await client.callTool({ name: "knowledge_index", arguments: {} }));
  assert.equal(indexJob.status, "running");
  let indexReport = null;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const polled = parseToolResult(await client.callTool({ name: "job_output", arguments: { job_id: indexJob.jobId, wait: true } }));
    if (polled.status === "completed") {
      indexReport = JSON.parse(polled.output);
      break;
    }
    if (polled.status === "failed" || polled.status === "killed") {
      assert.fail(`knowledge_index job ${polled.status}: ${polled.detail ?? "no detail"}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.ok(indexReport, "knowledge_index completed");
  assert.equal(indexReport.status, "ok", indexReport.error ?? "");
  assert.ok(indexReport.addedChunks >= 1, "chunks embedded");

  const answer = parseToolResult(await client.callTool({ name: "knowledge_query", arguments: { query: "where is the license serial" } }));
  assert.equal(answer.status, "ok", answer.error ?? "");
  assert.ok(answer.ranked.length >= 1, "ranked chunks returned");
  assert.ok(answer.ranked[0].file, "hits carry the source file pointer");
});
