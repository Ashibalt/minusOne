import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { operations } from "../dist/core/operations.js";

function stringEnvironment(extra) {
  return Object.fromEntries(
    Object.entries({ ...process.env, ...extra }).filter((entry) => typeof entry[1] === "string"),
  );
}

test("MCP facade mirrors the operation table and runs the job seam", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-mcp-"));
  const workspace = path.join(parent, "workspace");
  await mkdir(workspace);
  await writeFile(path.join(workspace, "sample.bin"), Buffer.from("MZ\0\0hello-from-mcp\0", "ascii"));
  await writeFile(path.join(parent, "outside.bin"), "outside");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.resolve("dist/mcp/server.js")],
    env: stringEnvironment({
      MINUSONE_WORKSPACE: workspace,
      MINUSONE_GHIDRA_IMAGE: "",
      MINUSONE_GHIDRA_HEADLESS: "",
    }),
    stderr: "pipe",
  });
  const client = new Client({ name: "minusone-test", version: "0.1.0" });
  context.after(async () => {
    await client.close();
    await rm(parent, { recursive: true, force: true });
  });
  await client.connect(transport);

  // The facade is rendered from the operation table: parity is structural.
  const listed = await client.listTools();
  const names = listed.tools.map((tool) => tool.name);
  const expected = [...operations.map((operation) => operation.toolName), "job_output", "job_kill"];
  assert.deepEqual(names.sort(), [...expected].sort());
  const decompile = listed.tools.find((tool) => tool.name === "function_decompile");
  assert.ok(decompile, "function_decompile is exposed over MCP");
  assert.equal(decompile.inputSchema.type, "object");
  assert.ok(decompile.inputSchema.properties.addresses, "address-scoped parameters carried over");

  const strings = await client.callTool({
    name: "strings_extract",
    arguments: { path: "sample.bin", minLength: 5, limit: 10 },
  });
  assert.equal(strings.isError, undefined);
  assert.match(strings.content[0].text, /hello-from-mcp/);

  const escaped = await client.callTool({
    name: "binary_inspect",
    arguments: { path: "../outside.bin" },
  });
  assert.equal(escaped.isError, true);
  assert.match(escaped.content[0].text, /escapes the workspace/);

  // Job-based operations work over MCP through the in-process registry.
  const submission = await client.callTool({
    name: "function_decompile",
    arguments: { path: "sample.bin" },
  });
  const submitted = JSON.parse(submission.content[0].text);
  assert.equal(submitted.status, "running");
  assert.match(submitted.jobId, /^mcp-job-\d+$/);

  const outcome = await client.callTool({
    name: "job_output",
    arguments: { job_id: submitted.jobId, wait: true },
  });
  const settled = JSON.parse(outcome.content[0].text);
  assert.equal(settled.status, "failed", "no Ghidra backend is configured in this environment");
  assert.match(settled.detail, /Ghidra is disabled|disabled/);

  const unknown = await client.callTool({
    name: "job_output",
    arguments: { job_id: "mcp-job-999" },
  });
  assert.equal(unknown.isError, true);
  assert.match(unknown.content[0].text, /unknown job id/);
});
