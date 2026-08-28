import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function stringEnvironment(extra) {
  return Object.fromEntries(
    Object.entries({ ...process.env, ...extra }).filter((entry) => typeof entry[1] === "string"),
  );
}

// The MCP initialize handshake carries the distilled usage doctrine — the
// contract lines whose violation used to read as "minusOne is broken"
// (30s client timeouts, rankers, megaprocedure decompile budgets, spawn-vs-attach).
test("MCP initialize sends the doctrine instructions", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-instructions-"));
  const workspace = path.join(parent, "workspace");
  await mkdir(workspace);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.resolve("dist/mcp/server.js")],
    env: stringEnvironment({ MINUSONE_WORKSPACE: workspace }),
    stderr: "pipe",
  });
  const client = new Client({ name: "minusone-instructions-test", version: "0.1.0" });
  context.after(async () => {
    await client.close();
    await rm(parent, { recursive: true, force: true });
  });
  await client.connect(transport);

  const instructions = client.getInstructions();
  assert.ok(instructions, "server sends initialize instructions");
  for (const marker of [
    "job_output", // long operations are jobs — poll, don't conclude "broken"
    "replay-out.txt", // trace_replay is file-polled
    "function_decompile_range", // megaprocedure path, not bigger budgets
    "console_launch", // one-live-instance pattern for interactive targets
    "minusOne arm", // dynamic gating is by design
    "binary_patch", // write ops act on copies
  ]) {
    assert.ok(
      instructions.includes(marker),
      `instructions carry the "${marker}" contract line`,
    );
  }
});
