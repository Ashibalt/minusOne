import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { renderMcpConfig, MCP_TARGETS } from "../dist/cli/mcp-config.js";
import { rmRoot } from "./helpers.mjs";

const HTTP_PORT = 3929;

function sseJson(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  for (const line of trimmed.split(/\r?\n/)) {
    if (line.startsWith("data: ")) {
      const data = line.slice(6).trim();
      if (data.startsWith("{")) return JSON.parse(data);
    }
  }
  throw new Error(`no JSON payload in response: ${trimmed.slice(0, 200)}`);
}

test("renderMcpConfig emits a copy-pasteable snippet for every host", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-mcpcfg-"));
  context.after(() => rmRoot(parent));
  for (const target of MCP_TARGETS) {
    const stdio = renderMcpConfig(target, { workspace: parent });
    assert.ok(stdio.snippet.length > 10, `${target} has a snippet`);
    assert.ok(stdio.file.length > 0, `${target} names its config file`);
    assert.ok(stdio.note.length > 0, `${target} explains itself`);
    const http = renderMcpConfig(target, { workspace: parent, httpUrl: "http://127.0.0.1:3080/mcp" });
    assert.ok(http.snippet.includes("http://127.0.0.1:3080/mcp"), `${target} HTTP snippet carries the URL`);
  }
  const vscode = renderMcpConfig("vscode", { workspace: parent });
  assert.ok(vscode.snippet.includes("server.js"), "stdio snippets reference the server module");
});

test("HTTP transport serves the full operation table and executes tools", { timeout: 60_000 }, async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-mcphttp-"));
  context.after(() => rmRoot(parent));
  await writeFile(path.join(parent, "sample.bin"), "minusone-http-test-content");

  const serverPath = path.resolve("dist/mcp/server.js");
  const child = spawn(process.execPath, [serverPath, "--transport", "http", "--port", String(HTTP_PORT)], {
    env: { ...process.env, MINUSONE_WORKSPACE: parent },
    stdio: ["ignore", "ignore", "pipe"],
  });
  context.after(() => child.kill());
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const base = `http://127.0.0.1:${HTTP_PORT}`;
  const post = async (body) =>
    await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify(body),
    });

  // Wait for the listener.
  let up = false;
  for (let attempt = 0; attempt < 100 && !up; attempt += 1) {
    try {
      up = (await fetch(`${base}/health`)).ok;
    } catch {
      // not yet
    }
    if (!up) await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(up, `server never came up; stderr: ${stderr}`);

  const health = await (await fetch(`${base}/health`)).json();
  assert.equal(health.server, "minusone-re");
  assert.equal(health.transport, "http");

  const initResponse = await post({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } },
  });
  const init = sseJson(await initResponse.text());
  assert.equal(init.result.serverInfo.name, "minusone-re");

  const listResponse = await post({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const list = sseJson(await listResponse.text());
  const names = list.result.tools.map((tool) => tool.name);
  assert.ok(names.includes("binary_find"), "intent ops are exposed over HTTP");
  assert.ok(names.includes("binary_triage"));
  assert.ok(names.includes("pe_rebuild"));
  assert.ok(names.includes("job_output"));

  const callResponse = await post({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "binary_find", arguments: { path: "sample.bin", needle: "http-test" } },
  });
  const call = sseJson(await callResponse.text());
  assert.equal(call.result.isError, undefined);
  const payload = JSON.parse(call.result.content[0].text);
  assert.ok(payload.hitCount >= 1, "the tool actually executed over HTTP");
  assert.ok(payload.planeCounts.strings >= 1);

  const methodGuard = await fetch(`${base}/mcp`, { method: "GET" });
  assert.equal(methodGuard.status, 405);
});
