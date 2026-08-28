import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { rmRoot } from "./helpers.mjs";

const CLI = path.resolve("dist/cli/main.js");

function runCli(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) =>
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
  });
}

async function freshProject() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-mcplink-"));
  return root;
}

test("minusone mcp link writes a project-scoped .mcp.json with the workspace pinned", async (context) => {
  const project = await freshProject();
  context.after(() => rmRoot(project));

  const result = await runCli(["mcp", "link", project]);
  assert.equal(result.code, 0, `cli exited ${result.code}: ${result.stderr}`);
  assert.match(result.stdout, /linked minusone_re into/);

  const config = JSON.parse(await readFile(path.join(project, ".mcp.json"), "utf8"));
  const server = config.mcpServers.minusone_re;
  assert.ok(server, "minusone_re server entry present");
  assert.equal(server.command, process.execPath);
  assert.ok(server.args[0].endsWith(path.join("dist", "mcp", "server.js")));
  assert.equal(server.env.MINUSONE_WORKSPACE, project);
});

test("minusone mcp link merges into an existing .mcp.json without clobbering other servers", async (context) => {
  const project = await freshProject();
  context.after(() => rmRoot(project));

  const configFile = path.join(project, ".mcp.json");
  await writeFile(
    configFile,
    JSON.stringify(
      {
        mcpServers: {
          filesystem: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  const result = await runCli(["mcp", "link", project]);
  assert.equal(result.code, 0, `cli exited ${result.code}: ${result.stderr}`);
  assert.match(result.stdout, /other servers preserved/);

  const config = JSON.parse(await readFile(configFile, "utf8"));
  assert.ok(config.mcpServers.filesystem, "pre-existing filesystem server preserved");
  assert.equal(config.mcpServers.filesystem.command, "npx");
  assert.ok(config.mcpServers.minusone_re, "minusone_re added alongside");
  assert.equal(config.mcpServers.minusone_re.env.MINUSONE_WORKSPACE, project);
});

test("minusone mcp link overwrites a previous minusone_re entry and keeps others", async (context) => {
  const project = await freshProject();
  context.after(() => rmRoot(project));

  const configFile = path.join(project, ".mcp.json");
  await writeFile(
    configFile,
    JSON.stringify(
      {
        mcpServers: {
          minusone_re: { command: "stale", args: ["old.js"], env: { MINUSONE_WORKSPACE: "/old" } },
          other: { command: "keep", args: [] },
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  const result = await runCli(["mcp", "link", project]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /overwrote minusone_re/);

  const config = JSON.parse(await readFile(configFile, "utf8"));
  assert.equal(config.mcpServers.minusone_re.command, process.execPath, "stale command overwritten");
  assert.equal(config.mcpServers.minusone_re.env.MINUSONE_WORKSPACE, project, "workspace repointed");
  assert.equal(config.mcpServers.other.command, "keep", "unrelated server untouched");
});

test("minusone mcp link rejects a non-directory target", async (context) => {
  const project = await freshProject();
  context.after(() => rmRoot(project));
  const fileTarget = path.join(project, "not-a-dir.txt");
  await writeFile(fileTarget, "nope", "utf8");

  const result = await runCli(["mcp", "link", fileTarget]);
  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /not a directory/);
});
