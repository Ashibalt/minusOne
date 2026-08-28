#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFile, realpath, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { baselineAnalyze } from "../core/analyzer.js";
import { configPath, readWorkspaceConfig, trustRoot, untrustRoot, writeModelsMode, writeWorkspaceConfig } from "../core/config.js";
import { killExternalModelsSidecar } from "../core/models.js";
import { createDoctorReport } from "../core/doctor.js";
import { cleanWorkspaceHygiene, collectHygiene, formatBytes } from "../core/hygiene.js";
import { runGhidraAnalysis } from "../core/ghidra.js";
import { resolveOpenCodeExecutable } from "../core/opencode.js";
import { MCP_TARGETS, buildProjectMcpConfig, renderMcpConfig, type McpTarget } from "./mcp-config.js";
import { Workspace } from "../core/workspace.js";

const executableDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(executableDirectory, "../..");
const serverModulePath = path.join(packageRoot, "dist", "mcp", "server.js");

function printHelp(): void {
  console.log(`minusOne proof of concept

Usage:
  minusOne setup [--images-only|--report-only|--skip-build]
                                One-command setup: docker images + TTD + readiness report
  minusOne doctor [workspace] [--json] [--clean]
                                Health check + disk hygiene report; --clean empties
                                .minusone/tmp and unloads an orphan models sidecar
                                (explicit flag only — nothing is deleted silently)
  minusOne analyze <binary> [--workspace <path>] [--json]
  minusOne ghidra <binary> [--workspace <path>]
  minusOne mcp-check [workspace]
  minusOne chat [workspace] [-- <opencode options>]
  minusOne arm [workspace]      Arm the dynamic plane for this workspace (one-time)
  minusOne disarm [workspace]   Disarm the dynamic plane for this workspace
  minusOne models on|off|status [workspace]
                                Toggle the model-ranking plane (CLAP + BinSeek; opt-in)
  minusOne trust <dir>          Authorize a READ-ONLY external sample directory (workspace stays write-only)
  minusOne untrust <dir>        Remove a trusted root; bare 'untrust' lists them
  minusOne mcp --for <claude|cursor|cline|continue|vscode|dsh|opencode> [--http [url]]
                                Print a host-specific MCP config snippet
  minusOne mcp serve [--http] [--port <n>] [--host <addr>]
                                Run the MCP facade (stdio default; HTTP for remote hosts)
  minusOne mcp link [project]   Drop a project-scoped .mcp.json (workspace follows the project)

Environment:
  MINUSONE_OPENCODE_BIN      Optional explicit path to the OpenCode executable
  MINUSONE_GHIDRA_HEADLESS  Path to a safe analyzeHeadless executable wrapper
  MINUSONE_GHIDRA_IMAGE     Docker image for Ghidra headless mode
  MINUSONE_ALLOW_DYNAMIC    "1" arms the dynamic plane for one invocation (overrides .minusone/config.json)
  MINUSONE_DYNAMIC_TARGET   "local" authorizes the analyst host as the execution target (owner decision)
  MINUSONE_TRUSTED_ROOTS    path.delimiter-separated read-only external sample roots`);
}

function printDoctor(report: Awaited<ReturnType<typeof createDoctorReport>>): void {
  console.log(`Workspace: ${report.workspace}`);
  console.log(`Platform:  ${report.platform}/${report.architecture}`);
  console.log(`Node:      ${report.node}`);
  console.log("");
  for (const capability of report.capabilities) {
    const status = capability.available ? "ok" : "missing";
    const detail = capability.version ?? capability.path ?? capability.note ?? "";
    console.log(`${status.padEnd(8)} ${capability.name.padEnd(10)} ${detail}`.trimEnd());
  }
  console.log("");
  console.log(`Baseline analysis: ${report.readyForBaselineAnalysis ? "ready" : "not ready"}`);
  console.log(`Ghidra analysis:   ${report.readyForGhidra ? "ready" : "not configured"}`);
}

function printHygiene(hygiene: Awaited<ReturnType<typeof collectHygiene>>): void {
  console.log("");
  console.log("Disk hygiene:");
  if (!hygiene.present) {
    console.log("  .minusone directory not present — nothing held");
  } else {
    console.log(`  .minusone holds ${formatBytes(hygiene.totalBytes)} (${hygiene.minusoneDir})`);
    for (const entry of hygiene.entries) {
      if (entry.bytes === 0) continue;
      const tag = entry.cleanable ? "cleanable" : "kept";
      console.log(`    ${tag.padEnd(10)} ${formatBytes(entry.bytes).padStart(9)}  ${entry.name}${entry.note !== undefined ? ` — ${entry.note}` : ""}`);
    }
    if (hygiene.cleanableBytes > 0) {
      console.log(`  reclaimable now: ${formatBytes(hygiene.cleanableBytes)} — run 'minusOne doctor --clean'`);
    }
  }
  console.log(`  ${hygiene.sidecar.detail}`);
  if (hygiene.docker.reclaimable !== null) {
    console.log(`  docker reclaimable: ${hygiene.docker.reclaimable}`);
  }
  if (hygiene.docker.suggestion !== null) {
    console.log(`  ${hygiene.docker.suggestion}`);
  }
}

function mergeOpenCodeConfig(existingValue: string | undefined, workspace: string): string {
  let existing: Record<string, unknown> = {};
  if (existingValue) {
    try {
      existing = JSON.parse(existingValue) as Record<string, unknown>;
    } catch {
      throw new Error("OPENCODE_CONFIG_CONTENT contains invalid JSON");
    }
  }

  const existingMcp = typeof existing.mcp === "object" && existing.mcp !== null ? existing.mcp : {};
  const existingPermissions = typeof existing.permission === "object" && existing.permission !== null ? existing.permission : {};
  const existingSkills = typeof existing.skills === "object" && existing.skills !== null
    ? existing.skills as Record<string, unknown>
    : {};
  const existingSkillPaths = Array.isArray(existingSkills.paths) ? existingSkills.paths : [];
  const mcpServer = path.join(packageRoot, "dist", "mcp", "server.js");
  const skillDirectory = path.join(packageRoot, ".opencode", "skills");

  return JSON.stringify({
    ...existing,
    mcp: {
      ...existingMcp,
      minusone_re: {
        type: "local",
        command: [process.execPath, mcpServer],
        enabled: true,
        environment: {
          MINUSONE_WORKSPACE: workspace,
          ...(process.env.MINUSONE_GHIDRA_HEADLESS ? { MINUSONE_GHIDRA_HEADLESS: process.env.MINUSONE_GHIDRA_HEADLESS } : {}),
          ...(process.env.MINUSONE_GHIDRA_IMAGE ? { MINUSONE_GHIDRA_IMAGE: process.env.MINUSONE_GHIDRA_IMAGE } : {}),
        },
      },
    },
    skills: {
      ...existingSkills,
      paths: [...existingSkillPaths, skillDirectory],
    },
    permission: {
      ...existingPermissions,
      "minusone_re_*": "allow",
      bash: "ask",
      edit: "ask",
      write: "ask",
    },
  });
}

async function spawnOpenCode(workspacePath: string, args: string[]): Promise<number> {
  const workspace = await Workspace.create(workspacePath);
  const openCodeExecutable = await resolveOpenCodeExecutable();
  if (!openCodeExecutable) throw new Error("OpenCode executable was not found; set MINUSONE_OPENCODE_BIN");
  const env = {
    ...process.env,
    OPENCODE_CONFIG_CONTENT: mergeOpenCodeConfig(process.env.OPENCODE_CONFIG_CONTENT, workspace.root),
  };
  return await new Promise<number>((resolve, reject) => {
    const child = spawn(openCodeExecutable, args, {
      cwd: workspace.root,
      stdio: "inherit",
      env,
      shell: false,
    });
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
}

async function runOpenCode(workspacePath: string, extraArgs: string[]): Promise<number> {
  const workspace = await Workspace.create(workspacePath);
  return await spawnOpenCode(workspace.root, [workspace.root, "--pure", ...extraArgs]);
}

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return 0;
  }

  if (command === "setup") {
    const bootstrap = await import("node:child_process");
    const result = bootstrap.spawnSync(process.execPath, [path.join(packageRoot, "scripts", "bootstrap.mjs"), ...args.filter((arg) => !arg.startsWith("--root"))], { stdio: "inherit" });
    return result.status ?? 1;
  }

  if (command === "doctor") {
    const json = args.includes("--json");
    const clean = args.includes("--clean");
    const workspaceArg = args.find((arg) => !arg.startsWith("--")) ?? process.cwd();
    const workspace = await Workspace.create(workspaceArg);
    if (clean) {
      // Explicit flag only: empty .minusone/tmp + unload an orphan sidecar.
      // Everything else (artifacts, outputs, run dirs, datasets) stays.
      const result = await cleanWorkspaceHygiene(workspace);
      for (const action of result.actions) console.log(action);
      console.log(`Total freed: ${formatBytes(result.freedBytes)}`);
      return 0;
    }
    const report = await createDoctorReport(workspace);
    const hygiene = await collectHygiene(workspace);
    if (json) {
      console.log(JSON.stringify({ ...report, hygiene }, null, 2));
    } else {
      printDoctor(report);
      printHygiene(hygiene);
    }
    return report.readyForBaselineAnalysis ? 0 : 1;
  }

  if (command === "analyze") {
    const binary = args[0];
    if (!binary) throw new Error("analyze requires a workspace-relative binary path");
    const workspaceFlag = args.indexOf("--workspace");
    const workspacePath = workspaceFlag >= 0 ? args[workspaceFlag + 1] : process.cwd();
    if (!workspacePath) throw new Error("--workspace requires a path");
    const workspace = await Workspace.create(workspacePath);
    const analysis = await baselineAnalyze(workspace, binary);
    console.log(JSON.stringify(analysis, null, 2));
    return 0;
  }

  if (command === "ghidra") {
    const binary = args[0];
    if (!binary) throw new Error("ghidra requires a workspace-relative binary path");
    const workspaceFlag = args.indexOf("--workspace");
    const workspacePath = workspaceFlag >= 0 ? args[workspaceFlag + 1] : process.cwd();
    if (!workspacePath) throw new Error("--workspace requires a path");
    const workspace = await Workspace.create(workspacePath);
    const analysis = await runGhidraAnalysis(workspace, binary);
    console.log(JSON.stringify(analysis, null, 2));
    return analysis.command.exitCode === 0 && !analysis.command.timedOut ? 0 : 1;
  }

  if (command === "mcp-check") {
    return await spawnOpenCode(args[0] ?? process.cwd(), ["mcp", "list", "--pure"]);
  }

  if (command === "arm" || command === "disarm") {
    const workspaceArg = args[0];
    if (!workspaceArg) throw new Error(`${command} requires a workspace path (or run it inside the workspace)`);
    const workspace = await Workspace.create(workspaceArg);
    const config = await writeWorkspaceConfig(workspace, command === "arm" ? "local" : "none");
    if (command === "arm") {
      console.log(`Dynamic plane ARMED: this host is the LOCAL execution target.`);
      console.log(`sample_execute / dynamic_unpack / debug sessions now run samples here by owner decision.`);
    } else {
      console.log(`Dynamic plane DISARMED: samples are never executed until 'minusone arm' is run again.`);
    }
    console.log(configPath(workspace));
    void config;
    return 0;
  }

  if (command === "models") {
    const mode = args[0];
    const workspaceArg = mode === "on" || mode === "off" ? args[1] : args[0];
    const workspace = await Workspace.create(workspaceArg ?? process.cwd());
    if (mode === "on" || mode === "off") {
      const config = await writeModelsMode(workspace, mode);
      if (mode === "on") {
        console.log(`Model ranking ENABLED (CLAP + BinSeek sidecar).`);
        console.log(`model_rank_assembly / model_rank_pseudocode now rank; needs python + torch + transformers + sentence-transformers.`);
      } else {
        // Unload a live sidecar immediately (even one owned by the running
        // MCP server) — `models off` must free the VRAM, not just flip the
        // config the next request would read.
        const unload = await killExternalModelsSidecar();
        console.log(`Model ranking DISABLED: ranking operations return status=unavailable, everything else is unchanged.`);
        console.log(`Sidecar: ${unload.detail}${unload.pid !== null ? ` (pid ${unload.pid})` : ""}`);
      }
      console.log(configPath(workspace));
      void config;
      return 0;
    }
    const config = await readWorkspaceConfig(workspace);
    console.log(`Model ranking: ${config.models === "on" ? "ON (CLAP + BinSeek sidecar)" : "OFF (ranking operations report unavailable)"}`);
    console.log(`Toggle with: minusone models on|off`);
    console.log(configPath(workspace));
    return 0;
  }

  if (command === "trust" || command === "untrust") {
    const workspaceArg = command === "trust" ? (args[1] !== undefined && args[1] !== "--root" ? args[0] : process.cwd()) : process.cwd();
    const rootFlag = args.indexOf("--root");
    const directory = rootFlag >= 0 ? args[rootFlag + 1] : (command === "trust" ? args[args.length - 1] : args[0]);
    const workspace = await Workspace.create(workspaceArg);
    if (command === "untrust" && (directory === undefined || directory === process.cwd()) && rootFlag < 0) {
      const config = await readWorkspaceConfig(workspace);
      if (config.trustedRoots.length === 0) {
        console.log("No trusted roots configured.");
        return 0;
      }
      console.log("Trusted read-only roots (remove with 'minusone untrust <dir>'):");
      for (const root of config.trustedRoots) console.log(`  ${root}`);
      return 0;
    }
    if (!directory || !directory.trim()) throw new Error(`${command} requires a directory path`);
    const resolved = await realpath(path.resolve(directory));
    const stats = await stat(resolved);
    if (!stats.isDirectory()) throw new Error(`trust target is not a directory: ${directory}`);
    if (command === "trust") {
      const config = await trustRoot(workspace, resolved);
      console.log(`Trusted READ-ONLY root added: ${resolved}`);
      console.log(`  samples inside it resolve without copying/hardlinking; writes NEVER go there.`);
      console.log(`  ${config.trustedRoots.length} root(s) configured at ${configPath(workspace)}`);
    } else {
      const config = await untrustRoot(workspace, resolved);
      console.log(`Trusted root removed: ${resolved}`);
      console.log(`  ${config.trustedRoots.length} root(s) remain at ${configPath(workspace)}`);
    }
    return 0;
  }

  if (command === "chat") {
    const separator = args.indexOf("--");
    const beforeSeparator = separator >= 0 ? args.slice(0, separator) : args;
    const extraArgs = separator >= 0 ? args.slice(separator + 1) : [];
    const workspacePath = beforeSeparator[0] ?? process.cwd();
    return await runOpenCode(workspacePath, extraArgs);
  }

  if (command === "mcp") {
    const sub = args[0];
    if (sub === "serve") {
      const rest = args.slice(1);
      const serverArgs: string[] = [];
      if (rest.includes("--http")) serverArgs.push("--transport", "http");
      const portFlag = rest.indexOf("--port");
      if (portFlag >= 0) serverArgs.push("--port", rest[portFlag + 1] ?? "");
      const hostFlag = rest.indexOf("--host");
      if (hostFlag >= 0) serverArgs.push("--host", rest[hostFlag + 1] ?? "");
      const server = path.join(packageRoot, "dist", "mcp", "server.js");
      const child = spawn(process.execPath, [server, ...serverArgs], { stdio: "inherit" });
      return await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
    }

    if (sub === "link") {
      const projectArg = args[1] ?? process.cwd();
      const projectRoot = await realpath(path.resolve(projectArg));
      const projectStats = await stat(projectRoot);
      if (!projectStats.isDirectory()) {
        throw new Error(`link target is not a directory: ${projectArg}`);
      }
      const configFile = path.join(projectRoot, ".mcp.json");
      const built = buildProjectMcpConfig(projectRoot);
      // Merge minusone_re into any existing project .mcp.json (preserve other servers).
      let existing: Record<string, unknown> = {};
      try {
        existing = JSON.parse(await readFile(configFile, "utf8")) as Record<string, unknown>;
      } catch {
        existing = {};
      }
      const existingServers = (typeof existing.mcpServers === "object" && existing.mcpServers !== null
        ? existing.mcpServers
        : {}) as Record<string, unknown>;
      const hadMinusone = existingServers.minusone_re !== undefined;
      const merged: Record<string, unknown> = {
        ...existing,
        mcpServers: { ...existingServers, minusone_re: (built.mcpServers as Record<string, unknown>).minusone_re },
      };
      await writeFile(configFile, JSON.stringify(merged, null, 2) + "\n", "utf8");
      const minusoneServer = (built.mcpServers as { minusone_re: { command: string; args: string[] } }).minusone_re;
      console.log(`linked minusone_re into ${configFile}`);
      console.log(`  workspace: ${projectRoot}`);
      console.log(`  command:   ${minusoneServer.command} ${minusoneServer.args.join(" ")}`);
      console.log(`  server:    ${serverModulePath}`);
      console.log(`  ${hadMinusone ? "overwrote" : "added"} minusone_re${Object.keys(existingServers).filter((k) => k !== "minusone_re").length > 0 ? " (other servers preserved)" : ""}`);
      console.log(`run 'claude mcp list' inside ${projectRoot} to verify`);
      return 0;
    }

    const forFlag = args.indexOf("--for");
    const target = forFlag >= 0 ? args[forFlag + 1] : undefined;
    if (target === undefined || !MCP_TARGETS.includes(target as McpTarget)) {
      throw new Error(`mcp --for requires one of: ${MCP_TARGETS.join(", ")} (or use 'mcp link [project]' / 'mcp serve')`);
    }
    const httpFlag = args.indexOf("--http");
    const httpUrl =
      httpFlag >= 0
        ? (args[httpFlag + 1]?.startsWith("http") ? args[httpFlag + 1] : "http://127.0.0.1:3080/mcp")
        : undefined;
    const workspacePath = process.cwd();
    const workspace = await Workspace.create(workspacePath);
    const config = renderMcpConfig(target as McpTarget, { workspace: workspace.root, ...(httpUrl === undefined ? {} : { httpUrl }) });
    console.log(`# Host: ${target}`);
    console.log(`# Config file: ${config.file}`);
    console.log(`# ${config.note}`);
    console.log("");
    console.log(config.snippet);
    return 0;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(`minusone: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  },
);
