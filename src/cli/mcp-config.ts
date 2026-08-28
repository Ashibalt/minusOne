/**
 * Config snippets for plugging minusOne into agent hosts. Each host speaks
 * MCP differently (command arrays, env maps, URLs); one function per host
 * keeps the differences explicit and copy-pasteable.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

const executableDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(executableDirectory, "../..");

export type McpTarget = "claude" | "cursor" | "cline" | "continue" | "vscode" | "dsh" | "opencode";

export const MCP_TARGETS: readonly McpTarget[] = ["claude", "cursor", "cline", "continue", "vscode", "dsh", "opencode"] as const;

function serverModule(): string {
  return path.join(packageRoot, "dist", "mcp", "server.js");
}

export interface McpConfigContext {
  workspace: string;
  /** HTTP endpoint instead of stdio (e.g. http://127.0.0.1:3080/mcp). */
  httpUrl?: string;
}

function stdioEnv(context: McpConfigContext): Record<string, string> {
  const env: Record<string, string> = { MINUSONE_WORKSPACE: context.workspace };
  for (const key of ["MINUSONE_GHIDRA_HEADLESS", "MINUSONE_GHIDRA_IMAGE", "MINUSONE_FLOSS_IMAGE", "MINUSONE_DIE_IMAGE", "MINUSONE_BINWALK_IMAGE", "MINUSONE_CAPA_IMAGE", "MINUSONE_PE_TOOLS_IMAGE", "MINUSONE_R2_IMAGE", "MINUSONE_IDAT_PATH", "MINUSONE_IDA_HOME", "MINUSONE_CDB_PATH", "MINUSONE_X64DBG_HOME", "MINUSONE_PESIEVE_BIN"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key] as string;
  }
  return env;
}

/**
 * Build the project-scoped .mcp.json object for Claude Code (mcpServers). Used
 * by `minusone mcp link` to drop a file that follows the project's workspace
 * and overrides the user-scope registration.
 */
export function buildProjectMcpConfig(workspace: string): Record<string, unknown> {
  return {
    mcpServers: {
      minusone_re: {
        command: process.execPath,
        args: [serverModule()],
        env: stdioEnv({ workspace }),
      },
    },
  };
}

export function renderMcpConfig(target: McpTarget, context: McpConfigContext): { file: string; snippet: string; note: string } {
  const command = [process.execPath, serverModule()];
  const env = stdioEnv(context);

  switch (target) {
    case "claude":
      // Claude Code: `claude mcp add` flags or ~/.claude.json mcpServers.
      return {
        file: "~/.claude.json (mcpServers) or `claude mcp add` command",
        snippet: context.httpUrl !== undefined
          ? `claude mcp add --transport http minusone_re ${context.httpUrl} --env MINUSONE_WORKSPACE="${context.workspace}"`
          : `claude mcp add minusone_re -- ${process.execPath} "${serverModule()}" --env MINUSONE_WORKSPACE="${context.workspace}"`,
        note: "Claude Code registers the server per project; the command form is the fastest route. Set MINUSONE_WORKSPACE to your analysis workspace before adding.",
      };
    case "cursor":
      return {
        file: ".cursor/mcp.json",
        snippet: JSON.stringify({
          mcpServers: {
            minusone_re: context.httpUrl !== undefined
              ? { url: context.httpUrl }
              : { command: process.execPath, args: [serverModule()], env },
          },
        }, null, 2),
        note: "Drop the file at the workspace root (or merge into the global one). Cursor supports stdio and HTTP MCP servers.",
      };
    case "cline":
      return {
        file: "VS Code settings: cline.mcpServers (settings.json)",
        snippet: JSON.stringify({
          "cline.mcpServers": {
            minusone_re: context.httpUrl !== undefined
              ? { url: context.httpUrl, disabled: false }
              : { command: process.execPath, args: [serverModule()], env, disabled: false },
          },
        }, null, 2),
        note: "Cline reads MCP servers from VS Code settings. Merge the block into your settings.json.",
      };
    case "continue":
      return {
        file: "~/.continue/config.yaml (experimental.mcpServers)",
        snippet: [
          "experimental:",
          "  modelContextProtocolServers:",
          "    - name: minusone_re",
          ...(context.httpUrl !== undefined
            ? [`      url: ${context.httpUrl}`]
            : [
                `      command: ${process.execPath}`,
                `      args:`,
                `        - ${serverModule()}`,
                `      env:`,
                ...(Object.keys(env).length === 0 ? [] : Object.entries(env).map(([key, value]) => `        ${key}: ${JSON.stringify(value)}`)),
              ]),
        ].join("\n"),
        note: "Continue supports MCP servers experimentally; see their docs for the current key names.",
      };
    case "vscode":
      return {
        file: ".vscode/mcp.json",
        snippet: JSON.stringify({
          servers: {
            minusone_re: context.httpUrl !== undefined
              ? { type: "http", url: context.httpUrl }
              : { type: "stdio", command: process.execPath, args: [serverModule()], env },
          },
        }, null, 2),
        note: "VS Code 1.99+ ships native MCP support (.vscode/mcp.json). Use the chat 'agent' mode to reach the tools.",
      };
    case "dsh":
      return {
        file: "~/.dsh/profiles/<profile>.yaml or the native plugin config",
        snippet: context.httpUrl !== undefined
          ? `# dsh native plugin speaks to minusOne over HTTP\nminusone:\n  transport: http\n  url: ${context.httpUrl}`
          : `# dsh native plugin launches the MCP facade over stdio\nminusone:\n  transport: stdio\n  command: ${JSON.stringify(command)}\n  env:\n${Object.entries(env).map(([key, value]) => `    ${key}: ${JSON.stringify(value)}`).join("\n")}`,
        note: "The dsh native plugin renders the operation table as dsh tools directly; this snippet is for MCP-based integrations.",
      };
    case "opencode":
      return {
        file: "opencode.json (mcp)",
        snippet: JSON.stringify({
          mcp: {
            minusone_re: context.httpUrl !== undefined
              ? { type: "remote", url: context.httpUrl, enabled: true }
              : { type: "local", command: [process.execPath, serverModule()], enabled: true, environment: env },
          },
        }, null, 2),
        note: "`minusone chat` wires this automatically; the snippet is for a manual setup.",
      };
  }
}
