/**
 * Native dsh plugin for minusOne: renders the semantic operation table onto
 * `ctx.tools`, bypassing the MCP transport for dsh hosts. Long-running
 * providers (Ghidra) submit through `ctx.jobs` when the composition provides
 * a controller. Loaded from a profile patch row whose `name` is a `file://`
 * URL of the compiled `dist/dsh/plugin.js`.
 */
import { operations } from "../core/operations.js";
import type { JobSubmitSpec, OperationServices } from "../core/operations.js";
import { capToolOutput, resolveMaxOutput } from "../core/outputbudget.js";
import { Workspace } from "../core/workspace.js";

interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  output: {
    schema: Record<string, unknown>;
    render: (args: unknown, value: unknown) => Array<{ type: "text"; text: string }>;
  };
  timeoutMs?: number;
  execute: (args: never, exec: ToolExec) => Promise<unknown>;
}

interface JobsSeam {
  start: (spec: JobSubmitSpec) => string;
}

interface ToolExec {
  agent?: unknown;
  signal?: AbortSignal;
}

interface PluginContext {
  tools: { register: (definition: ToolDefinition) => () => void };
  get: (name: "jobs") => JobsSeam | undefined;
}

export const name = "minusone-re";
export const inject = ["tools", "systemPrompt"];

export interface PluginConfig {
  workspace?: string;
}

function renderJson(_args: unknown, value: unknown) {
  return [{ type: "text" as const, text: JSON.stringify(value, null, 2) }];
}

export async function apply(ctx: PluginContext, config: PluginConfig) {
  if (config !== undefined && config !== null && typeof config !== "object") {
    throw new Error("minusone-re: config must be an object with an optional string `workspace`");
  }
  if (config?.workspace !== undefined && typeof config.workspace !== "string") {
    throw new Error("minusone-re: config.workspace must be a string path");
  }
  const workspace = await Workspace.create(config?.workspace ?? process.env.MINUSONE_WORKSPACE);
  const jobs = ctx.get("jobs");

  for (const operation of operations) {
    ctx.tools.register({
      name: operation.toolName,
      description: operation.description,
      parameters: operation.parameters,
      output: { schema: operation.outputSchema, render: renderJson },
      ...(operation.timeoutMs === undefined ? {} : { timeoutMs: operation.timeoutMs }),
      execute: async (args, exec) => {
        const services: OperationServices = { workspace };
        if (jobs !== undefined) services.jobs = jobs;
        if (exec.agent !== undefined) services.jobOwner = exec.agent;
        if (exec.signal !== undefined) services.signal = exec.signal;
        const value = await operation.execute(args, services);
        const maxOutput = resolveMaxOutput((args as { max_output?: unknown }).max_output);
        const capped = await capToolOutput(workspace, operation.toolName, JSON.stringify(value, null, 2), maxOutput);
        return capped.text;
      },
    });
  }
}
