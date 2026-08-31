#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { operations, type JobSubmitSpec } from "../core/operations.js";
import { shutdownModels } from "../core/models.js";
import { capToolOutput, resolveMaxOutput } from "../core/outputbudget.js";
import { shutdownRadareSessions } from "../core/radare.js";
import { Workspace } from "../core/workspace.js";

/**
 * MCP facade rendered directly from the semantic operation table: every
 * operation appears here with its JSON Schema parameters unchanged, so the
 * transports (dsh plugin, MCP stdio, MCP HTTP) can never drift. The
 * low-level Server is used on purpose — it speaks raw JSON Schema, which is
 * what the table holds.
 *
 * Transports:
 *   stdio (default)      — local agent hosts (opencode, dsh, claude code)
 *   --transport http     — Streamable HTTP on 127.0.0.1 for remote/web hosts
 *                          (VS Code extensions, web UIs, anything speaking MCP
 *                          over HTTP). Stateless mode: one server instance
 *                          per connection, matching the SDK's recommended
 *                          scalable deployment.
 */

const DEFAULT_HTTP_PORT = 3080;

/**
 * Distilled usage doctrine, sent to clients in the MCP initialize handshake.
 * The full guide lives in .agents/skills/minusone (SKILL.md + references/) —
 * this is the part that must be in context even when the skill is not loaded:
 * the contracts whose violation reads as "minusOne is broken" but is not.
 */
const MINUSONE_INSTRUCTIONS = [
  "minusOne reverse-engineering doctrine (full guide: .agents/skills/minusone/SKILL.md):",
  "1. Pick the operation that matches your question — each of the ~70 operations is the shortest path to some answer; do not probe around a question with weaker tools, and do not ration calls.",
  "2. Rankers (model_rank_pseudocode/model_rank_assembly) return candidates to verify, never verdicts.",
  "3. Long operations are jobs (poll job_output wait:true) or file-polled (trace_replay writes replay-out.txt beside the trace). A client response that is empty or times out near 30s says NOTHING about success — poll; never conclude 'broken' from it.",
  "4. A decompile timeout on a megaprocedure is expected on flattened code: use function_decompile_range, then model_rank_assembly on the disassembly. Never retry the decompiler with bigger budgets.",
  "5. Most dynamic operations SPAWN their own instance. Interactive/TUI/stateful targets need the one-live-instance pattern: console_launch once, then attach by pid (console_send, frida attach, TTD attach).",
  "6. Write operations (binary_patch, pe_rebuild) act on copies; the original sample is never modified.",
  "7. Dynamic execution is owner-gated: `minusOne arm` once per machine; unarmed refusal is by design.",
  "8. Campaigns (v2): for a CORPUS (2+ files) or a long multi-stage engagement — write a plan and let plan_run orchestrate it (same ops across the batch, fallbacks, parallelism, dossier checkpoint; resume = edit plan.json + re-run). For ONE sample with a few questions, call the operations directly — a single-file plan is overhead. Read notes_read/campaign_status FIRST at session start (context compaction kills unrecorded state); write notes_update CONTINUOUSLY as findings land.",
].join("\n");


function parseArguments(argv: string[]): { transport: "stdio" | "http"; port: number; host: string } {
  const transportFlag = argv.indexOf("--transport");
  const transport = transportFlag >= 0 ? argv[transportFlag + 1] : "stdio";
  if (transport !== "stdio" && transport !== "http") {
    throw new Error(`unknown --transport "${transport}" (expected: stdio | http)`);
  }
  const portFlag = argv.indexOf("--port");
  const port = portFlag >= 0 ? Number(argv[portFlag + 1]) : DEFAULT_HTTP_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid --port "${argv[portFlag + 1] ?? ""}"`);
  }
  const hostFlag = argv.indexOf("--host");
  const host = hostFlag >= 0 ? (argv[hostFlag + 1] ?? "127.0.0.1") : "127.0.0.1";
  return { transport: transport as "stdio" | "http", port, host };
}

const server = new Server(
  { name: "minusone-re", version: "0.1.0" },
  { capabilities: { tools: {} }, instructions: MINUSONE_INSTRUCTIONS },
);
const workspace = await Workspace.create();

interface JobOutcome {
  status: "completed" | "killed" | "failed";
  detail?: string;
  output?: string;
}

interface RunningJob {
  label: string;
  hooks: ReturnType<JobSubmitSpec["run"]>;
  settled?: JobOutcome;
}

/** Minimal in-process job registry so job-based operations work over MCP too. */
const jobs = new Map<string, RunningJob>();
let jobCounter = 0;

const jobRegistry = {
  start(spec: JobSubmitSpec): string {
    jobCounter += 1;
    const id = `mcp-job-${jobCounter}`;
    const hooks = spec.run();
    const job: RunningJob = { label: spec.label, hooks };
    jobs.set(id, job);
    void hooks.done.then(
      (outcome: JobOutcome) => {
        job.settled = outcome;
      },
      (error: unknown) => {
        job.settled = { status: "failed", detail: error instanceof Error ? error.message : String(error) };
      },
    );
    return id;
  },
};

const JOB_WAIT_TIMEOUT_MS = 300_000;

async function jobOutcome(id: string, wait: boolean): Promise<unknown> {
  const job = jobs.get(id);
  if (job === undefined) throw new Error(`unknown job id "${id}"`);
  if (wait && job.settled === undefined) {
    await Promise.race([
      job.hooks.done,
      new Promise((resolve) => setTimeout(resolve, JOB_WAIT_TIMEOUT_MS)),
    ]);
  }
  const settled: JobOutcome | { status: "running" } = job.settled ?? { status: "running" };
  if (settled.status === "running") return { jobId: id, label: job.label, status: "running" };
  return {
    jobId: id,
    label: job.label,
    status: settled.status,
    ...(settled.detail === undefined ? {} : { detail: settled.detail }),
    ...(settled.output === undefined ? {} : { output: settled.output }),
  };
}

const hostTools: Tool[] = [
  {
    name: "job_output",
    description:
      "Read a background job's status and output. Pass wait: true to block until it settles (bounded to 300 seconds).",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string", description: "Job id returned by a job-based tool" },
        wait: { type: "boolean", description: "Block until the job settles" },
      },
      required: ["job_id"],
      additionalProperties: false,
    },
  },
  {
    name: "job_kill",
    description: "Cancel a running background job.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string" },
        reason: { type: "string" },
      },
      required: ["job_id"],
      additionalProperties: false,
    },
  },
];

function result(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

/**
 * Every tool answer goes through the max_output budget (D10): longer than
 * the cap → first max_output chars + the full text spilled to a file under
 * .minusone/outputs/ with the path reported in the answer; shorter → whole
 * text, nothing written. The cap defaults to 8000 and the model overrides it
 * per call via the `max_output` argument.
 */
async function budgetResult(label: string, value: unknown, maxOutput: number) {
  const full = JSON.stringify(value, null, 2);
  const capped = await capToolOutput(workspace, label, full, maxOutput);
  return { content: [{ type: "text" as const, text: capped.text }] };
}

const MAX_OUTPUT_SCHEMA: Record<string, unknown> = {
  type: "integer",
  minimum: 256,
  description: "Max characters of the tool answer returned to you (default 8000). Longer answers are truncated to the first max_output chars and the FULL output is saved to a file under .minusone/outputs/ — the answer carries the file path. Shorter answers come back whole and no file is written.",
};

/** Inject the max_output parameter into every tool schema so models can use it even under additionalProperties:false. */
function withMaxOutput(schema: Tool["inputSchema"]): Tool["inputSchema"] {
  if (schema === null || typeof schema !== "object" || schema.type !== "object") return schema;
  const properties = typeof schema.properties === "object" && schema.properties !== null ? { ...schema.properties } : {};
  if (!("max_output" in properties)) properties.max_output = MAX_OUTPUT_SCHEMA;
  return { ...schema, properties };
}

function failure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return { isError: true, content: [{ type: "text" as const, text: message }] };
}

/** Wire the operation table into a Server instance (shared by both transports). */
function registerHandlers(target: Server): void {
  target.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      ...operations.map((operation) => ({
        name: operation.toolName,
        description: operation.description,
        inputSchema: withMaxOutput(operation.parameters as Tool["inputSchema"]),
      })),
      ...hostTools,
    ],
  }));

  target.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const maxOutput = resolveMaxOutput((args as { max_output?: unknown }).max_output);
    try {
      if (name === "job_output") {
        const { job_id: jobId, wait } = args as { job_id: string; wait?: boolean };
        return await budgetResult("job_output", await jobOutcome(jobId, wait === true), maxOutput);
      }
      if (name === "job_kill") {
        const { job_id: jobId, reason } = args as { job_id: string; reason?: string };
        const job = jobs.get(jobId);
        if (job === undefined) throw new Error(`unknown job id "${jobId}"`);
        job.hooks.cancel(reason);
        return await budgetResult("job_kill", { jobId, status: "killed" }, maxOutput);
      }
      const operation = operations.find((entry) => entry.toolName === name);
      if (operation === undefined) {
        throw new Error(`unknown tool "${name}"; available: ${operations.map((entry) => entry.toolName).join(", ")}, job_output, job_kill`);
      }
      return await budgetResult(operation.toolName, await operation.execute(args, { workspace, jobs: jobRegistry }), maxOutput);
    } catch (error) {
      return failure(error);
    }
  });
}

registerHandlers(server);

// ---------------------------------------------------------------------------
// HTTP transport: one fresh stateless transport per request (SDK-recommended
// scalable pattern). GET /health is a plain liveness probe for orchestrators.
// ---------------------------------------------------------------------------
async function runHttp(options: { port: number; host: string }): Promise<void> {
  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: "minusone-re", transport: "http", workspace: workspace.root }));
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "method not allowed; MCP Streamable HTTP uses POST" }));
      return;
    }
    try {
      // Each request gets its own transport bound to a fresh server instance
      // sharing this module's registries: stateless and horizontally scalable.
      const perRequestServer = new Server(
        { name: "minusone-re", version: "0.1.0" },
        { capabilities: { tools: {} }, instructions: MINUSONE_INSTRUCTIONS },
      );
      registerHandlers(perRequestServer);
      const transport = new StreamableHTTPServerTransport(
        // Stateless mode: every request is self-contained, no session ids.
        // (exactOptionalPropertyTypes forbids `undefined`, so the field is
        // only present in stateful mode; omitting it IS the stateless mode.)
        {},
      );
      res.on("close", () => {
        void transport.close();
        void perRequestServer.close();
      });
      // The SDK's StreamableHTTPServerTransport declares optional lifecycle
      // callbacks as required under exactOptionalPropertyTypes; the runtime
      // contract is satisfied — bridge through a Transport-typed view.
      await perRequestServer.connect(transport as unknown as Parameters<typeof perRequestServer.connect>[0]);
      await transport.handleRequest(req, res);
    } catch (error) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
    }
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(options.port, options.host, () => resolve());
  });
  process.stderr.write(
    `minusone-re MCP (HTTP) listening on http://${options.host}:${options.port}/mcp — POST JSON-RPC; GET /health is the liveness probe\n` +
      `workspace: ${workspace.root}\n`,
  );
  const shutdown = (): void => {
    httpServer.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

const parsed = parseArguments(process.argv.slice(2));
if (parsed.transport === "http") {
  await runHttp(parsed);
} else {
  await server.connect(new StdioServerTransport());
}

// Kill cached r2 analysis sessions and unload the models sidecar on host
// shutdown — leaked `docker run -i` containers and a parked python sidecar
// (≈1.8 GB VRAM) are exactly the leaks the post-combat audit measured.
process.once("SIGINT", () => void Promise.allSettled([shutdownRadareSessions(), shutdownModels()]));
process.once("SIGTERM", () => void Promise.allSettled([shutdownRadareSessions(), shutdownModels()]));
