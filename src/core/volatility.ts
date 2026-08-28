/**
 * Volatility 3 memory-image analysis: full RAM captures (raw/dd/lime/Windows
 * crash dumps) examined with read-only DFIR plugins. This is the postmortem
 * plane for whole-system images — the capture is never executed, the sandbox
 * runs with --network none, and kernel symbols come from a host-side cache
 * (tools/volatility-symbols) so scans never reach the internet.
 */
import { stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * Curated whitelist: read-only, offline, useful across XP-era and modern
 * Windows captures. Deliberately excludes plugins that write output files or
 * need live state — this table is for evidence extraction, not interaction.
 */
export const VOLATILITY_PLUGINS = [
  "windows.info",
  "windows.pslist",
  "windows.pstree",
  "windows.cmdline",
  "windows.dlllist",
  "windows.modules",
  "windows.netscan",
  "windows.envars",
  "windows.privileges",
  "windows.registry.hivelist",
  "windows.callbacks",
  "windows.svcscan",
  "windows.filescan",
  "windows.malfind",
] as const;
export type VolatilityPlugin = (typeof VOLATILITY_PLUGINS)[number];

export const VOLATILITY_DEFAULT_TIMEOUT_SECONDS = 900;
export const VOLATILITY_MAX_TIMEOUT_SECONDS = 1800;
export const VOLATILITY_MIN_TIMEOUT_SECONDS = 30;
export const VOLATILITY_DEFAULT_MAX_ROWS = 200;
export const VOLATILITY_MAX_ROWS_HARD_CAP = 2000;
export const VOLATILITY_MAX_PLUGINS_PER_RUN = 8;
/** Tree plugins (pstree) are flattened before capping. */
const VOLATILITY_MAX_FLATTENED_ROWS = 20_000;

export interface VolatilityPluginResult {
  plugin: string;
  ok: boolean;
  columns: string[];
  rowCountTotal: number;
  rows: Array<Record<string, unknown>>;
  truncated: boolean;
  timedOut: boolean;
  seconds: number;
  error?: string;
}

export interface VolatilityRunOptions {
  plugins?: readonly string[];
  maxRows?: number;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface VolatilityRunResult {
  backend: "local" | "docker";
  backendPath: string;
  plugins: VolatilityPluginResult[];
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalVolatility(): Promise<string | null> {
  const explicit = process.env.MINUSONE_VOLATILITY_BIN;
  if (explicit) return explicit;
  // vol has no --version flag; the help banner identifies the framework.
  const probe = await probeCommand("vol", ["-h"]);
  if (probe && /volatility/i.test(`${probe.stdout}\n${probe.stderr}`)) return "vol";
  return null;
}

/**
 * Kernel symbol cache probed in priority order. tools/volatility-symbols is
 * committed (the XP test-corpus kernel ISF), .minusone/datasets holds larger
 * packs fetched by scripts/fetch-volatility-data.mjs, and the env override
 * wins outright when set.
 */
export async function resolveVolatilitySymbolsDir(workspace: Workspace): Promise<string | null> {
  const candidates = [
    process.env.MINUSONE_VOLATILITY_SYMBOLS?.trim() || null,
    path.join(workspace.root, "tools", "volatility-symbols"),
    path.join(workspace.root, ".minusone", "datasets", "volatility-symbols"),
  ].filter((candidate): candidate is string => candidate !== null);
  for (const candidate of candidates) {
    if (await stat(candidate).then(() => true, () => false)) return candidate;
  }
  return null;
}

export function validateVolatilityPlugins(requested: readonly string[] | undefined): VolatilityPlugin[] {
  const selection = requested === undefined || requested.length === 0 ? ["windows.info"] : [...requested];
  if (selection.length > VOLATILITY_MAX_PLUGINS_PER_RUN) {
    throw new Error(`at most ${VOLATILITY_MAX_PLUGINS_PER_RUN} plugins per run; got ${selection.length}`);
  }
  const unknown = selection.filter((name) => !(VOLATILITY_PLUGINS as readonly string[]).includes(name));
  if (unknown.length > 0) {
    throw new Error(`unknown volatility plugin(s): ${unknown.join(", ")}. Whitelist: ${VOLATILITY_PLUGINS.join(", ")}`);
  }
  // Dedupe, keeping whitelist order so cache keys and runs are stable.
  return VOLATILITY_PLUGINS.filter((name) => selection.includes(name));
}

function normalizeCell(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  const rendered = JSON.stringify(value);
  return rendered.length <= 512 ? rendered : `${rendered.slice(0, 512)}…`;
}

/**
 * vol3's JSON renderer emits a top-level array of row objects (column names
 * as keys; tree plugins nest children under "__children"). Multi-plugin
 * invocations wrap tables by plugin name — accept both shapes. Children are
 * flattened breadth-first: pstree keeps parent links via the PPID column.
 */
export function summarizeVolatilityTable(
  table: unknown,
  plugin: string,
  maxRows: number,
): { columns: string[]; rowCountTotal: number; rows: Array<Record<string, unknown>>; truncated: boolean } {
  const direct = Array.isArray(table)
    ? table
    : table !== null && typeof table === "object" && Array.isArray((table as Record<string, unknown>)[plugin])
      ? ((table as Record<string, unknown>)[plugin] as unknown[])
      : [];

  const flat: Array<Record<string, unknown>> = [];
  const queue: unknown[] = [...direct];
  while (queue.length > 0 && flat.length < VOLATILITY_MAX_FLATTENED_ROWS) {
    const entry = queue.shift();
    if (entry === null || typeof entry !== "object") continue;
    const row = entry as Record<string, unknown>;
    const children = Array.isArray(row.__children) ? row.__children : [];
    const clean: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      if (key === "__children") continue;
      clean[key] = normalizeCell(value);
    }
    flat.push(clean);
    queue.push(...children);
  }

  const columns: string[] = [];
  for (const row of flat) {
    for (const key of Object.keys(row)) {
      if (!columns.includes(key)) columns.push(key);
    }
  }
  return {
    columns,
    rowCountTotal: flat.length,
    rows: flat.slice(0, maxRows),
    truncated: flat.length > maxRows,
  };
}

function parseVolatilityStdout(stdout: string, plugin: string): unknown | null {
  const trimmed = stdout.trim();
  if (trimmed === "" || !(trimmed.startsWith("[") || trimmed.startsWith("{"))) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) return parsed;
    if (parsed !== null && typeof parsed === "object" && plugin in (parsed as Record<string, unknown>)) {
      return (parsed as Record<string, unknown>)[plugin];
    }
    return null;
  } catch {
    return null;
  }
}

function lastUsefulLine(text: string): string {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line !== "");
  return lines[lines.length - 1] ?? "";
}

async function runOnePlugin(
  backend: "local" | "docker",
  backendPath: string,
  workspace: Workspace,
  relativePath: string,
  plugin: VolatilityPlugin,
  perPluginSeconds: number,
  symbolsDir: string | null,
  signal: AbortSignal | undefined,
): Promise<VolatilityPluginResult> {
  const target = backend === "docker" ? dockerPath(relativePath) : path.join(workspace.root, relativePath);
  // vol's argparse binds -f to the global group: it must precede the plugin.
  const volArgs = [
    "-q", "-r", "json",
    ...(symbolsDir !== null && backend === "docker" ? ["-s", "/symbols"] : []),
    ...(symbolsDir !== null && backend === "local" ? ["-s", symbolsDir] : []),
    "-f", target,
    plugin,
  ];
  const args = backend === "docker"
    ? [
        "run", "--rm",
        "--network", "none",
        "--cpus", "2",
        "--memory", "4g",
        "--volume", dockerVolume(workspace.root, "/workspace", "ro"),
        ...(symbolsDir !== null ? ["--volume", dockerVolume(symbolsDir, "/symbols", "ro")] : []),
        "--entrypoint", "vol",
        backendPath,
        ...volArgs,
      ]
    : volArgs;

  const startedAt = Date.now();
  let command: CommandResult;
  try {
    command = await runBoundedCommand(backend === "docker" ? "docker" : backendPath, args, {
      cwd: workspace.root,
      timeoutMs: (perPluginSeconds + 60) * 1000,
      maxOutputBytes: 64 * 1024 * 1024,
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (error) {
    return {
      plugin,
      ok: false,
      columns: [],
      rowCountTotal: 0,
      rows: [],
      truncated: false,
      timedOut: false,
      seconds: (Date.now() - startedAt) / 1000,
      error: `${backend} backend failed to start: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  const seconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));

  if (command.exitCode !== 0 || command.timedOut) {
    return {
      plugin,
      ok: false,
      columns: [],
      rowCountTotal: 0,
      rows: [],
      truncated: false,
      timedOut: command.timedOut,
      seconds,
      error: command.timedOut
        ? `plugin exceeded its ${perPluginSeconds}s budget`
        : `vol exited with code ${command.exitCode}; ${lastUsefulLine(command.stderr).slice(0, 512)}`,
    };
  }

  const table = parseVolatilityStdout(command.stdout, plugin);
  if (table === null) {
    return {
      plugin,
      ok: false,
      columns: [],
      rowCountTotal: 0,
      rows: [],
      truncated: false,
      timedOut: false,
      seconds,
      error: `vol produced no JSON table for ${plugin}; ${lastUsefulLine(command.stderr).slice(0, 512)}`,
    };
  }
  return { plugin, ok: true, timedOut: false, seconds, ...summarizeVolatilityTable(table, plugin, VOLATILITY_MAX_ROWS_HARD_CAP) };
}

export async function runVolatilityPlugins(
  workspace: Workspace,
  userPath: string,
  options: VolatilityRunOptions = {},
): Promise<VolatilityRunResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const plugins = validateVolatilityPlugins(options.plugins);
  const maxRows = Math.min(Math.max(options.maxRows ?? VOLATILITY_DEFAULT_MAX_ROWS, 1), VOLATILITY_MAX_ROWS_HARD_CAP);
  const timeoutSeconds = Math.min(
    Math.max(options.timeoutSeconds ?? VOLATILITY_DEFAULT_TIMEOUT_SECONDS, VOLATILITY_MIN_TIMEOUT_SECONDS),
    VOLATILITY_MAX_TIMEOUT_SECONDS,
  );
  const perPluginSeconds = Math.max(60, Math.floor(timeoutSeconds / plugins.length));

  const localVolatility = await resolveLocalVolatility();
  const image = resolveDockerImage(process.env.MINUSONE_VOLATILITY_IMAGE, DEFAULT_IMAGES.volatility3);
  if (localVolatility === null && image === null) {
    throw new Error("volatility3 is disabled: MINUSONE_VOLATILITY_IMAGE is explicitly empty and no local vol was found. Unset the variable to restore the pinned default image.");
  }
  const backend: "local" | "docker" = localVolatility !== null ? "local" : "docker";
  const backendPath = (localVolatility ?? image) as string;
  const symbolsDir = await resolveVolatilitySymbolsDir(workspace);

  const results: VolatilityPluginResult[] = [];
  for (const plugin of plugins) {
    if (options.signal?.aborted) break;
    const result = await runOnePlugin(backend, backendPath, workspace, relativePath, plugin, perPluginSeconds, symbolsDir, options.signal);
    results.push({ ...result, rows: result.rows.slice(0, maxRows), truncated: result.truncated || result.rowCountTotal > maxRows });
  }
  return { backend, backendPath, plugins: results };
}
