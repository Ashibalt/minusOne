/**
 * IDA Pro headless backend: `idat -A -c -S<script>` batch runs driven by
 * tools/ida/export.py. The exporter writes a JSON report (metadata,
 * functions, imports/exports, Hex-Rays pseudocode on demand) into the
 * writable run directory; mode and targets travel through MINUSONE_IDA_*
 * env vars so the -S argument stays a plain path with no quoting hazards.
 *
 * IDA is a licensed local tool (owner-installed, never bundled): resolveIda
 * honors MINUSONE_IDAT_PATH / MINUSONE_IDA_HOME and falls back to the
 * standard "IDA Professional 9.4" location. The sample is only ever
 * DISASSEMBLED by IDA — never executed — so this plane is static, not
 * dynamic-gated.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { runBoundedCommand } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export const IDA_DEFAULT_TIMEOUT_SECONDS = 900;
export const IDA_MAX_TIMEOUT_SECONDS = 3600;
export const IDA_MAX_TARGETS = 16;

const STANDARD_INSTALLS = [
  "C:\\Program Files\\IDA Professional 9.4",
  "C:\\Program Files\\IDA Professional 9.3",
  "C:\\Program Files\\IDA Professional 9.2",
  "C:\\Program Files\\IDA Pro 9.4",
  "C:\\Program Files\\IDA Pro 9.3",
  "C:\\Program Files\\IDA Professional",
];

export function resolveIdat(): string | null {
  // Test seam: an explicit disable beats every discovery path.
  if (process.env.MINUSONE_IDA_DISABLED === "1") return null;
  const explicit = process.env.MINUSONE_IDAT_PATH;
  if (explicit !== undefined && explicit !== "" && existsSync(explicit)) return explicit;
  const home = process.env.MINUSONE_IDA_HOME;
  if (home !== undefined && home !== "") {
    const candidate = path.join(home, "idat.exe");
    if (existsSync(candidate)) return candidate;
  }
  for (const install of STANDARD_INSTALLS) {
    const candidate = path.join(install, "idat.exe");
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

const idaModuleDirectory = path.dirname(fileURLToPath(import.meta.url));
const idaPackageRoot = path.resolve(idaModuleDirectory, "../..");

/**
 * The exporter ships with the package (tools/ida/export.py). Resolved from
 * THIS module's location, never process.cwd(): the MCP facade is spawned by
 * clients from arbitrary directories, and a cwd-based lookup made IDA
 * "missing" on every host except the repo root.
 */
export function resolveIdaExporter(): string {
  const explicit = process.env.MINUSONE_IDA_EXPORTER;
  if (explicit !== undefined && explicit !== "") return explicit;
  const packaged = path.join(idaPackageRoot, "tools", "ida", "export.py");
  if (existsSync(packaged)) return packaged;
  // Fallback for unusual layouts (e.g. dist copied elsewhere): cwd.
  return path.join(process.cwd(), "tools", "ida", "export.py");
}

export type IdaExportMode = "overview" | "functions" | "decompile" | "xrefs";

export interface IdaRunOptions {
  mode: IdaExportMode;
  targets?: string[];
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface IdaExportResult {
  backend: "idat";
  idatPath: string;
  runDir: string;
  reportPath: string;
  command: CommandResult;
  report: Record<string, unknown> | null;
}

/**
 * One idat batch: fresh runDir, fresh database (-c), exporter writes the
 * JSON report, then idat exits. The input sample is read-only for IDA.
 */
export async function runIdaExport(
  workspace: Workspace,
  userPath: string,
  options: IdaRunOptions,
): Promise<IdaExportResult> {
  const idatPath = resolveIdat();
  if (idatPath === null) {
    throw new Error(
      "IDA is not available. Set MINUSONE_IDAT_PATH (or MINUSONE_IDA_HOME) to the idat.exe of a licensed IDA installation.",
    );
  }
  const exporter = resolveIdaExporter();
  if (!existsSync(exporter)) {
    throw new Error(`IDA exporter script is missing: ${exporter}`);
  }

  const absolutePath = await workspace.resolveFile(userPath);
  const runDir = path.join(workspace.root, ".minusone", "ida", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });
  const database = path.join(runDir, "db.i64");
  const reportPath = path.join(runDir, "report.json");
  const logPath = path.join(runDir, "idat.log");

  const timeoutSeconds = Math.min(
    IDA_MAX_TIMEOUT_SECONDS,
    Math.max(60, options.timeoutSeconds ?? IDA_DEFAULT_TIMEOUT_SECONDS),
  );

  const targets = (options.targets ?? []).slice(0, IDA_MAX_TARGETS);

  const command = await runBoundedCommand(idatPath, [
    "-A",
    "-c",
    `-o${database}`,
    `-L${logPath}`,
    `-S${exporter}`,
    absolutePath,
  ], {
    cwd: runDir,
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 2 * 1024 * 1024,
    env: {
      MINUSONE_IDA_MODE: options.mode,
      MINUSONE_IDA_OUTPUT: reportPath,
      ...(targets.length === 0 ? {} : { MINUSONE_IDA_TARGETS: JSON.stringify(targets) }),
    },
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  let report: Record<string, unknown> | null = null;
  try {
    report = JSON.parse(await readFile(reportPath, "utf8")) as Record<string, unknown>;
  } catch {
    report = null;
  }

  // The .i64 database is transient for one-shot exports; the JSON report is
  // the durable artifact. Drop the multi-hundred-MB database eagerly.
  await rm(database, { force: true });
  await rm(database + ".id0", { force: true });
  await rm(database + ".id1", { force: true });
  await rm(database + ".id2", { force: true });
  await rm(database + ".nam", { force: true });
  await rm(database + ".til", { force: true });

  return {
    backend: "idat",
    idatPath,
    runDir: workspace.relative(runDir),
    reportPath: workspace.relative(reportPath),
    command,
    report,
  };
}

/** Bounded model-facing summary of an overview/functions export. */
export interface IdaFunctionSummary {
  name: string;
  start: string;
  end: string;
  size: number;
  blocks: number | null;
}

export function summarizeIdaFunctions(
  report: Record<string, unknown> | null,
  filter: string | undefined,
  maxFunctions = 100,
): { total: number; truncated: boolean; functions: IdaFunctionSummary[] } {
  if (report === null) return { total: 0, truncated: false, functions: [] };
  const all = Array.isArray(report.functions) ? (report.functions as Array<Record<string, unknown>>) : [];
  const needle = filter?.toLowerCase();
  const matched = needle === undefined || needle === ""
    ? all
    : all.filter(
        (fn) =>
          (typeof fn.name === "string" && fn.name.toLowerCase().includes(needle)) ||
          (typeof fn.start === "string" && fn.start.toLowerCase().includes(needle)),
      );
  return {
    total: matched.length,
    truncated: matched.length > maxFunctions,
    functions: matched.slice(0, maxFunctions).map((fn) => ({
      name: typeof fn.name === "string" ? fn.name : "",
      start: typeof fn.start === "string" ? fn.start : "",
      end: typeof fn.end === "string" ? fn.end : "",
      size: typeof fn.size === "number" ? fn.size : 0,
      blocks: typeof fn.blocks === "number" ? fn.blocks : null,
    })),
  };
}
