import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * Detect It Easy: static packer/compiler/linker/protector identification
 * plus per-section entropy. Two diec invocations inside one container (the
 * -e flag replaces the detects array with entropy records, so they cannot
 * be combined); results merge into one artifact.
 */
export const DIE_MAX_ENTROPY_RECORDS = 64;
export const DIE_MAX_DETECTS = 32;

export interface DieDetectionOptions {
  deep?: boolean;
  signal?: AbortSignal;
}

export interface DieDetectionResult {
  backend: "local" | "docker";
  resultPath: string;
  command: CommandResult;
  report?: { detections?: unknown; entropy?: unknown };
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalDie(): Promise<string | null> {
  const explicit = process.env.MINUSONE_DIE_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("diec", ["--version"]);
  return probe ? "diec" : null;
}

export async function runDieDetection(
  workspace: Workspace,
  userPath: string,
  options: DieDetectionOptions = {},
): Promise<DieDetectionResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const binary = await inspectBinary(workspace, userPath);
  const outDirectory = path.join(workspace.root, ".minusone", "die", "out");
  const detectFile = path.join(outDirectory, `die-${binary.sampleId}.json`);
  const entropyFile = path.join(outDirectory, `die-entropy-${binary.sampleId}.json`);
  await mkdir(outDirectory, { recursive: true });
  await rm(detectFile, { force: true });
  await rm(entropyFile, { force: true });

  const base = ["--"];
  if (options.deep === true) base.unshift("-d");

  const createResult = async (
    backend: "local" | "docker",
    command: CommandResult,
    detectJson?: string,
    entropyJson?: string,
  ): Promise<DieDetectionResult> => {
    const baseResult: DieDetectionResult = {
      backend,
      resultPath: workspace.relative(detectFile),
      command,
    };
    if (command.exitCode !== 0 || command.timedOut) return baseResult;
    const parse = async (source: string | undefined, fallbackPath: string): Promise<unknown | undefined> => {
      try {
        const raw = source !== undefined && source.trimStart().startsWith("{") ? source : await readFile(fallbackPath, "utf8");
        return JSON.parse(raw) as unknown;
      } catch {
        return undefined;
      }
    };
    const detections = await parse(detectJson, detectFile);
    const entropy = await parse(entropyJson, entropyFile);
    if (detections === undefined) return baseResult;
    return { ...baseResult, report: { detections, entropy } };
  };

  const localDie = await resolveLocalDie();
  const image = resolveDockerImage(process.env.MINUSONE_DIE_IMAGE, DEFAULT_IMAGES.die);
  if (localDie === null && image === null) {
    throw new Error("detect-it-easy is disabled: MINUSONE_DIE_IMAGE is explicitly empty and no local diec was found. Unset the variable to restore the pinned default image.");
  }

  if (localDie !== null) {
    const detect = await runBoundedCommand(localDie, ["-j", ...base, absolutePath], {
      cwd: workspace.root,
      timeoutMs: 120_000,
      maxOutputBytes: 8 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (detect.exitCode !== 0 || detect.timedOut) return await createResult("local", detect);
    const entropy = await runBoundedCommand(localDie, ["-j", "-e", ...base, absolutePath], {
      cwd: workspace.root,
      timeoutMs: 120_000,
      maxOutputBytes: 8 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return await createResult("local", detect, detect.stdout, entropy.stdout);
  }

  const command = await runBoundedCommand("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "1",
    "--memory",
    "1g",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    "--volume",
    dockerVolume(outDirectory, "/out"),
    "--entrypoint",
    "sh",
    image as string,
    "-c",
    `diec -j ${options.deep === true ? "-d " : ""}'${dockerPath(relativePath)}' > '/out/${path.basename(detectFile)}' `
      + `&& diec -j -e ${options.deep === true ? "-d " : ""}'${dockerPath(relativePath)}' > '/out/${path.basename(entropyFile)}'`,
  ], {
    cwd: workspace.root,
    timeoutMs: 180_000,
    maxOutputBytes: 256 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return await createResult("docker", command);
}

interface DieDetectReport {
  detects?: Array<{
    filetype?: unknown;
    parentfilepart?: unknown;
    offset?: unknown;
    values?: Array<{ type?: unknown; name?: unknown; string?: unknown; version?: unknown; info?: unknown }>;
  }>;
}

interface DieEntropyReport {
  status?: unknown;
  total?: unknown;
  records?: Array<{ name?: unknown; entropy?: unknown; offset?: unknown; size?: unknown; status?: unknown }>;
}

/**
 * Compact model-facing summary: identified filetypes with detection values,
 * overall packed verdict, and bounded per-section entropy.
 */
export function summarizeDieReport(
  report: { detections?: unknown; entropy?: unknown } | undefined,
  maxDetects = DIE_MAX_DETECTS,
  maxRecords = DIE_MAX_ENTROPY_RECORDS,
): {
  filetypes: string[];
  detectionCount: number;
  truncated: boolean;
  detections: unknown[];
  entropyAvailable: boolean;
  packed: boolean;
  entropyStatus: string | null;
  totalEntropy: number | null;
  entropyRecords: unknown[];
} {
  const parsed = (report?.detections ?? {}) as DieDetectReport;
  const entropy = (report?.entropy ?? {}) as DieEntropyReport;
  const detects = Array.isArray(parsed.detects) ? parsed.detects : [];
  const records = Array.isArray(entropy.records) ? entropy.records : [];

  const detections = detects.slice(0, maxDetects).map((detect) => ({
    filetype: typeof detect.filetype === "string" ? detect.filetype : "",
    filepart: typeof detect.parentfilepart === "string" ? detect.parentfilepart : "",
    offset: typeof detect.offset === "string" ? detect.offset : "0",
    values: (Array.isArray(detect.values) ? detect.values : []).map((value) => ({
      type: typeof value.type === "string" ? value.type : "",
      name: typeof value.name === "string" ? value.name : "",
      string: typeof value.string === "string" ? value.string : "",
      version: typeof value.version === "string" ? value.version : "",
      info: typeof value.info === "string" ? value.info : "",
    })),
  }));

  const entropyAvailable = typeof entropy.status === "string";
  return {
    filetypes: [...new Set(detections.map((detect) => detect.filetype).filter((type) => type !== ""))],
    detectionCount: detects.length,
    truncated: detects.length > maxDetects || records.length > maxRecords,
    detections,
    entropyAvailable,
    packed: entropy.status === "packed",
    entropyStatus: entropyAvailable ? (entropy.status as string) : null,
    totalEntropy: typeof entropy.total === "number" ? entropy.total : null,
    entropyRecords: records.slice(0, maxRecords).map((record) => ({
      name: typeof record.name === "string" ? record.name : "",
      entropy: typeof record.entropy === "number" ? record.entropy : null,
      offset: typeof record.offset === "number" ? record.offset : null,
      size: typeof record.size === "number" ? record.size : null,
      status: typeof record.status === "string" ? record.status : "",
    })),
  };
}
