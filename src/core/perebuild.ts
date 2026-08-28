/**
 * pe.rebuild — reconstruct a loadable PE from a pe-sieve memory dump with
 * LIEF (docker backend `minusone/pe-tools:lief`). The dump is a faithful
 * copy of the in-memory image: virtual section sizes, possibly destroyed
 * import directory. The LIEF script transplants the original sample's
 * imports when the dump lost them, normalizes section raw sizes, and
 * rebuilds the import table — the Scylla workflow without the GUI.
 * Purely static: the container never executes the dump or the original.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rename, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export const PEREBUILD_MAX_DUMP_BYTES = 256 * 1024 * 1024;
export const PEREBUILD_TIMEOUT_SECONDS = 300;
const OUTPUT_SUFFIX = ".rebuilt.exe";

export interface PeRebuildOptions {
  /** Workspace-relative path to the ORIGINAL sample (import donor). */
  originalPath?: string;
  outputPath?: string;
  signal?: AbortSignal;
}

export interface PeRebuildResult {
  backend: "docker";
  rebuiltPath: string;
  bytes: number;
  sha256: string;
  command: CommandResult;
  report: {
    status: string;
    repairs: string[];
    importsRestored: Record<string, number> | null;
    dumpImports: Record<string, number> | null;
    originalImports: Record<string, number> | null;
    sectionAdjustments: Array<{ section: string; change: string }>;
  } | null;
}

async function sha256File(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function rebuildPe(
  workspace: Workspace,
  dumpPath: string,
  options: PeRebuildOptions = {},
): Promise<PeRebuildResult> {
  const absoluteDump = await workspace.resolveFile(dumpPath);
  const dumpStats = await stat(absoluteDump);
  if (dumpStats.size === 0) throw new Error(`dump is empty: ${dumpPath}`);
  if (dumpStats.size > PEREBUILD_MAX_DUMP_BYTES) {
    throw new Error(`dump is ${dumpStats.size} bytes; cap is ${PEREBUILD_MAX_DUMP_BYTES}`);
  }
  const dumpHead = Buffer.alloc(2);
  const dumpHandle = await import("node:fs/promises").then((fs) => fs.open(absoluteDump, "r"));
  try {
    await dumpHandle.read(dumpHead, 0, 2, 0);
  } finally {
    await dumpHandle.close();
  }
  if (dumpHead.toString("latin1") !== "MZ") {
    throw new Error(`dump does not start with the MZ signature: ${dumpPath}`);
  }

  const image = resolveDockerImage(process.env.MINUSONE_PE_TOOLS_IMAGE, DEFAULT_IMAGES.peTools);
  if (image === null) {
    throw new Error(
      "pe.rebuild is disabled: MINUSONE_PE_TOOLS_IMAGE is explicitly empty. Unset the variable to restore the pinned default image.",
    );
  }

  let originalContainerPath: string | null = null;
  if (options.originalPath !== undefined) {
    const absoluteOriginal = await workspace.resolveFile(options.originalPath);
    originalContainerPath = dockerPath(workspace.relative(absoluteOriginal));
  }

  const relativeDump = workspace.relative(absoluteDump);
  const stem = path.basename(relativeDump).replace(/\.[^.]+$/, "");
  const defaultOutput = path.join(".minusone", "exports", `${stem}.rebuilt.exe`);
  const outputUserPath = options.outputPath ?? defaultOutput;
  const absoluteOutput = await workspace.resolveWritablePath(outputUserPath);

  // The container reads the workspace read-only and writes only the rebuilt
  // PE; the output lands in a writable /out mount and is moved into place.
  const outDir = path.dirname(absoluteOutput);
  const containerOutputName = `rebuilt-${createHash("sha256").update(absoluteOutput).digest("hex").slice(0, 8)}${OUTPUT_SUFFIX}`;
  await mkdir(outDir, { recursive: true });

  const args = [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "2",
    "--memory",
    "2g",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    "--volume",
    dockerVolume(outDir, "/out"),
    image,
    dockerPath(relativeDump),
    `/out/${containerOutputName}`,
    ...(originalContainerPath === null ? [] : [originalContainerPath]),
  ];
  const command = await runBoundedCommand("docker", args, {
    cwd: workspace.root,
    timeoutMs: (PEREBUILD_TIMEOUT_SECONDS + 60) * 1000,
    maxOutputBytes: 2 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  const produced = path.join(outDir, containerOutputName);
  let report: PeRebuildResult["report"] = null;
  // The script prints its JSON report on stdout (logs go to stderr).
  const stdoutJson = command.stdout.trim();
  if (command.exitCode === 0 && stdoutJson.startsWith("{")) {
    try {
      const parsed = JSON.parse(stdoutJson) as Record<string, unknown>;
      report = {
        status: typeof parsed.status === "string" ? parsed.status : "unknown",
        repairs: Array.isArray(parsed.repairs) ? (parsed.repairs as string[]) : [],
        importsRestored: (parsed.importsRestored ?? null) as Record<string, number> | null,
        dumpImports: (parsed.dumpImports ?? null) as Record<string, number> | null,
        originalImports: (parsed.originalImports ?? null) as Record<string, number> | null,
        sectionAdjustments: Array.isArray(parsed.sectionAdjustments)
          ? (parsed.sectionAdjustments as Array<{ section: string; change: string }>)
          : [],
      };
    } catch {
      report = null;
    }
  }

  if (command.exitCode !== 0 || command.timedOut) {
    throw new Error(
      `pe.rebuild: LIEF container exited with code ${command.exitCode ?? -1}${command.timedOut ? " (timed out)" : ""}; stderr preview: ${command.stderr.slice(0, 512)}`,
    );
  }

  let producedStats;
  try {
    producedStats = await stat(produced);
  } catch {
    throw new Error(
      `pe.rebuild: the container succeeded but produced no output file at ${workspace.relative(produced)}; stderr preview: ${command.stderr.slice(0, 512)}`,
    );
  }
  if (producedStats.size === 0) throw new Error("pe.rebuild: the rebuilt PE is empty");

  // Move the artifact from /out into its final workspace path.
  await rename(produced, absoluteOutput);

  return {
    backend: "docker",
    rebuiltPath: workspace.relative(absoluteOutput),
    bytes: producedStats.size,
    sha256: await sha256File(absoluteOutput),
    command,
    report,
  };
}
