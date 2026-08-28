import { existsSync } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { inspectBinary } from "./binary.js";
import { runBoundedCommand, dockerVolume } from "./command.js";
import { resolveLocalGhidraHeadless } from "./doctor.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export interface GhidraAnalysisOptions {
  timeoutSeconds?: number;
  maxCpu?: number;
  maxFunctions?: number;
  maxDecompiledChars?: number;
  backend?: "auto" | "local" | "docker";
  /** Entry addresses (e.g. "0x140001450") limiting the export to those functions. */
  addresses?: string[];
  /**
   * References mode: find functions that REFERENCE the given addresses
   * (data or code) and export them with decompiled code — the
   * string→xref→decompile pipeline in one headless run.
   */
  referencesTo?: string[];
  /**
   * Range mode (the megaprocedure slicer): export functions INTERSECTING
   * [rangeStart, rangeEnd] with a short per-function decompile budget and
   * a disassembly fallback for whatever cannot be decompiled — the
   * response to flattened megaprocedures that time out whole.
   */
  rangeStart?: string;
  rangeEnd?: string;
  signal?: AbortSignal;
}

export interface GhidraAnalysisResult {
  backend: "local" | "docker";
  projectName: string;
  projectDirectory: string;
  artifactPath: string;
  command: CommandResult;
  report?: unknown;
}

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(moduleDirectory, "../..");
const scriptsDirectory = path.join(packageRoot, "ghidra_scripts");

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export async function runGhidraAnalysis(
  workspace: Workspace,
  userPath: string,
  options: GhidraAnalysisOptions = {},
): Promise<GhidraAnalysisResult> {
  const timeoutSeconds = Math.min(Math.max(options.timeoutSeconds ?? 300, 30), 3_600);
  const maxCpu = Math.min(Math.max(options.maxCpu ?? 2, 1), 32);
  const maxFunctions = Math.min(Math.max(options.maxFunctions ?? 40, 1), 200);
  // 4000 default (R3-3): a typical main() spends its first ~2500 chars on
  // the Ghidra local-variable declaration block — at the old 2500 cap the
  // preview showed ONLY declarations, and the actual statements were
  // reachable solely through artifact_read.
  const maxDecompiledChars = Math.min(Math.max(options.maxDecompiledChars ?? 4_000, 256), 10_000);
  const addresses = (options.addresses ?? []).slice(0, 64);
  for (const address of addresses) {
    if (!/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(address)) {
      throw new Error(`target address ${JSON.stringify(address)} must be decimal or hexadecimal`);
    }
  }
  const referencesTo = (options.referencesTo ?? []).slice(0, 32);
  for (const target of referencesTo) {
    if (!/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(target)) {
      throw new Error(`reference target ${JSON.stringify(target)} must be decimal or hexadecimal`);
    }
  }
  const rangeMode = options.rangeStart !== undefined || options.rangeEnd !== undefined;
  if (rangeMode) {
    if (options.rangeStart === undefined || options.rangeEnd === undefined) {
      throw new Error("range mode needs both rangeStart and rangeEnd");
    }
    if (!/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(options.rangeStart) || !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(options.rangeEnd)) {
      throw new Error("rangeStart/rangeEnd must be decimal or hexadecimal addresses");
    }
    if (Number(options.rangeEnd) < Number(options.rangeStart)) {
      throw new Error(`rangeEnd (${options.rangeEnd}) is before rangeStart (${options.rangeStart})`);
    }
  }
  const referenceArgs = referencesTo.map((target) => target.toLowerCase());
  const addressArgs = addresses.map((address) => address.toLowerCase());
  const rangeArgs = rangeMode
    ? ["--range", (options.rangeStart as string).toLowerCase(), (options.rangeEnd as string).toLowerCase()]
    : [];
  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const binary = await inspectBinary(workspace, userPath);
  const projectName = `sample-${binary.sampleId}`;
  const requestedBackend = options.backend ?? "auto";
  const localHeadless = await resolveLocalGhidraHeadless();
  if (requestedBackend === "local" && !localHeadless) {
    throw new Error("Local Ghidra headless backend is not configured");
  }
  const useLocalBackend = (requestedBackend === "auto" || requestedBackend === "local") && Boolean(localHeadless);
  const projectDirectory = useLocalBackend
    ? path.join(workspace.root, "minusone-ghidra-projects")
    : path.join(workspace.root, ".minusone", "ghidra");
  const artifactDirectory = path.join(workspace.root, ".minusone", "ghidra", "artifacts");
  const artifactPath = path.join(artifactDirectory, `${projectName}.json`);
  await mkdir(projectDirectory, { recursive: true });
  await mkdir(artifactDirectory, { recursive: true });
  await rm(artifactPath, { force: true });

  const createResult = async (
    backend: "local" | "docker",
    command: CommandResult,
  ): Promise<GhidraAnalysisResult> => {
    const baseResult = {
      backend,
      projectName,
      projectDirectory: workspace.relative(projectDirectory),
      artifactPath: workspace.relative(artifactPath),
      command,
    };
    if (command.exitCode !== 0 || command.timedOut) return baseResult;
    const report = JSON.parse(await readFile(artifactPath, "utf8")) as unknown;
    return { ...baseResult, report };
  };

  if (useLocalBackend && localHeadless) {
    if (process.platform === "win32" && /\.(?:bat|cmd)$/i.test(localHeadless)) {
      throw new Error("Direct .bat execution is intentionally disabled; use a safe executable wrapper or the Docker backend.");
    }
    const scriptArgs = [
      artifactPath,
      String(maxFunctions),
      String(maxDecompiledChars),
      ...(rangeArgs.length > 0 ? rangeArgs : []),
      ...(referenceArgs.length > 0 ? ["--references", ...referenceArgs] : []),
      ...addressArgs,
    ];
    const projectMarker = path.join(projectDirectory, `${projectName}.gpr`);
    // Project reuse (A3): the per-sample project (sample-<sampleId>) already
    // holds the analyzed program — -process reopens it WITHOUT re-import and
    // re-analysis. The import path runs once per sample.
    const args = existsSync(projectMarker)
      ? [
          projectDirectory,
          projectName,
          "-process",
          path.basename(absolutePath),
          "-noanalysis",
          "-scriptPath",
          scriptsDirectory,
          "-postScript",
          "ExportAnalysis.java",
          ...scriptArgs,
        ]
      : [
          projectDirectory,
          projectName,
          "-import",
          absolutePath,
          "-overwrite",
          "-analysisTimeoutPerFile",
          String(timeoutSeconds),
          "-max-cpu",
          String(maxCpu),
          "-scriptPath",
          scriptsDirectory,
          "-postScript",
          "ExportAnalysis.java",
          ...scriptArgs,
        ];
    const command = await runBoundedCommand(localHeadless, args, {
      cwd: workspace.root,
      timeoutMs: (timeoutSeconds + 60) * 1000,
      maxOutputBytes: 2 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (command.exitCode !== 0 && existsSync(projectMarker)) {
      // A corrupt half-written project would wedge every later call: drop it
      // so the next attempt re-imports from scratch.
      await rm(path.join(projectDirectory, `${projectName}.gpr`), { force: true });
      await rm(path.join(projectDirectory, `${projectName}.rep`), { recursive: true, force: true });
    }
    return await createResult("local", command);
  }

  const image = resolveDockerImage(process.env.MINUSONE_GHIDRA_IMAGE, DEFAULT_IMAGES.ghidra);
  if (image === null) {
    throw new Error("Ghidra is disabled: MINUSONE_GHIDRA_IMAGE is explicitly empty and no local headless backend was found. Unset the variable to restore the pinned default image.");
  }

  // The sample may live in a trusted external root: docker needs an explicit
  // read-only mount for it (the workspace mount alone doesn't cover it).
  const extraSampleMounts: string[] = [];
  if (!isWithin(workspace.root, absolutePath)) {
    extraSampleMounts.push("--volume", dockerVolume(path.dirname(absolutePath), "/external-sample", "ro"));
  }
  const dockerSamplePath = isWithin(workspace.root, absolutePath)
    ? dockerPath(relativePath)
    : `/external-sample/${path.basename(absolutePath)}`;

  const projectMarker = path.join(projectDirectory, `${projectName}.gpr`);
  const scriptArgs = [
    `/projects/artifacts/${projectName}.json`,
    String(maxFunctions),
    String(maxDecompiledChars),
    ...(rangeArgs.length > 0 ? rangeArgs : []),
    ...(referenceArgs.length > 0 ? ["--references", ...referenceArgs] : []),
    ...addressArgs,
  ];
  // Docker path mirrors the local one (A3): -process reuses the existing
  // per-sample project; -import runs once per sample.
  const ghidraArgs = existsSync(projectMarker)
    ? [
        "/projects",
        projectName,
        "-process",
        path.basename(dockerSamplePath),
        "-noanalysis",
        "-scriptPath",
        "/scripts",
        "-postScript",
        "ExportAnalysis.java",
        ...scriptArgs,
      ]
    : [
        "/projects",
        projectName,
        "-import",
        dockerSamplePath,
        "-overwrite",
        "-analysisTimeoutPerFile",
        String(timeoutSeconds),
        "-max-cpu",
        String(maxCpu),
        "-scriptPath",
        "/scripts",
        "-postScript",
        "ExportAnalysis.java",
        ...scriptArgs,
      ];
  const args = [
    "run",
    "--rm",
    "--network",
    "none",
    "--hostname",
    "minusone-ghidra",
    "--add-host",
    "minusone-ghidra:127.0.0.1",
    "--cpus",
    String(maxCpu),
    "--memory",
    "4g",
    "--env",
    "MODE=headless",
    "--volume",
    dockerVolume(workspace.root, "/workspace", "ro"),
    ...extraSampleMounts,
    "--volume",
    dockerVolume(projectDirectory, "/projects"),
    "--volume",
    dockerVolume(scriptsDirectory, "/scripts", "ro"),
    image,
    ...ghidraArgs,
  ];
  const command = await runBoundedCommand("docker", args, {
    cwd: workspace.root,
    timeoutMs: (timeoutSeconds + 300) * 1_000,
    maxOutputBytes: 2 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (command.exitCode !== 0 && existsSync(projectMarker)) {
    await rm(path.join(projectDirectory, `${projectName}.gpr`), { force: true });
    await rm(path.join(projectDirectory, `${projectName}.rep`), { recursive: true, force: true });
  }
  return await createResult("docker", command);
}
