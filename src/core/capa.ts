import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export interface CapaAnalysisOptions {
  signal?: AbortSignal;
}

export interface CapaAnalysisResult {
  backend: "local" | "docker";
  artifactPath: string;
  command: CommandResult;
  report?: unknown;
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalCapa(): Promise<string | null> {
  const explicit = process.env.MINUSONE_CAPA_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("capa", ["--version"]);
  return probe ? "capa" : null;
}

export async function runCapaAnalysis(
  workspace: Workspace,
  userPath: string,
  options: CapaAnalysisOptions = {},
): Promise<CapaAnalysisResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const binary = await inspectBinary(workspace, userPath);
  const artifactDirectory = path.join(workspace.root, ".minusone", "capa", "artifacts");
  const artifactPath = path.join(artifactDirectory, `capa-${binary.sampleId}.json`);
  await mkdir(artifactDirectory, { recursive: true });
  await rm(artifactPath, { force: true });

  const createResult = async (
    backend: "local" | "docker",
    command: CommandResult,
    stdoutJson?: string,
  ): Promise<CapaAnalysisResult> => {
    const base: CapaAnalysisResult = {
      backend,
      artifactPath: workspace.relative(artifactPath),
      command,
    };
    if (command.exitCode !== 0 || command.timedOut) return base;
    try {
      const raw = stdoutJson !== undefined && stdoutJson.trimStart().startsWith("{")
        ? stdoutJson
        : await readFile(artifactPath, "utf8");
      return { ...base, report: JSON.parse(raw) as unknown };
    } catch {
      return base;
    }
  };

  const localCapa = await resolveLocalCapa();
  const image = resolveDockerImage(process.env.MINUSONE_CAPA_IMAGE, DEFAULT_IMAGES.capa);
  if (localCapa === null && image === null) {
    throw new Error("capa is disabled: MINUSONE_CAPA_IMAGE is explicitly empty and no local capa was found. Unset the variable to restore the pinned default image.");
  }

  if (localCapa !== null) {
    const localRules = process.env.MINUSONE_CAPA_RULES;
    const args = ["-j"];
    if (localRules) args.push("-r", localRules);
    args.push(absolutePath);
    const command = await runBoundedCommand(localCapa, args, {
      cwd: workspace.root,
      timeoutMs: 600_000,
      maxOutputBytes: 32 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return await createResult("local", command, command.stdout);
  }

  // capa emits its JSON report on stdout; the shell redirect lands it in the
  // writable /out mount while the sample workspace stays read-only.
  const command = await runBoundedCommand("docker", [
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
    dockerVolume(artifactDirectory, "/out"),
    "--entrypoint",
    "sh",
    image as string,
    "-c",
    `capa -j -r /opt/capa-rules '${dockerPath(relativePath)}' > '/out/capa-${binary.sampleId}.json'`,
  ], {
    cwd: workspace.root,
    timeoutMs: 900_000,
    maxOutputBytes: 512 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return await createResult("docker", command);
}

/**
 * Compact model-facing summary of a capa JSON report: rule names with
 * namespaces and ATT&CK mappings, bounded.
 */
export function summarizeCapaReport(report: unknown, maxRules = 60): { ruleCount: number; truncated: boolean; rules: unknown[] } {
  if (report === null || typeof report !== "object") return { ruleCount: 0, truncated: false, rules: [] };
  const rules = (report as { rules?: Record<string, { meta?: Record<string, unknown> | null }> }).rules ?? {};
  const names = Object.keys(rules);
  const summarized = names.slice(0, maxRules).map((name) => {
    const meta = rules[name]?.meta ?? {};
    const attack = Array.isArray(meta["att&ck"]) ? meta["att&ck"] : [];
    return {
      rule: name,
      namespace: typeof meta.namespace === "string" ? meta.namespace : null,
      attack,
    };
  });
  return { ruleCount: names.length, truncated: names.length > maxRules, rules: summarized };
}
