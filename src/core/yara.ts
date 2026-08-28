import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

/**
 * YARA-X scanning. Rules arrive either as inline SOURCE text (validated and
 * compiled by yr inside the sandbox) or as a workspace file: a .yar source
 * or a compiled ruleset produced by `yr compile` (loaded via
 * --compiled-rules). Docker runs keep --network none and the read-only
 * sample mount either way.
 */
export const YARA_MAX_RULES_CHARS = 64 * 1024;
export const YARA_MAX_RULES_FILE_BYTES = 32 * 1024 * 1024;
export const YARA_DEFAULT_TIMEOUT_SECONDS = 60;
export const YARA_MAX_TIMEOUT_SECONDS = 600;
const MAX_MATCHES_PER_PATTERN = 20;

export interface YaraScanOptions {
  rules?: string;
  rulesFile?: string;
  compiled?: boolean;
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface YaraScanResult {
  backend: "local" | "docker";
  rulesFile: string;
  resultPath: string;
  command: CommandResult;
  report?: unknown;
}

interface YaraScanReport {
  version?: string;
  matches?: Array<{
    rule?: string;
    file?: string;
    meta?: Record<string, unknown> | null;
    tags?: unknown;
    strings?: Array<{ identifier?: string; offset?: number; match?: string }>;
  }>;
}

function dockerPath(relativePath: string): string {
  return `/workspace/${relativePath.split(path.sep).join("/")}`;
}

export async function resolveLocalYara(): Promise<string | null> {
  const explicit = process.env.MINUSONE_YARA_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("yr", ["--version"]);
  return probe ? "yr" : null;
}

/** Structural bounds on rule source before it is staged anywhere. */
export function validateYaraRules(rules: string): string | null {
  if (rules.trim() === "") return "rules source is empty";
  if (rules.includes("\0")) return "rules source contains NUL bytes";
  if (rules.length > YARA_MAX_RULES_CHARS) {
    return `rules source exceeds ${YARA_MAX_RULES_CHARS} characters`;
  }
  return null;
}

export function rulesDigest(rules: string): string {
  return createHash("sha256").update(rules, "utf8").digest("hex");
}

export type YaraRulesRef =
  | { kind: "inline"; compiled: false; digest: string; inlineRules: string }
  | {
      kind: "file";
      compiled: boolean;
      digest: string;
      rulesPath: string;
      rulesRelative: string;
    };

/**
 * Normalize the two rule inputs into one reference. Exactly one of inline
 * `rules` or a workspace `rulesFile` must be present; `compiled` marks the
 * file as a `yr compile` ruleset. The digest covers rule text (inline) or
 * file bytes (file) and feeds the scan cache key.
 */
export async function resolveYaraRulesRef(
  workspace: Workspace,
  options: YaraScanOptions,
): Promise<YaraRulesRef> {
  const hasInline = options.rules !== undefined;
  const hasFile = options.rulesFile !== undefined;
  if (hasInline === hasFile) {
    throw new Error(
      "rules.scan: provide exactly one of rules (inline YARA source text) or rulesFile (workspace path to a .yar source or a compiled ruleset)",
    );
  }
  const compiled = options.compiled === true;
  if (compiled && hasInline) {
    throw new Error(
      "rules.scan: compiled: true applies to rulesFile only (inline rules are always compiled inside the sandbox)",
    );
  }
  if (hasInline) {
    const rules = options.rules as string;
    const problem = validateYaraRules(rules);
    if (problem !== null) throw new Error(`rules.scan: ${problem}`);
    return { kind: "inline", compiled: false, digest: rulesDigest(rules), inlineRules: rules };
  }
  const absolutePath = await workspace.resolveFile(options.rulesFile as string);
  const fileStat = await stat(absolutePath);
  if (fileStat.size > YARA_MAX_RULES_FILE_BYTES) {
    throw new Error(`rules.scan: rulesFile exceeds ${YARA_MAX_RULES_FILE_BYTES} bytes (${options.rulesFile})`);
  }
  const bytes = await readFile(absolutePath);
  if (!compiled && bytes.includes(0)) {
    throw new Error(
      `rules.scan: source rulesFile contains NUL bytes (${options.rulesFile}) — if this is a compiled ruleset, pass compiled: true`,
    );
  }
  return {
    kind: "file",
    compiled,
    digest: createHash("sha256").update(bytes).digest("hex"),
    rulesPath: absolutePath,
    rulesRelative: workspace.relative(absolutePath),
  };
}

export async function runYaraScan(
  workspace: Workspace,
  userPath: string,
  options: YaraScanOptions,
): Promise<YaraScanResult> {
  const ref = await resolveYaraRulesRef(workspace, options);

  const absolutePath = await workspace.resolveFile(userPath);
  const relativePath = workspace.relative(absolutePath);
  const binary = await inspectBinary(workspace, userPath);
  const tag = ref.digest.slice(0, 12);
  const outDirectory = path.join(workspace.root, ".minusone", "yara", "out");
  const resultFile = path.join(outDirectory, `scan-${binary.sampleId.replace(":", "-")}-${tag}.json`);
  await mkdir(outDirectory, { recursive: true });

  // Inline source is staged into the writable out volume; a rules file is read
  // in place (local) or through the read-only /workspace mount (docker).
  let scanRulesPath: string;
  let containerRulesPath: string;
  if (ref.kind === "inline") {
    scanRulesPath = path.join(outDirectory, `rules-${tag}.yar`);
    const source = ref.inlineRules.endsWith("\n") ? ref.inlineRules : `${ref.inlineRules}\n`;
    await writeFile(scanRulesPath, source, "utf8");
    containerRulesPath = `/out/${path.basename(scanRulesPath)}`;
  } else {
    scanRulesPath = ref.rulesPath;
    containerRulesPath = dockerPath(ref.rulesRelative);
  }
  await rm(resultFile, { force: true });

  const timeoutSeconds = Math.min(YARA_MAX_TIMEOUT_SECONDS, options.timeoutSeconds ?? YARA_DEFAULT_TIMEOUT_SECONDS);
  const flags = [
    "scan",
    ...(ref.compiled ? ["--compiled-rules"] : []),
    "--output-format",
    "json",
    "--print-meta",
    "--print-namespace",
    "--print-tags",
    "--print-strings=100",
    "--timeout",
    String(timeoutSeconds),
    "--threads",
    "1",
    "--max-matches-per-pattern",
    String(MAX_MATCHES_PER_PATTERN),
  ];

  const createResult = async (
    backend: "local" | "docker",
    command: CommandResult,
    stdoutJson?: string,
  ): Promise<YaraScanResult> => {
    const base: YaraScanResult = {
      backend,
      rulesFile: workspace.relative(scanRulesPath),
      resultPath: workspace.relative(resultFile),
      command,
    };
    if (command.exitCode !== 0 || command.timedOut) return base;
    try {
      const raw =
        stdoutJson !== undefined && stdoutJson.trimStart().startsWith("{")
          ? stdoutJson
          : await readFile(resultFile, "utf8");
      return { ...base, report: JSON.parse(raw) as unknown };
    } catch {
      return base;
    }
  };

  const localYara = await resolveLocalYara();
  const image = resolveDockerImage(process.env.MINUSONE_YARA_IMAGE, DEFAULT_IMAGES.yaraX);
  if (localYara === null && image === null) {
    throw new Error("yara-x is disabled: MINUSONE_YARA_IMAGE is explicitly empty and no local yr was found. Unset the variable to restore the pinned default image.");
  }

  if (localYara !== null) {
    const command = await runBoundedCommand(localYara, [...flags, scanRulesPath, absolutePath], {
      cwd: workspace.root,
      timeoutMs: (timeoutSeconds + 60) * 1000,
      maxOutputBytes: 16 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return await createResult("local", command, command.stdout);
  }

  // JSON lands in the writable /out mount while the workspace stays read-only;
  // diagnostics (rule compile errors) stay on stderr for the job detail.
  const command = await runBoundedCommand("docker", [
    "run",
    "--rm",
    "--network",
    "none",
    "--cpus",
    "2",
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
    `yr ${flags.join(" ")} '${containerRulesPath}' '${dockerPath(relativePath)}' > '/out/${path.basename(resultFile)}'`,
  ], {
    cwd: workspace.root,
    timeoutMs: (timeoutSeconds + 120) * 1000,
    maxOutputBytes: 512 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  return await createResult("docker", command);
}

/**
 * Compact model-facing summary of a yr scan JSON report: matched rules with
 * metadata, tags, and bounded pattern offsets.
 */
export function summarizeYaraReport(
  report: unknown,
  maxMatches = 40,
  maxStringsPerMatch = 12,
): { engineVersion: string | null; ruleCount: number; truncated: boolean; matches: unknown[] } {
  if (report === null || typeof report !== "object") {
    return { engineVersion: null, ruleCount: 0, truncated: false, matches: [] };
  }
  const parsed = report as YaraScanReport;
  const rawMatches = Array.isArray(parsed.matches) ? parsed.matches : [];
  const matches = rawMatches.slice(0, maxMatches).map((match) => {
    const strings = Array.isArray(match.strings) ? match.strings : [];
    return {
      rule: typeof match.rule === "string" ? match.rule : "",
      tags: Array.isArray(match.tags) ? match.tags.filter((tag) => typeof tag === "string") : [],
      meta:
        match.meta && typeof match.meta === "object" && !Array.isArray(match.meta)
          ? match.meta
          : {},
      stringCount: strings.length,
      strings: strings.slice(0, maxStringsPerMatch).map((entry) => ({
        identifier: typeof entry.identifier === "string" ? entry.identifier : "",
        offset: typeof entry.offset === "number" ? entry.offset : -1,
        data: typeof entry.match === "string" ? entry.match : "",
      })),
    };
  });
  return {
    engineVersion: typeof parsed.version === "string" ? parsed.version : null,
    ruleCount: rawMatches.length,
    truncated: rawMatches.length > maxMatches,
    matches,
  };
}
