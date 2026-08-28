/**
 * unpack.static — UPX static decompression fast-path. `upx -d` is a pure
 * file transformation (the sample is never executed), so it is NOT
 * dynamic-gated: a UPX-packed sample unwraps in seconds without a
 * pe-sieve run. Local upx when present; otherwise the pe-tools docker
 * image (upx-ucl from Debian). Output lands in the writable /out mount;
 * the sample is read read-only.
 *
 * upx -d refuses non-UPX files (exit != 0), which the caller treats as
 * "not UPX-packed, use the dynamic path" — the operation is a probe and
 * an unpacker in one.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { inspectBinary } from "./binary.js";
import { probeCommand, runBoundedCommand, dockerVolume } from "./command.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export const UNPACK_STATIC_DEFAULT_TIMEOUT_SECONDS = 120;
export const UNPACK_STATIC_MAX_TIMEOUT_SECONDS = 600;

export interface UnpackStaticOptions {
  timeoutSeconds?: number;
  signal?: AbortSignal;
}

export interface UnpackStaticResult {
  backend: "local" | "docker";
  packed: boolean;
  outputPath: string | null;
  outputSha256: string | null;
  outputBytes: number | null;
  /** Packed → unpacked size delta from the upx banner (informational). */
  ratio: string | null;
  command: CommandResult;
  notes: string[];
}

async function sha256File(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

/** Parse the "Unpacked 1 file: ... -> ..." ratio line from upx output. */
function parseRatio(stdout: string): string | null {
  const match = /\]\s*([^\r\n]*->[^\r\n]*)/.exec(stdout);
  if (match !== null && match[1] !== undefined) return match[1].trim();
  const line = stdout.split(/\r?\n/).find((entry) => entry.includes("->"));
  return line?.trim() ?? null;
}

export async function resolveLocalUpx(): Promise<string | null> {
  const explicit = process.env.MINUSONE_UPX_BIN;
  if (explicit) return explicit;
  const probe = await probeCommand("upx", ["--version"]);
  return probe ? "upx" : null;
}

export async function unpackStatic(
  workspace: Workspace,
  userPath: string,
  options: UnpackStaticOptions = {},
): Promise<UnpackStaticResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const binary = await inspectBinary(workspace, userPath);
  const timeoutSeconds = Math.min(
    UNPACK_STATIC_MAX_TIMEOUT_SECONDS,
    Math.max(15, options.timeoutSeconds ?? UNPACK_STATIC_DEFAULT_TIMEOUT_SECONDS),
  );

  const outDir = path.join(workspace.root, ".minusone", "unpack-static", binary.sampleId);
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  const baseName = path.basename(absolutePath, path.extname(absolutePath));
  const outputName = `${baseName}-unpacked${path.extname(absolutePath)}`;
  const outputPath = path.join(outDir, outputName);
  const notes: string[] = [];

  const localUpx = await resolveLocalUpx();
  const image = resolveDockerImage(process.env.MINUSONE_PE_TOOLS_IMAGE, DEFAULT_IMAGES.peTools);
  if (localUpx === null && image === null) {
    throw new Error("static unpack is disabled: MINUSONE_PE_TOOLS_IMAGE is explicitly empty and no local upx was found. Unset the variable to restore the pinned default image.");
  }

  let command: CommandResult;
  let backend: "local" | "docker";
  if (localUpx !== null) {
    backend = "local";
    command = await runBoundedCommand(localUpx, ["-d", "-o", outputPath, absolutePath], {
      cwd: workspace.root,
      timeoutMs: timeoutSeconds * 1000,
      maxOutputBytes: 2 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } else {
    backend = "docker";
    // Sample read-only at /workspace; output into the writable /out mount.
    // The image ENTRYPOINT is pe-rebuild.py — override it to reach upx.
    const dockerRelative = workspace.relative(absolutePath).split(path.sep).join("/");
    command = await runBoundedCommand("docker", [
      "run",
      "--rm",
      "--network",
      "none",
      "--cpus",
      "1",
      "--memory",
      "512m",
      "--volume",
      dockerVolume(workspace.root, "/workspace", "ro"),
      "--volume",
      `${outDir}:/out`,
      "--entrypoint",
      "upx",
      image as string,
      "-d",
      "-o",
      `/out/${outputName}`,
      `/workspace/${dockerRelative}`,
    ], {
      cwd: workspace.root,
      timeoutMs: (timeoutSeconds + 60) * 1000,
      maxOutputBytes: 2 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  }

  const outputStats = await stat(outputPath).catch(() => null);
  if (command.exitCode !== 0 || outputStats === null) {
    // The common case: upx refuses the file (not UPX-packed, or a modified
    // UPX whose header it rejects). Surface upx's own words, not a guess.
    const stdoutTail = command.stdout.split(/\r?\n/).filter((line) => line.trim() !== "").slice(-3).join(" | ");
    notes.push(stdoutTail !== "" ? `upx says: ${stdoutTail}` : "upx produced no output");
    if (command.timedOut) notes.push("upx timed out");
    return {
      backend,
      packed: false,
      outputPath: null,
      outputSha256: null,
      outputBytes: null,
      ratio: null,
      command,
      notes,
    };
  }

  return {
    backend,
    packed: true,
    outputPath: workspace.relative(outputPath),
    outputSha256: await sha256File(outputPath),
    outputBytes: outputStats.size,
    ratio: parseRatio(command.stdout),
    command,
    notes,
  };
}

/** For tests: the banner parser. */
export { parseRatio as parseUpxRatio };
