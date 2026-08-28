import { spawn } from "node:child_process";
import type { CommandResult } from "./types.js";

export interface RunCommandOptions {
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  signal?: AbortSignal;
  /** Extra/overriding environment entries (merged over process.env). */
  env?: Record<string, string>;
  /** UTF-8 text piped to the child's stdin (then closed). */
  stdinData?: string;
}

/**
 * Build a docker `--volume` argument with a normalized host path. Docker
 * Desktop (post-2026-08 builds) rejects backslash host paths when the CLI is
 * spawned without an MSYS layer (node spawn) with a misleading "The system
 * cannot find the file specified" daemon error — forward slashes are accepted
 * everywhere, so every mount goes through here.
 */
export function dockerVolume(hostPath: string, containerPath: string, mode?: "ro" | "rw"): string {
  const host = hostPath.replace(/\\/g, "/");
  return mode === undefined ? `${host}:${containerPath}` : `${host}:${containerPath}:${mode}`;
}

export async function runBoundedCommand(
  command: string,
  args: string[],
  options: RunCommandOptions = {},
): Promise<CommandResult> {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const maxOutputBytes = options.maxOutputBytes ?? 128 * 1024;

  return await new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      stdio: [options.stdinData === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      ...(options.env === undefined ? {} : { env: { ...process.env, ...options.env } }),
    });

    if (options.stdinData !== undefined && child.stdin !== null) {
      child.stdin.on("error", () => {}); // EPIPE when the child exits before reading
      child.stdin.end(options.stdinData, "utf8");
    }

    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let timedOut = false;
    let outputTruncated = false;
    let aborted = false;
    let settled = false;

    const stopForOutputLimit = (): void => {
      outputTruncated = true;
      child.kill();
    };

    const append = (
      current: Buffer<ArrayBufferLike>,
      chunk: Buffer<ArrayBufferLike>,
    ): Buffer<ArrayBufferLike> => {
      const remaining = maxOutputBytes - stdout.length - stderr.length;
      if (remaining <= 0) {
        stopForOutputLimit();
        return current;
      }
      if (chunk.length > remaining) {
        stopForOutputLimit();
        return Buffer.concat([current, chunk.subarray(0, remaining)]);
      }
      return Buffer.concat([current, chunk]);
    };

    child.stdout?.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      stdout = append(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      stderr = append(stderr, chunk);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);

    const onAbort = (): void => {
      aborted = true;
      child.kill();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.once("error", (error) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (settled) return;
      settled = true;
      reject(error);
    });

    child.once("close", (exitCode) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (settled) return;
      settled = true;
      resolve({
        command,
        args,
        exitCode,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        timedOut,
        outputTruncated,
        aborted,
      });
    });
  });
}

export async function probeCommand(command: string, args: string[] = ["--version"]): Promise<CommandResult | null> {
  try {
    return await runBoundedCommand(command, args, { timeoutMs: 5_000, maxOutputBytes: 16 * 1024 });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    throw error;
  }
}
