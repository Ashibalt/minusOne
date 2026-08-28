import { access } from "node:fs/promises";
import path from "node:path";
import { probeCommand, runBoundedCommand } from "./command.js";

async function isAccessible(candidate: string): Promise<boolean> {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}

export async function resolveOpenCodeExecutable(): Promise<string | null> {
  const explicit = process.env.MINUSONE_OPENCODE_BIN;
  if (explicit) return await isAccessible(explicit) ? path.resolve(explicit) : null;

  if (process.platform !== "win32") {
    return await probeCommand("opencode") ? "opencode" : null;
  }

  const where = await runBoundedCommand("where.exe", ["opencode"], {
    timeoutMs: 5_000,
    maxOutputBytes: 16 * 1024,
  }).catch(() => null);
  if (!where) return null;

  const shims = where.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const candidates = shims.flatMap((shim) => [
    path.extname(shim).toLowerCase() === ".exe" ? shim : undefined,
    path.join(path.dirname(shim), "node_modules", "opencode-ai", "bin", "opencode.exe"),
  ]).filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    if (await isAccessible(candidate)) return candidate;
  }
  return null;
}
