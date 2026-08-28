/**
 * D810-ng deobfuscation backend (IDA Pro + Hex-Rays microcode rewriting).
 * D810 modifies the microcode DURING decompilation, so MBA expressions and
 * flattened control flow come out readable — the one tool class that
 * attacks obfuscation directly instead of timing out on it.
 *
 * Driver model: the headless activation recipe lives in
 * tools/ida/d810_smoke.py (idat -A -c -S). Rule classes register via
 * __init_subclass__ at module import; nothing imports them in headless
 * mode, so the driver scans every rule package the way d810-ng's own test
 * conftest does before touching D810State. The plugin must be installed
 * once by the owner: copy the d810-ng repo into
 * %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng (see README).
 */
import { copyFile, mkdir, readFile, rm, stat } from "node:fs/promises";
import path from "node:path";
import { runBoundedCommand } from "./command.js";
import { resolveIdat, resolveIdaExporter } from "./ida.js";
import type { CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export interface D810Options {
  /** Function name or hex address to decompile (default: first non-library function). */
  target?: string;
  /** D810 project profile file name (default: default_unflattening_ollvm). */
  profile?: string;
  /**
   * Workspace-relative path to a USER D810 project profile (.json) — staged
   * into the IDA user cfg dir (cfg/d810, d810's documented user-rules
   * mechanism) with a minusone- prefix and selected for this run. The way to
   * bring custom MBA rules when the bundled profiles don't collapse your
   * sample's expressions.
   */
  profilePath?: string;
  timeoutSeconds?: number;
  /** Job-cancellation signal (kills the idat process on abort). */
  signal?: AbortSignal;
}

export interface D810Result {
  idat: string;
  target: string;
  d810Available: boolean;
  baseline: string | null;
  deobfuscated: string | null;
  error: string | null;
  traceback: string | null;
  /** The profile selected for the run (stem name as passed to idat). */
  profile: string;
  /** Absolute path the user profile was staged to (profilePath runs only). */
  stagedProfile: string | null;
  command: CommandResult;
}

export const D810_DEFAULT_TIMEOUT_SECONDS = 600;
export const D810_DEFAULT_PROFILE = "default_unflattening_ollvm";

/** Resolve the installed d810-ng plugin's src directory (owner installs it once). */
export function resolveD810Path(): string | null {
  const explicit = process.env.MINUSONE_D810_PATH;
  if (explicit !== undefined && explicit !== "") return explicit;
  const appData = process.env.APPDATA;
  if (appData !== undefined && appData !== "") {
    const candidate = path.join(appData, "Hex-Rays", "IDA Pro", "plugins", "d810-ng", "src");
    return candidate;
  }
  return null;
}

export async function isD810Available(): Promise<boolean> {
  const d810Path = resolveD810Path();
  if (d810Path === null) return false;
  try {
    await stat(path.join(d810Path, "d810", "manager.py"));
    return true;
  } catch {
    return false;
  }
}

export async function runD810Deobfuscation(
  workspace: Workspace,
  userPath: string,
  options: D810Options = {},
): Promise<D810Result> {
  const idat = resolveIdat();
  if (idat === null) {
    throw new Error("no IDA backend found: set MINUSONE_IDAT_PATH or install IDA Professional (licensed)");
  }
  const d810Path = resolveD810Path();
  if (d810Path === null) {
    throw new Error("D810-ng plugin not installed: copy the d810-ng repository to %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng (or set MINUSONE_D810_PATH)");
  }
  const exporterRoot = path.dirname(resolveIdaExporter());
  const smokeScript = path.join(exporterRoot, "d810_smoke.py");
  try {
    await stat(smokeScript);
  } catch {
    throw new Error(`d810_smoke.py not found at ${smokeScript}`);
  }

  const absolutePath = await workspace.resolveFile(userPath);
  const runDir = path.join(workspace.root, ".minusone", "run", `d810-${Date.now().toString(36)}`);
  await mkdir(runDir, { recursive: true });
  const reportPath = path.join(runDir, "d810-report.json");
  const idbPath = path.join(runDir, "target.idb");
  const timeoutSeconds = Math.min(Math.max(options.timeoutSeconds ?? D810_DEFAULT_TIMEOUT_SECONDS, 60), 1800);

  // F6: a user-supplied profile is staged into d810's user cfg dir (its
  // documented override mechanism) with a minusone- prefix — never clobbering
  // the owner's own files — and selected by stem name for this run.
  let profileName = options.profile ?? D810_DEFAULT_PROFILE;
  let stagedProfile: string | null = null;
  if (options.profilePath !== undefined) {
    const profileAbsolute = await workspace.resolveFile(options.profilePath);
    const baseName = path.basename(profileAbsolute);
    if (!baseName.toLowerCase().endsWith(".json")) {
      throw new Error(`profilePath must point to a D810 project .json (got ${baseName})`);
    }
    const appData = process.env.APPDATA;
    if (appData === undefined || appData === "") {
      throw new Error("APPDATA is not set — cannot stage the user D810 profile into cfg/d810");
    }
    const cfgDir = path.join(appData, "Hex-Rays", "IDA Pro", "cfg", "d810");
    await mkdir(cfgDir, { recursive: true });
    const stagedName = baseName.startsWith("minusone-") ? baseName : `minusone-${baseName}`;
    stagedProfile = path.join(cfgDir, stagedName);
    await copyFile(profileAbsolute, stagedProfile);
    profileName = stagedName.replace(/\.json$/i, "");
  }

  const env: Record<string, string> = {
    MINUSONE_D810_OUT: reportPath,
    MINUSONE_D810_PATH: d810Path,
    MINUSONE_D810_PROJECT: profileName,
  };
  if (options.target !== undefined) {
    env.MINUSONE_D810_TARGET = options.target;
  }

  const args = [
    "-A", "-c",
    `-S${smokeScript}`,
    `-o${idbPath}`,
    absolutePath,
  ];
  const command = await runBoundedCommand(idat, args, {
    cwd: runDir,
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: 1024 * 1024,
    env,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  let report: Partial<D810Result> = {};
  try {
    report = JSON.parse(await readFile(reportPath, "utf8")) as Partial<D810Result>;
  } catch {
    report = { error: `idat produced no report (exit ${command.exitCode}${command.timedOut ? ", timed out" : ""}): ${command.stderr.slice(0, 400)}` };
  }
  // The IDB and report are intermediate; clean the idb to keep run dirs small.
  await rm(idbPath, { force: true }).catch(() => {});

  return {
    idat,
    target: options.target ?? "(first non-library function)",
    d810Available: report.d810Available === true,
    baseline: report.baseline ?? null,
    deobfuscated: report.deobfuscated ?? null,
    error: report.error ?? null,
    traceback: report.traceback ?? null,
    profile: profileName,
    stagedProfile,
    command,
  };
}
