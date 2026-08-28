/**
 * DLL host-process resolution. A DLL cannot be spawned directly — a host
 * loads it. rundll32.exe is the standard analyst host: it LoadLibrary's the
 * DLL (DllMain runs — where packers unpack) and calls a chosen export.
 * Every dynamic-plane spawn goes through resolveSampleLaunch, so DLLs take
 * the same combat path as EXEs: sample.execute, dynamic.unpack,
 * dynamic.frida, and both intent chains.
 *
 * The 32/64-bit mismatch is handled: a 32-bit DLL needs the SysWOW64
 * rundll32, a 64-bit one the System32 binary.
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { parsePeTables } from "./peimports.js";
import type { PeTables } from "./peimports.js";
import type { Workspace } from "./workspace.js";

export const IMAGE_FILE_DLL = 0x2000;

/** Export names an analyst would bet on when nothing else is known. */
const EXPORT_PICK_PATTERN = /(install|main|start|run|exec|entry|payload|service|dllregister|plugin)/i;

export interface SampleLaunch {
  command: string;
  args: string[];
  host: "direct" | "rundll32";
  /** The export rundll32 was told to call (null: bare load or direct spawn). */
  entryExport: string | null;
}

export function resolveRundll32(bits: 32 | 64 | null): string {
  const explicit = process.env.MINUSONE_RUNDLL32_BIN;
  if (explicit !== undefined && explicit !== "" && existsSync(explicit)) return explicit;
  const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
  if (bits === 32) {
    const wow64 = path.join(systemRoot, "SysWOW64", "rundll32.exe");
    if (existsSync(wow64)) return wow64;
  }
  const system32 = path.join(systemRoot, "System32", "rundll32.exe");
  if (existsSync(system32)) return system32;
  return "rundll32";
}

/** Pick the export rundll32 should call: heuristic, then first named, then first ordinal. */
export function pickDllExport(tables: PeTables): string | null {
  const named = tables.exports.filter((entry) => !entry.name.startsWith("#"));
  const heuristic = named.find((entry) => EXPORT_PICK_PATTERN.test(entry.name));
  if (heuristic !== undefined) return heuristic.name;
  if (named.length > 0) return named[0]?.name ?? null;
  const first = tables.exports[0];
  if (first !== undefined && first.ordinal !== null) return `#${first.ordinal}`;
  return null;
}

/**
 * Resolve how a sample must be launched on the dynamic plane. EXEs spawn
 * directly; DLLs go through rundll32 (`dll,Export` so the export runs, or a
 * bare path so at least DllMain executes). Non-PE files spawn directly and
 * fail at the OS level, exactly as before.
 */
export async function resolveSampleLaunch(
  workspace: Workspace,
  userPath: string,
  entryExport?: string,
): Promise<SampleLaunch> {
  const absolutePath = await workspace.resolveFile(userPath);
  const tables = await parsePeTables(workspace, userPath);
  if (tables === null || (tables.characteristics & IMAGE_FILE_DLL) === 0) {
    return { command: absolutePath, args: [], host: "direct", entryExport: null };
  }

  const rundll32 = resolveRundll32(tables.bits);
  const chosen = entryExport !== undefined && entryExport !== "" ? entryExport : pickDllExport(tables);
  if (chosen === null) {
    return { command: rundll32, args: [absolutePath], host: "rundll32", entryExport: null };
  }
  return { command: rundll32, args: [`${absolutePath},${chosen}`], host: "rundll32", entryExport: chosen };
}
