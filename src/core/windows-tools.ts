import { access, readdir } from "node:fs/promises";
import path from "node:path";
import type { ToolCapability } from "./types.js";

/**
 * Detection-only inventory of the native Windows RE toolchain: debuggers,
 * instrumentation, and capture helpers. Nothing here is ever executed —
 * presence means the operator has the tool, not that sample execution is
 * permitted (see the dynamic-plane policy gate in operations.ts).
 *
 * Every entry resolves in order: explicit env override, well-known install
 * paths, then an existence scan along PATH.
 */

interface ToolSpec {
  name: string;
  /** Env var holding a directory (or full exe path) that overrides discovery. */
  env: string;
  /** File names to look for inside the override directory / PATH entries. */
  executables: string[];
  /** Fixed well-known locations (may use %ENV% expansion via the caller). */
  fixedPaths: string[];
  /** Directory prefixes under Program Files whose children are scanned. */
  programFilesPrefixes?: string[];
  note: string;
}

const PROGRAM_FILES = process.env.ProgramFiles ?? "C:/Program Files";
const PROGRAM_FILES_X86 = process.env["ProgramFiles(x86)"] ?? "C:/Program Files (x86)";
const LOCAL_APPDATA = process.env.LOCALAPPDATA ?? "";
const WINDOWS_KITS = path.join(PROGRAM_FILES_X86, "Windows Kits", "10", "Debuggers");
/** Default extraction target for the x64dbg snapshot zip (release/x64 layout). */
const X64DBG_ROOT = "C:/x64dbg";
/** Default extraction target for the Sysinternals Suite zip (exes at root). */
const SYSINTERNALS_ROOT = "C:/SysinternalsSuite";

const TOOL_SPECS: ToolSpec[] = [
  {
    name: "x64dbg",
    env: "MINUSONE_X64DBG_HOME",
    executables: ["x64dbg.exe"],
    fixedPaths: [
      path.join(X64DBG_ROOT, "release", "x64", "x64dbg.exe"),
      path.join(PROGRAM_FILES, "x64dbg", "release", "x64", "x64dbg.exe"),
      path.join(PROGRAM_FILES, "x64dbg", "x64", "x64dbg.exe"),
      path.join(PROGRAM_FILES_X86, "x64dbg", "x64", "x64dbg.exe"),
    ],
    note: "user-mode debugger driver; headless-driven via native scripting batch model",
  },
  {
    name: "x32dbg",
    env: "MINUSONE_X64DBG_HOME",
    executables: ["x32dbg.exe"],
    fixedPaths: [
      path.join(X64DBG_ROOT, "release", "x32", "x32dbg.exe"),
      path.join(PROGRAM_FILES, "x64dbg", "release", "x32", "x32dbg.exe"),
      path.join(PROGRAM_FILES, "x64dbg", "x32", "x32dbg.exe"),
      path.join(PROGRAM_FILES_X86, "x64dbg", "x32", "x32dbg.exe"),
    ],
    note: "32-bit user-mode debugger driver",
  },
  {
    name: "windbg",
    env: "MINUSONE_WINDBG_HOME",
    executables: ["windbg.exe", "DbgX.Shell.exe"],
    fixedPaths: [
      ...(LOCAL_APPDATA ? [path.join(LOCAL_APPDATA, "Microsoft", "WindowsApps", "WinDbgX.exe")] : []),
      path.join(WINDOWS_KITS, "x64", "windbg.exe"),
    ],
    note: "debugger front end; console automation goes through cdb",
  },
  {
    name: "cdb",
    env: "MINUSONE_CDB_PATH",
    executables: ["cdb.exe"],
    fixedPaths: [path.join(WINDOWS_KITS, "x64", "cdb.exe"), path.join(WINDOWS_KITS, "x86", "cdb.exe")],
    note: "console debugger — the scriptable bridge for an armed dynamic plane (dump analysis is postmortem-safe)",
  },
  {
    name: "cheat-engine",
    env: "MINUSONE_CHEAT_ENGINE_HOME",
    executables: ["cheatengine-x86_64.exe", "cheatengine-x86_64-SSE4.2.exe", "cheatengine-i386.exe", "ce.exe"],
    programFilesPrefixes: ["cheat engine"],
    fixedPaths: [],
    note: "live memory inspection driver for the dynamic plane",
  },
  {
    name: "system-informer",
    env: "MINUSONE_SYSTEMINFORMER_HOME",
    executables: ["SystemInformer.exe", "ProcessHacker.exe"],
    programFilesPrefixes: ["systeminformer", "process hacker"],
    fixedPaths: [],
    note: "process/resource inspection; useful on the disposable target side",
  },
  {
    name: "procmon",
    env: "MINUSONE_SYSINTERNALS_HOME",
    executables: ["Procmon64.exe", "Procmon.exe"],
    fixedPaths: [path.join(SYSINTERNALS_ROOT, "Procmon64.exe"), path.join(SYSINTERNALS_ROOT, "Procmon.exe")],
    note: "filesystem/registry activity capture (trace analysis is offline)",
  },
  {
    name: "procexp",
    env: "MINUSONE_SYSINTERNALS_HOME",
    executables: ["procexp64.exe", "procexp.exe"],
    fixedPaths: [path.join(SYSINTERNALS_ROOT, "procexp64.exe"), path.join(SYSINTERNALS_ROOT, "procexp.exe")],
    note: "live process inspection; dynamic plane capture helper",
  },
  {
    name: "frida",
    env: "MINUSONE_FRIDA_BIN",
    executables: ["frida.exe", "frida-server.exe"],
    fixedPaths: [],
    note: "instrumentation driver — injecting into a sample is dynamic-plane activity and stays policy-gated",
  },
];

function pathEntries(): string[] {
  return (process.env.PATH ?? "").split(path.delimiter).filter((entry) => entry.trim() !== "");
}

async function resolveCandidate(candidate: string, executables: string[]): Promise<string | null> {
  const basename = path.basename(candidate).toLowerCase();
  const lowerExecutables = executables.map((executable) => executable.toLowerCase());
  if (lowerExecutables.includes(basename)) {
    try {
      await access(candidate);
      return path.resolve(candidate);
    } catch {
      return null;
    }
  }
  // The candidate is a directory: look for the executables inside it.
  for (const executable of executables) {
    const joined = path.join(candidate, executable);
    try {
      await access(joined);
      return path.resolve(joined);
    } catch {
      // Try the next executable name.
    }
  }
  return null;
}

async function programFilesScan(prefix: string, executables: string[]): Promise<string | null> {
  for (const root of [PROGRAM_FILES, PROGRAM_FILES_X86]) {
    let entries: string[];
    try {
      entries = await readdir(root);
    } catch {
      continue;
    }
    const match = entries.find((entry) => entry.toLowerCase().startsWith(prefix));
    if (match === undefined) continue;
    const resolved = await resolveCandidate(path.join(root, match), executables);
    if (resolved !== null) return resolved;
  }
  return null;
}

/** Detect one tool spec without executing anything. */
export async function detectWindowsTool(spec: ToolSpec): Promise<ToolCapability> {
  const override = process.env[spec.env];
  if (override) {
    const resolved = await resolveCandidate(override, spec.executables);
    if (resolved !== null) {
      return { name: spec.name, available: true, path: resolved, note: `${spec.note}; via ${spec.env}` };
    }
    return { name: spec.name, available: false, note: `${spec.env} is set but resolves to nothing` };
  }

  for (const fixed of spec.fixedPaths) {
    const resolved = await resolveCandidate(fixed, spec.executables);
    if (resolved !== null) return { name: spec.name, available: true, path: resolved, note: spec.note };
  }
  if (spec.programFilesPrefixes !== undefined) {
    for (const prefix of spec.programFilesPrefixes) {
      const resolved = await programFilesScan(prefix, spec.executables);
      if (resolved !== null) return { name: spec.name, available: true, path: resolved, note: spec.note };
    }
  }
  for (const entry of pathEntries()) {
    const resolved = await resolveCandidate(entry, spec.executables);
    if (resolved !== null) return { name: spec.name, available: true, path: resolved, note: `${spec.note}; found on PATH` };
  }
  return { name: spec.name, available: false, note: `Set ${spec.env} to the install location` };
}

export interface WindowsToolchain {
  tools: ToolCapability[];
  /** True when at least one interactive debugger driver is installed. */
  hasDebuggerDriver: boolean;
  /** True when the scriptable console debugger (cdb) is installed. */
  hasScriptableBridge: boolean;
}

export async function detectWindowsToolchain(): Promise<WindowsToolchain> {
  const tools = await Promise.all(TOOL_SPECS.map(detectWindowsTool));
  return {
    tools,
    hasDebuggerDriver: tools.some(
      (tool) => tool.available && ["x64dbg", "x32dbg", "windbg", "cheat-engine"].includes(tool.name),
    ),
    hasScriptableBridge: tools.some((tool) => tool.available && tool.name === "cdb"),
  };
}

export { TOOL_SPECS };
