import { inspectBinary } from "./binary.js";
import { probeCommand, runBoundedCommand } from "./command.js";
import { extractStrings } from "./strings.js";
import type { BaselineAnalysis, CommandResult } from "./types.js";
import type { Workspace } from "./workspace.js";

async function inspectHeaders(workspace: Workspace, userPath: string, kind: string): Promise<CommandResult | undefined> {
  const absolutePath = await workspace.resolveFile(userPath);
  if (kind === "elf" && await probeCommand("readelf")) {
    return await runBoundedCommand("readelf", ["-h", absolutePath], {
      cwd: workspace.root,
      timeoutMs: 20_000,
      maxOutputBytes: 16 * 1024,
    });
  }
  if (await probeCommand("objdump")) {
    return await runBoundedCommand("objdump", ["-f", absolutePath], {
      cwd: workspace.root,
      timeoutMs: 20_000,
      maxOutputBytes: 16 * 1024,
    });
  }
  return undefined;
}

export async function baselineAnalyze(workspace: Workspace, userPath: string): Promise<BaselineAnalysis> {
  const binary = await inspectBinary(workspace, userPath);
  const strings = await extractStrings(workspace, userPath, { limit: 80 });
  const headers = await inspectHeaders(workspace, userPath, binary.format.kind);
  const limitations: string[] = [];

  if (!headers) limitations.push("No compatible readelf/objdump command was found; header details are unavailable.");
  limitations.push("This baseline does not execute the sample.");
  limitations.push("Decompiler output requires the optional Ghidra backend.");

  return { binary, strings, ...(headers ? { headers } : {}), limitations };
}

export interface DisassembleOptions {
  symbol?: string;
  startAddress?: string;
  stopAddress?: string;
  section?: string;
  maxOutputBytes?: number;
  signal?: AbortSignal;
}

function validateAddress(value: string | undefined, name: string): void {
  if (value !== undefined && !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) {
    throw new Error(`${name} must be a decimal or hexadecimal address`);
  }
}

export async function disassemble(
  workspace: Workspace,
  userPath: string,
  options: DisassembleOptions = {},
): Promise<CommandResult> {
  if (!await probeCommand("objdump")) throw new Error("objdump is not available");
  validateAddress(options.startAddress, "startAddress");
  validateAddress(options.stopAddress, "stopAddress");
  if (options.symbol !== undefined && !/^[A-Za-z0-9_.$@?+-]{1,256}$/.test(options.symbol)) {
    throw new Error("symbol contains unsupported characters");
  }
  if (options.section !== undefined && !/^[A-Za-z0-9_.$-]{1,64}$/.test(options.section)) {
    throw new Error("section contains unsupported characters");
  }
  if (options.section !== undefined && (options.symbol !== undefined || options.startAddress !== undefined || options.stopAddress !== undefined)) {
    throw new Error("section dump cannot be combined with symbol or address ranges");
  }

  const absolutePath = await workspace.resolveFile(userPath);
  const args = options.section !== undefined
    ? ["-s", "-j", options.section, absolutePath]
    : ["-d", "--demangle"];
  if (options.section === undefined) {
    if (options.symbol) args.push(`--disassemble=${options.symbol}`);
    if (options.startAddress) args.push(`--start-address=${options.startAddress}`);
    if (options.stopAddress) args.push(`--stop-address=${options.stopAddress}`);
    args.push(absolutePath);
  }

  return await runBoundedCommand("objdump", args, {
    cwd: workspace.root,
    timeoutMs: 30_000,
    maxOutputBytes: Math.min(Math.max(options.maxOutputBytes ?? 128 * 1024, 4096), 1024 * 1024),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
}
