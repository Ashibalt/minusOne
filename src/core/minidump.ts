import { open, stat } from "node:fs/promises";
import type { Workspace } from "./workspace.js";

/**
 * Postmortem minidump inspection: parses Windows user-mode crash/minidumps
 * ("MDMP") entirely offline. Reading a dump never executes the captured
 * process, so this belongs to the static/captured plane, not the dynamic
 * one. Bounds every list before anything model-facing sees it.
 */
export const MINIDUMP_MAX_MODULES = 300;
export const MINIDUMP_MAX_THREADS = 128;
export const MINIDUMP_MAX_REGIONS = 64;

const STREAM_THREAD_LIST = 3;
const STREAM_MODULE_LIST = 4;
const STREAM_MEMORY_LIST = 5;
const STREAM_EXCEPTION = 6;
const STREAM_SYSTEM_INFO = 7;
const STREAM_MEMORY_64_LIST = 9;
const STREAM_MISC_INFO = 15;

const ARCHITECTURES: Record<number, string> = {
  0: "x86",
  5: "arm",
  9: "x86_64",
  12: "arm64",
};

interface DirectoryEntry {
  streamType: number;
  dataSize: number;
  rva: number;
}

export interface MinidumpModule {
  name: string;
  base: string;
  size: number;
  checksum: string | null;
  timestamp: number | null;
  version: string | null;
}

export interface MinidumpThread {
  id: number;
  teb: string | null;
  stackStart: string | null;
  stackSize: number | null;
}

export interface MinidumpException {
  threadId: number;
  code: string;
  address: string;
  parameters: string[];
}

export interface MinidumpReport {
  dumpKind: "minidump";
  timestamp: number | null;
  architecture: string;
  os: { major: number | null; minor: number | null; build: number | null };
  processParameters: Record<string, string> | null;
  exception: MinidumpException | null;
  modules: MinidumpModule[];
  moduleCountTotal: number;
  threads: MinidumpThread[];
  threadCountTotal: number;
  memory: {
    regionCount: number;
    totalBytes: number;
    largest: { start: string; size: number } | null;
    regionsPreview: Array<{ start: string; size: number }>;
  };
  streams: Array<{ type: number; typeKnown: string; bytes: number }>;
  truncated: boolean;
  bytes: number;
}

function hex(value: bigint | null): string | null {
  return value === null ? null : `0x${value.toString(16)}`;
}

function readDirectoryEntry(buffer: Buffer, offset: number): DirectoryEntry | null {
  if (offset + 12 > buffer.length) return null;
  return {
    streamType: buffer.readUInt32LE(offset),
    dataSize: buffer.readUInt32LE(offset + 4),
    rva: buffer.readUInt32LE(offset + 8),
  };
}

/** MINIDUMP_STRING: u32 byte length + UTF-16LE data. */
function readMinidumpString(buffer: Buffer, rva: number): string | null {
  if (rva === 0 || rva + 4 > buffer.length) return null;
  const byteLength = buffer.readUInt32LE(rva);
  if (byteLength > 32768 || rva + 4 + byteLength > buffer.length) return null;
  try {
    return buffer.toString("utf16le", rva + 4, rva + 4 + byteLength);
  } catch {
    return null;
  }
}

function parseModuleList(buffer: Buffer, entry: DirectoryEntry, maxModules: number): { modules: MinidumpModule[]; total: number } {
  const start = entry.rva;
  if (start + 4 > buffer.length) return { modules: [], total: 0 };
  const total = buffer.readUInt32LE(start);
  const modules: MinidumpModule[] = [];
  const MODULE_SIZE = 108;
  for (let index = 0; index < total && index < maxModules; index += 1) {
    const base = start + 4 + index * MODULE_SIZE;
    if (base + MODULE_SIZE > buffer.length) break;
    const baseOfImage = buffer.readBigUInt64LE(base);
    const sizeOfImage = buffer.readUInt32LE(base + 8);
    const checksum = buffer.readUInt32LE(base + 12);
    const timestamp = buffer.readUInt32LE(base + 16);
    const nameRva = buffer.readUInt32LE(base + 20);
    // VS_FIXEDFILEINFO starts at +24: signature u32, structure/struc/version
    // u32s, then FileVersionMS/LS at +16/+20 within it.
    const fileVersionMs = buffer.readUInt32LE(base + 24 + 16);
    const fileVersionLs = buffer.readUInt32LE(base + 24 + 20);
    const hasVersion =
      buffer.readUInt32LE(base + 24) === 0xfeef04bd && (fileVersionMs !== 0 || fileVersionLs !== 0);
    modules.push({
      name: readMinidumpString(buffer, nameRva) ?? "",
      base: hex(baseOfImage) ?? "0x0",
      size: sizeOfImage,
      checksum: checksum === 0 ? null : `0x${checksum.toString(16)}`,
      timestamp: timestamp === 0 ? null : timestamp,
      version: hasVersion
        ? `${fileVersionMs >>> 16}.${fileVersionMs & 0xffff}.${fileVersionLs >>> 16}.${fileVersionLs & 0xffff}`
        : null,
    });
  }
  return { modules, total };
}

function parseThreadList(buffer: Buffer, entry: DirectoryEntry, maxThreads: number): { threads: MinidumpThread[]; total: number } {
  const start = entry.rva;
  if (start + 4 > buffer.length) return { threads: [], total: 0 };
  const total = buffer.readUInt32LE(start);
  const threads: MinidumpThread[] = [];
  const THREAD_SIZE = 48;
  for (let index = 0; index < total && index < maxThreads; index += 1) {
    const base = start + 4 + index * THREAD_SIZE;
    if (base + THREAD_SIZE > buffer.length) break;
    threads.push({
      id: buffer.readUInt32LE(base),
      teb: hex(buffer.readBigUInt64LE(base + 16)),
      stackStart: hex(buffer.readBigUInt64LE(base + 24)),
      stackSize: buffer.readUInt32LE(base + 32) === 0 ? null : buffer.readUInt32LE(base + 32),
    });
  }
  return { threads, total };
}

function parseException(buffer: Buffer, entry: DirectoryEntry): MinidumpException | null {
  const base = entry.rva;
  if (base + 8 + 152 + 8 > buffer.length) return null;
  const threadId = buffer.readUInt32LE(base);
  const code = buffer.readUInt32LE(base + 8);
  const address = buffer.readBigUInt64LE(base + 8 + 16);
  const numberParameters = Math.min(buffer.readUInt32LE(base + 8 + 24), 15);
  const parameters: string[] = [];
  for (let index = 0; index < numberParameters; index += 1) {
    parameters.push(`0x${buffer.readBigUInt64LE(base + 8 + 40 + index * 8).toString(16)}`);
  }
  return { threadId, code: `0x${code.toString(16)}`, address: `0x${address.toString(16)}`, parameters };
}

function parseSystemInfo(buffer: Buffer, entry: DirectoryEntry): {
  architecture: string;
  os: { major: number | null; minor: number | null; build: number | null };
} {
  const base = entry.rva;
  if (base + 32 > buffer.length) {
    return { architecture: "unknown", os: { major: null, minor: null, build: null } };
  }
  const arch = buffer.readUInt16LE(base);
  // Layout per minidumpapiset.h: arch/level/revision u16, NumberOfProcessors
  // and ProductType are UCHARs at +6/+7, then Major +8, Minor +12, Build +16.
  return {
    architecture: ARCHITECTURES[arch] ?? `arch-${arch}`,
    os: { major: buffer.readUInt32LE(base + 8), minor: buffer.readUInt32LE(base + 12), build: buffer.readUInt32LE(base + 16) },
  };
}

function summarizeMemory(
  buffer: Buffer,
  memoryList: DirectoryEntry | null,
  memory64List: DirectoryEntry | null,
  maxRegions: number,
): MinidumpReport["memory"] {
  let regionCount = 0;
  let totalBytes = 0;
  let largest: { start: string; size: number } | null = null;
  const regionsPreview: Array<{ start: string; size: number }> = [];

  const note = (start: bigint, size: number) => {
    regionCount += 1;
    totalBytes += size;
    const record = { start: `0x${start.toString(16)}`, size };
    if (largest === null || size > (largest as { start: string; size: number }).size) {
      largest = record;
    }
    if (regionsPreview.length < maxRegions) regionsPreview.push(record);
  };

  if (memoryList !== null && memoryList.rva + 4 <= buffer.length) {
    const count = buffer.readUInt32LE(memoryList.rva);
    for (let index = 0; index < count; index += 1) {
      const base = memoryList.rva + 4 + index * 16;
      if (base + 16 > buffer.length) break;
      note(buffer.readBigUInt64LE(base), buffer.readUInt32LE(base + 8));
    }
  }
  if (memory64List !== null && memory64List.rva + 16 <= buffer.length) {
    const count = Number(buffer.readBigUInt64LE(memory64List.rva));
    for (let index = 0; index < count; index += 1) {
      const base = memory64List.rva + 16 + index * 16;
      if (base + 16 > buffer.length) break;
      note(buffer.readBigUInt64LE(base), Number(buffer.readBigUInt64LE(base + 8)));
    }
  }
  return { regionCount, totalBytes, largest, regionsPreview };
}

const KNOWN_STREAMS: Record<number, string> = {
  [STREAM_THREAD_LIST]: "ThreadList",
  [STREAM_MODULE_LIST]: "ModuleList",
  [STREAM_MEMORY_LIST]: "MemoryList",
  [STREAM_EXCEPTION]: "Exception",
  [STREAM_SYSTEM_INFO]: "SystemInfo",
  [STREAM_MEMORY_64_LIST]: "Memory64List",
  [STREAM_MISC_INFO]: "MiscInfo",
};

export class MinidumpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MinidumpError";
  }
}

export async function inspectMinidump(workspace: Workspace, userPath: string): Promise<MinidumpReport> {
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const handle = await open(absolutePath, "r");
  const buffer = Buffer.alloc(fileStats.size);
  try {
    await handle.read(buffer, 0, buffer.length, 0);
  } finally {
    await handle.close();
  }

  if (buffer.length < 32 || buffer.toString("ascii", 0, 4) !== "MDMP") {
    throw new MinidumpError(`${workspace.relative(absolutePath)} is not a minidump (missing MDMP signature)`);
  }

  const numberOfStreams = buffer.readUInt32LE(8);
  const directoryRva = buffer.readUInt32LE(12);
  const timestamp = buffer.readUInt32LE(20);

  const entries: DirectoryEntry[] = [];
  for (let index = 0; index < numberOfStreams; index += 1) {
    const entry = readDirectoryEntry(buffer, directoryRva + index * 12);
    if (entry === null) break;
    entries.push(entry);
  }
  const find = (type: number): DirectoryEntry | null => entries.find((entry) => entry.streamType === type) ?? null;

  const systemInfoEntry = find(STREAM_SYSTEM_INFO);
  const moduleListEntry = find(STREAM_MODULE_LIST);
  const { modules, total: moduleCountTotal } = moduleListEntry
    ? parseModuleList(buffer, moduleListEntry, MINIDUMP_MAX_MODULES)
    : { modules: [], total: 0 };
  const threadResult = (() => {
    const entry = find(STREAM_THREAD_LIST);
    return entry ? parseThreadList(buffer, entry, MINIDUMP_MAX_THREADS) : { threads: [], total: 0 };
  })();
  const exceptionEntry = find(STREAM_EXCEPTION);
  const systemInfo = systemInfoEntry ? parseSystemInfo(buffer, systemInfoEntry) : null;

  return {
    dumpKind: "minidump",
    timestamp: timestamp === 0 ? null : timestamp,
    architecture: systemInfo ? systemInfo.architecture : "unknown",
    os: systemInfo ? systemInfo.os : { major: null, minor: null, build: null },
    processParameters: null,
    exception: exceptionEntry ? parseException(buffer, exceptionEntry) : null,
    modules,
    moduleCountTotal,
    threads: threadResult.threads,
    threadCountTotal: threadResult.total,
    memory: summarizeMemory(buffer, find(STREAM_MEMORY_LIST), find(STREAM_MEMORY_64_LIST), MINIDUMP_MAX_REGIONS),
    streams: entries.map((entry) => ({
      type: entry.streamType,
      typeKnown: KNOWN_STREAMS[entry.streamType] ?? `unknown-${entry.streamType}`,
      bytes: entry.dataSize,
    })),
    truncated: moduleCountTotal > MINIDUMP_MAX_MODULES || threadResult.total > MINIDUMP_MAX_THREADS,
    bytes: buffer.length,
  };
}
