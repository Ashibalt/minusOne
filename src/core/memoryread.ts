/**
 * memory.read — the address plane. One verb turns an address into bytes,
 * decoded values, or a followed pointer chain, with NO manual VA/RVA/offset
 * arithmetic left to the agent (the classic hours-long "one byte off and I
 * patched the wrong place" trap). Two modes:
 *
 *   file mode    — read the on-disk image: va (or rva/offset) is resolved
 *                  through the PE section table via random-access positioned
 *                  reads. Big binaries are fine: only the requested window
 *                  is read.
 *   session mode — read a LIVE address from a debugger session (gdb inferior
 *                  or cdb postmortem dump): runtime VA as-is, ASLR included.
 *
 * Pointer chasing: a decoded u32/u64 that lands inside the image is followed
 * (depth-limited) with section/symbol annotation at every hop — the manual
 * table walk from the pain file becomes one call.
 */
import { open, stat } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import { fileOffsetToRva, parsePeTablesFromPath, rvaToFileOffset, sectionForFileOffset, sectionForRva, type PeTables } from "./peimports.js";
import { loadSymbolIndex, lookupSymbol, parseVa, type SymbolEntry } from "./symbols.js";
import { activeDebugSessionKind, sendDebugCommand } from "./debugger.js";
import type { DebuggerKind } from "./debug-driver.js";
import type { Workspace } from "./workspace.js";

export const MEMORY_DEFAULT_BYTES = 64;
export const MEMORY_MAX_INLINE_BYTES = 2048;
export const MEMORY_MAX_DUMP_ROWS = 64;
export const MEMORY_MAX_INLINE_ELEMENTS = 512;
export const MEMORY_MAX_READ_BYTES = 4 * 1024 * 1024;
export const MEMORY_MAX_CHASE_DEPTH = 4;
export const MEMORY_MAX_CHASE_ELEMENTS = 16;

export type MemoryDecodeType =
  | "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64"
  | "f32" | "f64" | "cstr" | "utf16";

const SCALAR_TYPES: Record<string, number> = {
  u8: 1, i8: 1, u16: 2, i16: 2, u32: 4, i32: 4, u64: 8, i64: 8, f32: 4, f64: 8,
};

export interface MemoryReadOptions {
  /** Workspace-relative path (file mode). */
  path?: string;
  /** Debugger session id (session mode). */
  sessionId?: string;
  /** Address in any mode; hex ("0x140001000") or decimal. */
  va?: string;
  /** Relative virtual address (file mode). */
  rva?: string;
  /** Raw file offset (file mode). */
  offset?: number;
  /** Bytes to read (default 64; cstr/utf16: max scan length). */
  count?: number;
  /** Decode the read window as this type instead of (or in addition to) the raw dump. */
  type?: MemoryDecodeType;
  /** Element count for scalar decodes (default 1) — reads a TABLE. */
  elements?: number;
  /** Follow in-image pointer values with section/symbol annotation (file mode). */
  chasePointers?: boolean;
}

export interface MemoryAddressReport {
  input: string;
  kind: "va" | "rva" | "offset" | "runtime";
  fileOffset: number | null;
  rva: number | null;
  va: string | null;
  section: string | null;
  symbol: string | null;
  symbolComment: string | null;
}

export interface MemoryChaseHop {
  va: string;
  value: string;
  section: string | null;
  symbol: string | null;
  note: string | null;
}

export interface MemoryPointerChase {
  from: string;
  hops: MemoryChaseHop[];
  /** Printable string at the end of the chain, when one lives there. */
  leafString: string | null;
}

export interface MemoryReadResult {
  mode: "file" | "session";
  /** Workspace-relative path (file mode) or null (session mode). */
  path: string | null;
  /** Session id (session mode) or "" (file mode) — never null: hosts validate. */
  sessionId: string;
  /** Backend of the session read ("gdb"/"cdb") or "" (file mode). */
  debugger: string;  address: MemoryAddressReport;
  requestedBytes: number;
  readBytes: number;
  truncated: boolean;
  hexdump: string;
  hexdumpTruncated: boolean;
  bytesHex: string | null;
  ascii: string | null;
  decode: {
    type: string;
    elements: number;
    values: Array<string | number>;
    truncated: boolean;
    /** Present when the value list overflowed the inline cap. */
    fullValues: { artifactId: string; bytes: number } | null;
  };
  pointers: MemoryPointerChase[];
  notes: string[];
  next: string[];
}

function hex(value: number | null): string | null {
  if (value === null) return null;
  return `0x${value.toString(16)}`;
}

function printableAscii(buffer: Buffer): string {
  const chars: string[] = [];
  for (const byte of buffer.subarray(0, MEMORY_MAX_INLINE_BYTES)) {
    chars.push(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".");
  }
  return chars.join("");
}

function renderHexdump(buffer: Buffer, baseVa: number | null): { text: string; truncated: boolean } {
  const rows: string[] = [];
  for (let row = 0; row * 16 < buffer.length && row < MEMORY_MAX_DUMP_ROWS; row += 1) {
    const slice = buffer.subarray(row * 16, row * 16 + 16);
    const addressText = baseVa === null ? `${(row * 16).toString(16).padStart(8, "0")}` : `${(baseVa + row * 16).toString(16).padStart(12, "0")}`;
    const hexPart = [...slice].map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const asciiPart = [...slice].map((byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".")).join("");
    rows.push(`${addressText}  ${hexPart}  ${asciiPart}`);
  }
  return { text: rows.join("\n"), truncated: buffer.length > MEMORY_MAX_DUMP_ROWS * 16 };
}

function readAsciiZ(buffer: Buffer, start: number, limit: number): { value: string; consumed: number } {
  let end = start;
  while (end < buffer.length && end - start < limit && buffer[end] !== 0) end += 1;
  return { value: buffer.toString("ascii", start, end), consumed: end - start + 1 };
}

function readUtf16Z(buffer: Buffer, start: number, limit: number): { value: string; consumed: number } {
  let end = start;
  while (end + 1 < buffer.length && end - start < limit && !(buffer[end] === 0 && buffer[end + 1] === 0)) end += 2;
  return { value: buffer.toString("utf16le", start, end), consumed: end - start + 2 };
}

function decodeScalar(buffer: Buffer, type: MemoryDecodeType, position: number): number | null {
  const width = SCALAR_TYPES[type];
  if (width === undefined || position < 0 || position + width > buffer.length) return null;
  switch (type) {
    case "u8": return buffer[position] ?? null;
    case "i8": return buffer.readInt8(position);
    case "u16": return buffer.readUInt16LE(position);
    case "i16": return buffer.readInt16LE(position);
    case "u32": return buffer.readUInt32LE(position);
    case "i32": return buffer.readInt32LE(position);
    case "u64": return Number(buffer.readBigUInt64LE(position));
    case "i64": return Number(buffer.readBigInt64LE(position));
    case "f32": return buffer.readFloatLE(position);
    case "f64": return buffer.readDoubleLE(position);
    default: return null;
  }
}

function formatScalar(type: MemoryDecodeType, value: number): string {
  if (type === "f32" || type === "f64") return String(value);
  if (type.startsWith("u") || type.startsWith("i64")) {
    // Pointer-ish widths render as hex + decimal; small scalars stay decimal.
    if (type === "u32" && value > 0xffff) return `0x${value.toString(16)} (${value})`;
    if (type === "u64" || type === "i64") return `0x${value.toString(16)} (${value})`;
  }
  return String(value);
}

function imageBounds(tables: PeTables): { imageBase: number; imageEnd: number } {
  let end = 0;
  for (const section of tables.sections) {
    end = Math.max(end, section.virtualAddress + Math.max(section.virtualSize, section.rawSize));
  }
  return { imageBase: tables.imageBase, imageEnd: tables.imageBase + Math.max(end, 0x1000) };
}

/** Parse raw debugger memory-dump output (gdb `x/Nbx` or cdb `db`) into bytes. */
export function parseDebuggerMemoryOutput(output: string): Buffer {
  const bytes: number[] = [];
  for (const line of output.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    const body = colon >= 0 ? line.slice(colon + 1) : line;
    // gdb: "0x140001000 <main+8>:\t0x4d\t0x49" — tokens are 0xNN.
    for (const match of body.matchAll(/0x([0-9a-f]{2})\b/gi)) {
      const hexText = match[1];
      if (hexText === undefined) continue;
      const value = Number.parseInt(hexText, 16);
      if (!Number.isNaN(value)) bytes.push(value);
    }
    // cdb: "00007ff6`c6de1234  4d 49 4e-55 00" — bare NN pairs (the address
    // lives before the double space; the backtick splits the 64-bit form).
    if (colon < 0 || !/0x/.test(body)) {
      for (const match of body.matchAll(/\b([0-9a-f]{2})\b/gi)) {
        const hexText = match[1];
        if (hexText === undefined) continue;
        const value = Number.parseInt(hexText, 16);
        if (!Number.isNaN(value)) bytes.push(value);
      }
    }
  }
  return Buffer.from(bytes);
}

async function readFromSession(
  options: MemoryReadOptions,
  addressInput: string,
  requested: number,
): Promise<{ raw: DebugCommandResultLike; buffer: Buffer; kind: DebuggerKind }> {
  const sessionId = options.sessionId as string;
  const kind = activeDebugSessionKind(sessionId);
  if (kind === null) {
    throw new Error(`unknown debug session ${JSON.stringify(sessionId)} — create one with debug_session_create first`);
  }
  if (kind === "x64dbg") {
    throw new Error("memory.read session mode supports gdb and cdb sessions; for x64dbg read memory inside the script you send via debug_command (e.g. \"mov $result, [addr]\" / log it)");
  }
  const command = kind === "gdb"
    ? `x/${requested}bx ${addressInput}`
    : `db ${addressInput} L${requested}`;
  const raw = await sendDebugCommand(sessionId, command, 60);
  if (!raw.ok) {
    throw new Error(`debugger memory read failed: ${raw.error ?? raw.output.slice(0, 200)}`);
  }
  return { raw, buffer: parseDebuggerMemoryOutput(raw.output), kind };
}

interface DebugCommandResultLike {
  ok: boolean;
  output: string;
  error?: string;
}

export async function readMemory(workspace: Workspace, options: MemoryReadOptions): Promise<MemoryReadResult> {
  const addressInputs = [options.va, options.rva, options.offset !== undefined ? String(options.offset) : undefined].filter((value) => value !== undefined);
  if (addressInputs.length === 0) {
    throw new Error("pass exactly one address field: va (preferred), rva, or offset");
  }
  if (addressInputs.length > 1) {
    throw new Error(`pass only ONE of va/rva/offset (got ${addressInputs.length})`);
  }
  if (options.path !== undefined && options.sessionId !== undefined) {
    throw new Error("pass either path (file mode) or sessionId (session mode), not both");
  }
  if (options.path === undefined && options.sessionId === undefined) {
    throw new Error("pass path (file mode) or sessionId (session mode)");
  }
  if (options.sessionId !== undefined && options.rva !== undefined) {
    throw new Error("session mode takes a runtime va — rva/offset are file-image concepts");
  }

  const requested = Math.max(1, Math.min(options.count ?? MEMORY_DEFAULT_BYTES, MEMORY_MAX_READ_BYTES));
  const type = options.type;
  const elements = Math.max(1, options.elements ?? 1);
  const notes: string[] = [];
  const next: string[] = [];

  // ---- session mode -------------------------------------------------------
  if (options.sessionId !== undefined) {
    const addressInput = options.va as string;
    const addressNumber = parseVa(addressInput);
    if (addressNumber === null) throw new Error(`cannot parse address ${JSON.stringify(addressInput)}`);
    const { raw, buffer, kind } = await readFromSession(options, addressInput, requested);
    const address: MemoryAddressReport = {
      input: addressInput,
      kind: "runtime",
      fileOffset: null,
      rva: null,
      va: hex(addressNumber),
      section: null,
      symbol: null,
      symbolComment: null,
    };
    const dump = renderHexdump(buffer, addressNumber);
    notes.push(`${kind} session memory: the address is the LIVE runtime address (ASLR included)`);
    if (buffer.length < requested) notes.push(`debugger returned ${buffer.length} of ${requested} requested bytes (unreadable tail?)`);
    const decode = decodeWindow(buffer, type ?? "u8", 0);
    return {
      mode: "session",
      path: null,
      sessionId: options.sessionId,
      debugger: kind,
      address,
      requestedBytes: requested,
      readBytes: buffer.length,
      truncated: buffer.length < requested,
      hexdump: dump.text,
      hexdumpTruncated: dump.truncated,
      bytesHex: buffer.length <= MEMORY_MAX_INLINE_BYTES ? buffer.toString("hex") : null,
      ascii: printableAscii(buffer),
      decode,
      pointers: [],
      notes: [...notes, ...(decode.truncated ? ["value list truncated; re-run with a smaller elements count or narrower window"] : [])],
      next: [...next, `raw debugger output: ${raw.output.slice(0, 400)}`],
    };
  }

  // ---- file mode ----------------------------------------------------------
  const userPath = options.path as string;
  const absolutePath = await workspace.resolveFile(userPath);
  const binary = await inspectBinary(workspace, userPath);
  const tables = await parsePeTablesFromPath(absolutePath);
  if (tables === null) {
    throw new Error(`${userPath} is not a parsable PE image — memory.read needs a PE (ELF/Mach-O tables are not implemented yet)`);
  }
  const symbolIndex = await loadSymbolIndex(workspace, binary.sampleId);

  let fileOffset: number;
  let rva: number | null;
  let vaNumber: number | null;
  const input = addressInputs[0] as string;
  let kind: "va" | "rva" | "offset";

  if (options.va !== undefined) {
    const value = parseVa(options.va);
    if (value === null) throw new Error(`cannot parse va ${JSON.stringify(options.va)}`);
    if (value < tables.imageBase) {
      throw new Error(`va 0x${value.toString(16)} is below the image base 0x${tables.imageBase.toString(16)} — it looks like an RVA; pass it as rva instead`);
    }
    kind = "va";
    vaNumber = value;
    rva = value - tables.imageBase;
    const resolved = rvaToFileOffset(tables.sections, rva);
    if (resolved === null) {
      throw new Error(`va 0x${value.toString(16)} (rva 0x${rva.toString(16)}) does not map to file bytes — it may live in a virtual-only section (BSS) or outside the image`);
    }
    fileOffset = resolved;
  } else if (options.rva !== undefined) {
    const value = parseVa(options.rva);
    if (value === null) throw new Error(`cannot parse rva ${JSON.stringify(options.rva)}`);
    kind = "rva";
    rva = value;
    vaNumber = tables.imageBase + value;
    const resolved = rvaToFileOffset(tables.sections, value);
    if (resolved === null) {
      throw new Error(`rva 0x${value.toString(16)} does not map to file bytes — it may live in a virtual-only section (BSS) or outside the image`);
    }
    fileOffset = resolved;
  } else {
    const value = options.offset as number;
    if (!Number.isInteger(value) || value < 0) throw new Error(`offset must be a non-negative integer (got ${JSON.stringify(options.offset)})`);
    kind = "offset";
    fileOffset = value;
    rva = fileOffsetToRva(tables.sections, value);
    vaNumber = rva === null ? null : tables.imageBase + rva;
  }

  const section = kind === "offset" ? sectionForFileOffset(tables.sections, fileOffset) : sectionForRva(tables.sections, rva as number);
  const symbol = vaNumber === null ? null : lookupSymbol(symbolIndex, vaNumber);

  const stats = await stat(absolutePath);
  const available = Math.max(0, stats.size - fileOffset);
  const readLength = Math.min(requested, available);
  if (readLength === 0) {
    throw new Error(`address resolves to file offset ${fileOffset} which is at/past end of file (${stats.size} bytes)`);
  }
  const handle = await open(absolutePath, "r");
  let buffer: Buffer;
  try {
    const chunk = Buffer.alloc(readLength);
    const { bytesRead } = await handle.read(chunk, 0, readLength, fileOffset);
    buffer = chunk.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }

  const dump = renderHexdump(buffer, vaNumber);
  const decode = type === undefined ? null : decodeWindow(buffer, type, elements);

  // Pointer chasing: in-image u32/u64 values followed with annotation. The
  // file stays open for the whole walk — one handle, positioned reads.
  const pointers: MemoryPointerChase[] = [];
  if (options.chasePointers === true && (type === "u32" || type === "u64") && tables !== null) {
    const bounds = imageBounds(tables);
    const width = SCALAR_TYPES[type] ?? 4;
    const chaseCount = Math.min(elements, MEMORY_MAX_CHASE_ELEMENTS);
    const handle = await open(absolutePath, "r");
    try {
      const probe = Buffer.alloc(8);
      const scan = Buffer.alloc(256);
      for (let index = 0; index < chaseCount; index += 1) {
        const value = decodeScalar(buffer, type, index * width);
        if (value === null) break;
        const hops: MemoryChaseHop[] = [];
        let current = value;
        let leafString: string | null = null;
        for (let depth = 0; depth < MEMORY_MAX_CHASE_DEPTH; depth += 1) {
          if (current < bounds.imageBase || current >= bounds.imageEnd) break;
          const hopRva = current - bounds.imageBase;
          const hopSection = sectionForRva(tables.sections, hopRva);
          const hopSymbol = lookupSymbol(symbolIndex, current);
          const resolved = rvaToFileOffset(tables.sections, hopRva);
          let nextValue: number | null = null;
          if (resolved !== null && resolved + 8 <= stats.size) {
            const { bytesRead } = await handle.read(probe, 0, 8, resolved);
            if (bytesRead === 8) {
              nextValue = tables.bits === 64 ? Number(probe.readBigUInt64LE(0)) : probe.readUInt32LE(0);
            }
            const { bytesRead: scanned } = await handle.read(scan, 0, 256, resolved);
            const text = readAsciiZ(scan.subarray(0, scanned), 0, 128);
            if (text.value.length >= 3 && /^[\x20-\x7e]+$/.test(text.value)) {
              leafString = text.value;
            }
          }
          hops.push({
            va: `0x${current.toString(16)}`,
            value: nextValue === null ? "unreadable" : `0x${nextValue.toString(16)}`,
            section: hopSection === null ? null : hopSection.name,
            symbol: hopSymbol === null ? null : hopSymbol.name,
            note: hopSymbol === null ? null : hopSymbol.comment ?? null,
          });
          if (nextValue === null) break;
          current = nextValue;
        }
        if (hops.length > 0) {
          pointers.push({ from: `0x${value.toString(16)}`, hops, leafString });
        }
      }
    } finally {
      await handle.close();
    }
  }

  if (options.chasePointers === true && type !== "u32" && type !== "u64") {
    notes.push("chasePointers applies to type u32/u64 decodes only");
  }
  if (rva !== null && tables.bits !== null && vaNumber !== null && vaNumber > 0xffffffff && tables.bits === 32) {
    notes.push("PE declares 32-bit but the VA exceeds 32 bits — check the image base");
  }
  next.push(`binary_search (kind bytes, needle ${(buffer.subarray(0, 8).toString("hex") || "…")}) finds xrefs to this data`);
  if (symbol === null && vaNumber !== null) {
    next.push(`annotate.symbol (va 0x${vaNumber.toString(16)}) names this address for every later hit`);
  }

  return {
    mode: "file",
    path: path.relative(workspace.root, absolutePath).split(path.sep).join("/"),
    sessionId: "",
    debugger: "",
    address: {
      input,
      kind,
      fileOffset,
      rva,
      va: hex(vaNumber),
      section: section === null ? null : section.name,
      symbol: symbol === null ? null : symbol.name,
      symbolComment: symbol === null ? null : symbol.comment ?? null,
    },
    requestedBytes: requested,
    readBytes: buffer.length,
    truncated: buffer.length < requested,
    hexdump: dump.text,
    hexdumpTruncated: dump.truncated,
    bytesHex: buffer.length <= MEMORY_MAX_INLINE_BYTES ? buffer.toString("hex") : null,
    ascii: printableAscii(buffer),
    decode: decode ?? emptyDecode(),
    pointers,
    notes,
    next,
  };
}

function emptyDecode(): MemoryReadResult["decode"] {
  return { type: "none", elements: 0, values: [], truncated: false, fullValues: null };
}

function decodeWindow(buffer: Buffer, type: MemoryDecodeType, elements: number): MemoryReadResult["decode"] {
  const values: Array<string | number> = [];
  let truncated = false;
  if (type === "cstr" || type === "utf16") {
    let position = 0;
    while (position < buffer.length && values.length < elements) {
      const text = type === "cstr" ? readAsciiZ(buffer, position, 512) : readUtf16Z(buffer, position, 1024);
      if (text.consumed <= 0) break;
      values.push(text.value);
      position += text.consumed;
    }
    truncated = values.length >= elements && position < buffer.length;
  } else {
    const width = SCALAR_TYPES[type] ?? 1;
    for (let index = 0; index < elements; index += 1) {
      const value = decodeScalar(buffer, type, index * width);
      if (value === null) {
        truncated = index * width < buffer.length;
        break;
      }
      values.push(formatScalar(type, value));
      if (index * width + width >= buffer.length) break;
    }
  }
  const inline = values.slice(0, MEMORY_MAX_INLINE_ELEMENTS);
  return {
    type,
    elements,
    values: inline,
    truncated: truncated || values.length > inline.length,
    fullValues: null,
  };
}

