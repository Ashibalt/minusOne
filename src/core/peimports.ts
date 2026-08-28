/**
 * Native PE structure parser: section table, import table, export table,
 * and the offset↔RVA mapping between them. Purely static, bounded, no
 * external tools — the substrate for cross-plane operations (binary.find,
 * binary.triage, binary.search) that need to say "this string lives in
 * .rdata of this image at this VA" without spawning a disassembler.
 * Malformed tables degrade to partial results (recorded in `partial`)
 * instead of throwing.
 *
 * Parsing is RANDOM-ACCESS: the header buffer yields the section table,
 * then import/export structures are read through positioned reads at the
 * exact file offsets their RVAs map to (windowed 64KB read cache). A
 * multi-hundred-MB image parses its tables without loading the file —
 * no "first 64MB" truncation.
 */
import { open, stat } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import type { Workspace } from "./workspace.js";

const MAX_IMPORT_DLLS = 256;
const MAX_IMPORTS_PER_DLL = 4096;
const MAX_TOTAL_IMPORTS = 16384;
const MAX_EXPORT_NAMES = 8192;
const MAX_NAME_CHARS = 512;
const HEADER_READ_BYTES = 8192;
const READER_WINDOW_BYTES = 64 * 1024;
const READER_MAX_WINDOWS = 64;

const PE_MACHINES: Record<number, string> = {
  0x014c: "x86",
  0x01c0: "arm",
  0x01c4: "armv7",
  0x8664: "x86_64",
  0xaa64: "aarch64",
};

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  pointerToRawData: number;
  rawSize: number;
  characteristics: number;
}

export interface PeImportEntry {
  dll: string;
  name: string;
  ordinal: number | null;
  /** File offset of the imported name string (null for ordinal imports). */
  nameOffset: number | null;
  /** Virtual address of the IAT slot for this import. */
  iatVa: number;
}

export interface PeExportEntry {
  name: string;
  ordinal: number;
  functionRva: number | null;
  va: number | null;
  nameOffset: number | null;
}

export interface PeTables {
  machine: string;
  bits: 32 | 64 | null;
  imageBase: number;
  entrypointRva: number | null;
  /** COFF characteristics (IMAGE_FILE_* flags; 0x2000 = DLL). */
  characteristics: number;
  sections: PeSection[];
  imports: PeImportEntry[];
  importDlls: string[];
  exportDll: string | null;
  exports: PeExportEntry[];
  /** Degradation notes: why a table is empty or truncated. */
  partial: string[];
}

/**
 * Positioned reader over a binary: reads little-endian integers and
 * NUL-terminated ASCII at absolute file offsets, null when out of range.
 * Two backends: an in-memory buffer and a windowed positioned-read cache
 * over an open file handle.
 */
interface OffsetReader {
  u32(offset: number): Promise<number | null>;
  u16(offset: number): Promise<number | null>;
  asciiZ(offset: number, limit?: number): Promise<string | null>;
}

function createBufferReader(buffer: Buffer): OffsetReader {
  return {
    u32: (offset) => Promise.resolve(offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : null),
    u16: (offset) => Promise.resolve(offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : null),
    asciiZ: (offset, limit = MAX_NAME_CHARS) =>
      Promise.resolve(offset < 0 || offset >= buffer.length ? null : readAsciiZFromBuffer(buffer, offset, limit)),
  };
}

function readAsciiZFromBuffer(buffer: Buffer, offset: number, limit: number): string | null {
  let end = offset;
  while (end < buffer.length && end - offset < limit && buffer[end] !== 0) end += 1;
  return buffer.toString("ascii", offset, end);
}

/**
 * File-backed reader with an aligned 64KB window cache. Import/export
 * structures cluster (same sections), so a handful of windows cover an
 * entire table walk; a FIFO cap bounds memory. Reads that straddle a
 * window edge fall back to one direct positioned read.
 */
function createFileReader(handle: FileHandle): OffsetReader {
  const windows = new Map<number, Buffer>();
  const order: number[] = [];

  async function windowAt(windowStart: number): Promise<Buffer> {
    const cached = windows.get(windowStart);
    if (cached !== undefined) return cached;
    const buffer = Buffer.alloc(READER_WINDOW_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, READER_WINDOW_BYTES, windowStart);
    const window = bytesRead === READER_WINDOW_BYTES ? buffer : buffer.subarray(0, bytesRead);
    windows.set(windowStart, window);
    order.push(windowStart);
    if (order.length > READER_MAX_WINDOWS) {
      const evict = order.shift();
      if (evict !== undefined) windows.delete(evict);
    }
    return window;
  }

  async function readDirect(offset: number, length: number): Promise<Buffer | null> {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, offset);
    return bytesRead === length ? buffer : bytesRead > 0 ? buffer.subarray(0, bytesRead) : null;
  }

  return {
    async u32(offset) {
      if (offset < 0) return null;
      const windowStart = Math.floor(offset / READER_WINDOW_BYTES) * READER_WINDOW_BYTES;
      const window = await windowAt(windowStart);
      const rel = offset - windowStart;
      if (rel + 4 <= window.length) return window.readUInt32LE(rel);
      const direct = await readDirect(offset, 4);
      return direct !== null && direct.length === 4 ? direct.readUInt32LE(0) : null;
    },
    async u16(offset) {
      if (offset < 0) return null;
      const windowStart = Math.floor(offset / READER_WINDOW_BYTES) * READER_WINDOW_BYTES;
      const window = await windowAt(windowStart);
      const rel = offset - windowStart;
      if (rel + 2 <= window.length) return window.readUInt16LE(rel);
      const direct = await readDirect(offset, 2);
      return direct !== null && direct.length === 2 ? direct.readUInt16LE(0) : null;
    },
    async asciiZ(offset, limit = MAX_NAME_CHARS) {
      if (offset < 0) return null;
      const windowStart = Math.floor(offset / READER_WINDOW_BYTES) * READER_WINDOW_BYTES;
      const window = await windowAt(windowStart);
      const rel = offset - windowStart;
      // NUL usually lands inside the same window; only long tails cross it.
      const nulInWindow = window.indexOf(0, rel);
      if (nulInWindow !== -1 && nulInWindow - rel < limit) {
        return window.toString("ascii", rel, nulInWindow);
      }
      const direct = await readDirect(offset, limit + 1);
      if (direct === null) return window.length > rel ? window.toString("ascii", rel) : null;
      let end = 0;
      while (end < direct.length && direct[end] !== 0) end += 1;
      return direct.toString("ascii", 0, end);
    },
  };
}

function sectionName(buffer: Buffer, offset: number): string {
  const raw = buffer.toString("ascii", offset, offset + 8);
  return raw.replace(/[\0 ]+$/, "");
}

/** Map an RVA to a file offset through the section table; null when unmapped. */
export function rvaToFileOffset(sections: PeSection[], rva: number): number | null {
  for (const section of sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      const delta = rva - section.virtualAddress;
      if (delta < section.rawSize && section.pointerToRawData + delta < Number.MAX_SAFE_INTEGER) {
        return section.pointerToRawData + delta;
      }
      return null;
    }
  }
  return null;
}

/** Map a file offset back to an RVA; null when the offset is not in any section. */
export function fileOffsetToRva(sections: PeSection[], offset: number): number | null {
  for (const section of sections) {
    if (offset >= section.pointerToRawData && offset < section.pointerToRawData + section.rawSize) {
      return section.virtualAddress + (offset - section.pointerToRawData);
    }
  }
  return null;
}

export function sectionForFileOffset(sections: PeSection[], offset: number): PeSection | null {
  for (const section of sections) {
    if (offset >= section.pointerToRawData && offset < section.pointerToRawData + section.rawSize) {
      return section;
    }
  }
  return null;
}

export function sectionForRva(sections: PeSection[], rva: number): PeSection | null {
  const offset = rvaToFileOffset(sections, rva);
  return offset === null ? null : sectionForFileOffset(sections, offset);
}

async function parseImports(reader: OffsetReader, sections: PeSection[], importDirRva: number, bits: 32 | 64 | null, imageBase: number, partial: string[]): Promise<{ imports: PeImportEntry[]; dlls: string[] }> {
  const imports: PeImportEntry[] = [];
  const dlls: string[] = [];
  const entrySize = bits === 64 ? 8 : 4;

  let descriptorOffset = rvaToFileOffset(sections, importDirRva);
  if (descriptorOffset === null) {
    partial.push("import directory RVA does not map into any section (unmapped or virtual-only imports)");
    return { imports, dlls };
  }

  for (let descriptor = 0; descriptor < MAX_IMPORT_DLLS; descriptor += 1) {
    const base = descriptorOffset + descriptor * 20;
    const fields = await Promise.all([reader.u32(base), reader.u32(base + 12), reader.u32(base + 16)]);
    if (fields.some((value) => value === null)) {
      partial.push("import descriptor table ran past the end of the file");
      break;
    }
    const [originalFirstThunk, nameRva, firstThunk] = fields as [number, number, number];
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

    const dll = (await reader.asciiZ(rvaToFileOffset(sections, nameRva) ?? -1)) ?? "";
    if (dll === "") {
      partial.push(`import descriptor #${descriptor} has an unreadable DLL name`);
      continue;
    }
    dlls.push(dll);

    const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
    for (let index = 0; index < MAX_IMPORTS_PER_DLL; index += 1) {
      if (imports.length >= MAX_TOTAL_IMPORTS) {
        partial.push(`import list capped at ${MAX_TOTAL_IMPORTS} entries`);
        break;
      }
      const thunkOffset = rvaToFileOffset(sections, thunkRva + index * entrySize);
      if (thunkOffset === null) break;
      let isOrdinal = false;
      let nameRva2 = 0;
      let ordinal: number | null = null;
      if (entrySize === 8) {
        const low = await reader.u32(thunkOffset);
        const high = await reader.u32(thunkOffset + 4);
        if (low === null || high === null) break;
        if ((high & 0x80000000) !== 0) {
          isOrdinal = true;
          ordinal = low & 0xffff;
        } else if ((high & 0x7fffffff) !== 0) {
          break;
        } else {
          nameRva2 = low;
        }
      } else {
        const entry = await reader.u32(thunkOffset);
        if (entry === null) break;
        if (entry === 0) break;
        if ((entry & 0x80000000) !== 0) {
          isOrdinal = true;
          ordinal = entry & 0xffff;
        } else {
          nameRva2 = entry & 0x7fffffff;
        }
      }
      if (!isOrdinal && nameRva2 === 0) break;

      if (isOrdinal) {
        imports.push({ dll, name: `#${ordinal}`, ordinal, nameOffset: null, iatVa: imageBase + firstThunk + index * entrySize });
        continue;
      }
      const nameOffset = rvaToFileOffset(sections, nameRva2);
      if (nameOffset === null) break;
      const name = await reader.asciiZ(nameOffset + 2);
      if (name === null || name === "") break;
      imports.push({
        dll,
        name,
        ordinal: null,
        nameOffset: nameOffset + 2,
        iatVa: imageBase + firstThunk + index * entrySize,
      });
    }
  }
  return { imports, dlls };
}

async function parseExports(reader: OffsetReader, sections: PeSection[], exportDirRva: number, imageBase: number, partial: string[]): Promise<{ dll: string | null; exports: PeExportEntry[] }> {
  const directoryOffset = rvaToFileOffset(sections, exportDirRva);
  if (directoryOffset === null) {
    partial.push("export directory RVA does not map into any section");
    return { dll: null, exports: [] };
  }
  const fields = await Promise.all([
    reader.u32(directoryOffset + 12),
    reader.u32(directoryOffset + 16),
    reader.u32(directoryOffset + 20),
    reader.u32(directoryOffset + 24),
    reader.u32(directoryOffset + 28),
    reader.u32(directoryOffset + 32),
    reader.u32(directoryOffset + 36),
  ]);
  const [nameRva, ordinalBase, numberOfFunctions, numberOfNames, addressOfFunctions, addressOfNames, addressOfNameOrdinals] = fields;
  if (fields.some((value) => value === null)) {
    partial.push("export directory header ran past the end of the file");
    return { dll: null, exports: [] };
  }

  const dll = await reader.asciiZ(rvaToFileOffset(sections, nameRva as number) ?? -1);
  const exports: PeExportEntry[] = [];
  const capped = (numberOfNames as number) > MAX_EXPORT_NAMES;
  const count = Math.min(numberOfNames as number, MAX_EXPORT_NAMES);
  if (capped) partial.push(`export name table capped at ${MAX_EXPORT_NAMES} of ${numberOfNames} entries`);

  for (let index = 0; index < count; index += 1) {
    const entryNameRva = await reader.u32(rvaToFileOffset(sections, (addressOfNames as number) + index * 4) ?? -1);
    const entryOrdinal = await reader.u16(rvaToFileOffset(sections, (addressOfNameOrdinals as number) + index * 2) ?? -1);
    if (entryNameRva === null || entryOrdinal === null) break;
    const nameOffset = rvaToFileOffset(sections, entryNameRva);
    const name = nameOffset === null ? null : await reader.asciiZ(nameOffset);
    if (name === null || name === "") continue;

    let functionRva: number | null = null;
    if (entryOrdinal < (numberOfFunctions as number)) {
      functionRva = await reader.u32(rvaToFileOffset(sections, (addressOfFunctions as number) + entryOrdinal * 4) ?? -1);
    }
    exports.push({
      name,
      ordinal: (ordinalBase as number) + entryOrdinal,
      functionRva,
      va: functionRva === null ? null : imageBase + functionRva,
      nameOffset,
    });
  }
  return { dll: dll ?? null, exports };
}

interface PeHeaders {
  machine: string;
  bits: 32 | 64 | null;
  imageBase: number;
  entrypointRva: number | null;
  characteristics: number;
  sections: PeSection[];
  exportDirRva: number;
  importDirRva: number;
  partial: string[];
}

/** Headers + section table from a lead buffer; null when the buffer is not a PE. */
function parsePeHeadersFromBuffer(buffer: Buffer): PeHeaders | null {
  if (buffer.length < 0x100 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null;
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset === null || peOffset + 26 > buffer.length) return null;
  if (buffer.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") return null;

  const machine = buffer.readUInt16LE(peOffset + 4);
  const numberOfSections = Math.min(buffer.readUInt16LE(peOffset + 6), 96);
  const characteristics = buffer.readUInt16LE(peOffset + 22);
  const sizeOfOptionalHeader = buffer.readUInt16LE(peOffset + 20);
  const optionalHeaderOffset = peOffset + 24;
  if (optionalHeaderOffset + 2 > buffer.length) return null;
  const optionalMagic = buffer.readUInt16LE(optionalHeaderOffset);
  const bits: 32 | 64 | null = optionalMagic === 0x10b ? 32 : optionalMagic === 0x20b ? 64 : null;
  const partial: string[] = [];

  let imageBase = 0;
  if (bits === 64) {
    const low = optionalHeaderOffset + 24 + 4 <= buffer.length ? buffer.readUInt32LE(optionalHeaderOffset + 24) : null;
    const high = optionalHeaderOffset + 28 + 4 <= buffer.length ? buffer.readUInt32LE(optionalHeaderOffset + 28) : null;
    if (low !== null && high !== null) imageBase = high * 0x1_0000_0000 + low;
  } else if (bits === 32) {
    imageBase = optionalHeaderOffset + 28 + 4 <= buffer.length ? buffer.readUInt32LE(optionalHeaderOffset + 28) : 0;
  } else {
    partial.push("unknown optional-header magic; image base is 0");
  }
  const entrypointRva = optionalHeaderOffset + 16 + 4 <= buffer.length ? buffer.readUInt32LE(optionalHeaderOffset + 16) : null;

  const sections: PeSection[] = [];
  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  for (let index = 0; index < numberOfSections; index += 1) {
    const entryOffset = sectionTableOffset + index * 40;
    const enough = (field: number) => entryOffset + field + 4 <= buffer.length;
    if (!enough(8) || !enough(12) || !enough(16) || !enough(20) || !enough(36)) {
      partial.push(`section #${index} header ran past the end of the file`);
      break;
    }
    sections.push({
      name: sectionName(buffer, entryOffset),
      virtualAddress: buffer.readUInt32LE(entryOffset + 12),
      virtualSize: buffer.readUInt32LE(entryOffset + 8),
      rawSize: buffer.readUInt32LE(entryOffset + 16),
      pointerToRawData: buffer.readUInt32LE(entryOffset + 20),
      characteristics: buffer.readUInt32LE(entryOffset + 36),
    });
  }

  const directoriesOffset = optionalHeaderOffset + (bits === 64 ? 112 : 96);
  const dirField = (delta: number) => directoriesOffset + delta + 4 <= buffer.length ? buffer.readUInt32LE(directoriesOffset + delta) : 0;
  const exportDirRva = dirField(0);
  const importDirRva = dirField(8);
  if (sections.length === 0) partial.push("no sections parsed from the section table");

  return {
    machine: PE_MACHINES[machine] ?? `pe-machine-0x${machine.toString(16)}`,
    bits,
    imageBase,
    entrypointRva,
    characteristics,
    sections,
    exportDirRva,
    importDirRva,
    partial,
  };
}

/** Parse PE tables from an in-memory buffer; null when the buffer is not a PE. */
export async function parsePeTablesFromBuffer(buffer: Buffer): Promise<PeTables | null> {
  const headers = parsePeHeadersFromBuffer(buffer);
  if (headers === null) return null;
  const reader = createBufferReader(buffer);
  return await finishTables(headers, reader);
}

async function finishTables(headers: PeHeaders, reader: OffsetReader): Promise<PeTables> {
  const parsedImports = headers.importDirRva !== 0
    ? await parseImports(reader, headers.sections, headers.importDirRva, headers.bits, headers.imageBase, headers.partial)
    : { imports: [], dlls: [] };
  const parsedExports = headers.exportDirRva !== 0
    ? await parseExports(reader, headers.sections, headers.exportDirRva, headers.imageBase, headers.partial)
    : { dll: null, exports: [] };

  return {
    machine: headers.machine,
    bits: headers.bits,
    imageBase: headers.imageBase,
    entrypointRva: headers.entrypointRva,
    characteristics: headers.characteristics,
    sections: headers.sections,
    imports: parsedImports.imports,
    importDlls: parsedImports.dlls,
    exportDll: parsedExports.dll,
    exports: parsedExports.exports,
    partial: headers.partial,
  };
}

/**
 * Parse PE tables from a file by absolute path using positioned reads —
 * the file is never loaded whole, so images of any size parse completely.
 * Null when the file is not a PE.
 */
export async function parsePeTablesFromPath(absolutePath: string): Promise<PeTables | null> {
  const handle = await open(absolutePath, "r");
  try {
    const headerBuffer = Buffer.alloc(HEADER_READ_BYTES);
    const { bytesRead } = await handle.read(headerBuffer, 0, HEADER_READ_BYTES, 0);
    const headers = parsePeHeadersFromBuffer(bytesRead === HEADER_READ_BYTES ? headerBuffer : headerBuffer.subarray(0, bytesRead));
    if (headers === null) return null;
    return await finishTables(headers, createFileReader(handle));
  } finally {
    await handle.close();
  }
}

/** Resolve a workspace file and parse its PE tables; null when not a PE. */
export async function parsePeTables(workspace: Workspace, userPath: string): Promise<PeTables | null> {
  const absolutePath = await workspace.resolveFile(userPath);
  return await parsePeTablesFromPath(absolutePath);
}
