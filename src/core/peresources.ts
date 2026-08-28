import { open, stat } from "node:fs/promises";
import { inspectBinary } from "./binary.js";
import type { Workspace } from "./workspace.js";

/**
 * Native PE resource parser: walks the .rsrc directory and extracts the
 * triage-relevant payloads — version information (VS_VERSION_INFO fixed
 * fields + StringFileInfo) and the application manifest. Purely static,
 * bounded, no external tools. Malformed resource trees degrade to partial
 * results rather than throwing.
 */
export const PE_RESOURCES_MAX_RSRC_BYTES = 8 * 1024 * 1024;
export const PE_RESOURCES_MAX_MANIFEST_CHARS = 16 * 1024;
const MAX_NODES = 4096;
const MAX_TYPES = 64;
const MAX_ENTRIES_PER_NODE = 512;
const MAX_VERSION_STRINGS = 64;
const MAX_STRING_CHARS = 1024;
const RT_VERSION = 16;
const RT_MANIFEST = 24;
const VS_FIXEDFILEINFO_SIGNATURE = 0xfeef04bd;

const TYPE_NAMES: Record<number, string> = {
  1: "cursor",
  2: "bitmap",
  3: "icon",
  4: "menu",
  5: "dialog",
  6: "string-table",
  10: "font-directory",
  11: "font",
  12: "accelerator",
  14: "group-icon",
  16: "version",
  24: "manifest",
};

export interface PeResourceTypeInfo {
  typeId: number;
  typeName: string | null;
  entryCount: number;
}

export interface PeVersionInfo {
  fileVersion: string;
  productVersion: string;
  fileOs: string;
  fileType: string;
  strings: Record<string, string>;
  translations: string[];
}

export interface PeResourcesReport {
  types: PeResourceTypeInfo[];
  versionInfo: PeVersionInfo | null;
  manifestPreview: string | null;
  manifestTruncated: boolean;
  truncated: boolean;
}

function align4(value: number): number {
  return (value + 3) & ~3;
}

/** Reads a NUL-terminated UTF-16LE string; returns [text, bytesConsumed]. */
function readWideString(buffer: Buffer, offset: number, limit: number): [string, number] | null {
  if (offset < 0 || offset >= limit) return null;
  for (let position = offset; position + 1 < limit; position += 2) {
    if (buffer.readUInt16LE(position) === 0) {
      const text = buffer.toString("utf16le", offset, position);
      return [text, position + 2 - offset];
    }
  }
  return null;
}

interface ResourceContext {
  buffer: Buffer;
  /** RVA that buffer offset 0 corresponds to (the resource directory RVA). */
  baseRva: number;
  nodesVisited: number;
  truncated: boolean;
}

interface DataEntry {
  offset: number;
  size: number;
}

function readDirectoryEntryName(context: ResourceContext, nameOrId: number): { id: number; name: string | null } {
  if ((nameOrId & 0x80000000) === 0) return { id: nameOrId, name: null };
  const nameOffset = nameOrId & 0x7fffffff;
  if (nameOffset + 2 > context.buffer.length) return { id: nameOrId, name: null };
  const length = context.buffer.readUInt16LE(nameOffset);
  const end = nameOffset + 2 + length * 2;
  if (end > context.buffer.length || length > 512) return { id: nameOrId, name: null };
  return { id: nameOrId, name: context.buffer.toString("utf16le", nameOffset + 2, end) };
}

function readDataEntry(context: ResourceContext, offset: number): DataEntry | null {
  if (offset < 0 || offset + 16 > context.buffer.length) return null;
  const dataRva = context.buffer.readUInt32LE(offset);
  const size = context.buffer.readUInt32LE(offset + 4);
  const dataOffset = dataRva - context.baseRva;
  if (dataOffset < 0 || size > context.buffer.length - dataOffset) return null;
  return { offset: dataOffset, size };
}

/** Depth-first walk of one directory node; depth 0 is the type level. */
function walkDirectory(
  context: ResourceContext,
  directoryOffset: number,
  depth: number,
  typeId: number | null,
  sink: {
    types: Map<number, { name: string | null; entries: number }>;
    versionPayloads: DataEntry[];
    manifestPayloads: DataEntry[];
  },
): void {
  if (context.nodesVisited >= MAX_NODES) {
    context.truncated = true;
    return;
  }
  context.nodesVisited += 1;
  const buffer = context.buffer;
  if (directoryOffset < 0 || directoryOffset + 16 > buffer.length) return;
  const namedEntries = buffer.readUInt16LE(directoryOffset + 12);
  const idEntries = buffer.readUInt16LE(directoryOffset + 14);
  const totalEntries = namedEntries + idEntries;
  if (totalEntries > MAX_ENTRIES_PER_NODE) {
    context.truncated = true;
    return;
  }
  let cursor = directoryOffset + 16;
  for (let index = 0; index < totalEntries; index += 1) {
    if (cursor + 8 > buffer.length) {
      context.truncated = true;
      return;
    }
    const nameOrId = buffer.readUInt32LE(cursor);
    const offsetToData = buffer.readUInt32LE(cursor + 4);
    cursor += 8;

    let entryTypeId = typeId;
    if (depth === 0) {
      const named = readDirectoryEntryName(context, nameOrId);
      entryTypeId = named.id & 0x7fffffff;
      if (sink.types.size < MAX_TYPES) {
        const record = sink.types.get(entryTypeId) ?? { name: named.name, entries: 0 };
        sink.types.set(entryTypeId, record);
      }
    }

    if ((offsetToData & 0x80000000) !== 0) {
      walkDirectory(context, offsetToData & 0x7fffffff, depth + 1, entryTypeId, sink);
      continue;
    }
    const data = readDataEntry(context, offsetToData);
    if (data === null) continue;
    if (depth >= 2 && entryTypeId !== null) {
      const record = sink.types.get(entryTypeId);
      if (record !== undefined) record.entries += 1;
      if (entryTypeId === RT_VERSION && sink.versionPayloads.length < 4) sink.versionPayloads.push(data);
      if (entryTypeId === RT_MANIFEST && sink.manifestPayloads.length < 4) sink.manifestPayloads.push(data);
    }
  }
}

function quadVersion(high: number, low: number): string {
  return `${(high >>> 16) & 0xffff}.${high & 0xffff}.${(low >>> 16) & 0xffff}.${low & 0xffff}`;
}

function parseVersionStrings(context: ResourceContext, block: Buffer, into: Record<string, string>): void {
  // StringFileInfo block: children are language blocks, whose children are
  // key/value String entries.
  const blockLength = Math.min(block.readUInt16LE(0), block.length);
  const header = readWideString(block, 6, blockLength);
  if (header === null) return;
  let cursor = align4(6 + header[1]);
  while (cursor + 6 <= blockLength && Object.keys(into).length < MAX_VERSION_STRINGS) {
    const entryLength = block.readUInt16LE(cursor);
    const valueWords = block.readUInt16LE(cursor + 2);
    if (entryLength < 6 || cursor + entryLength > blockLength) return;
    const key = readWideString(block, cursor + 6, cursor + entryLength);
    if (key === null) return;
    const valueOffset = align4(cursor + 6 + key[1]);
    const valueEnd = Math.min(valueOffset + valueWords * 2, cursor + entryLength, block.length);
    const value = valueEnd > valueOffset ? block.toString("utf16le", valueOffset, valueEnd).replace(/\0+$/, "") : "";
    if (key[0] !== "" && Object.keys(into).length < MAX_VERSION_STRINGS) {
      into[key[0]] = value.slice(0, MAX_STRING_CHARS);
    }
    cursor += align4(entryLength) || 4;
  }
}

function parseVersionInfo(context: ResourceContext, data: DataEntry): PeVersionInfo | null {
  const buffer = context.buffer;
  const start = data.offset;
  const end = Math.min(start + data.size, buffer.length);
  if (end - start < 6) return null;
  const rootLength = Math.min(buffer.readUInt16LE(start), end - start);
  const valueLength = buffer.readUInt16LE(start + 2);
  const key = readWideString(buffer, start + 6, start + rootLength);
  if (key === null || key[0] !== "VS_VERSION_INFO") return null;

  let fileVersion = "";
  let productVersion = "";
  let fileOs = "";
  let fileType = "";
  let cursor = align4(start + 6 + key[1]);
  if (valueLength >= 52 && cursor + 52 <= start + rootLength && buffer.readUInt32LE(cursor) === VS_FIXEDFILEINFO_SIGNATURE) {
    fileVersion = quadVersion(buffer.readUInt32LE(cursor + 8), buffer.readUInt32LE(cursor + 12));
    productVersion = quadVersion(buffer.readUInt32LE(cursor + 16), buffer.readUInt32LE(cursor + 20));
    fileOs = `0x${buffer.readUInt32LE(cursor + 32).toString(16)}`;
    fileType = `0x${buffer.readUInt32LE(cursor + 36).toString(16)}`;
    cursor += valueLength;
  }
  cursor = align4(cursor);

  const strings: Record<string, string> = {};
  const translations: string[] = [];
  while (cursor + 6 <= start + rootLength) {
    const childLength = buffer.readUInt16LE(cursor);
    const childValueLength = buffer.readUInt16LE(cursor + 2);
    if (childLength < 6 || cursor + childLength > start + rootLength) break;
    const childKey = readWideString(buffer, cursor + 6, cursor + childLength);
    if (childKey === null) break;
    const childValueOffset = align4(cursor + 6 + childKey[1]);
    if (childKey[0] === "StringFileInfo") {
      const blockEnd = Math.min(cursor + childLength, end);
      let blockCursor = childValueOffset;
      while (blockCursor + 6 <= blockEnd) {
        const langLength = buffer.readUInt16LE(blockCursor);
        if (langLength < 6 || blockCursor + langLength > blockEnd) break;
        parseVersionStrings(
          context,
          buffer.subarray(blockCursor, Math.min(blockCursor + langLength, buffer.length)),
          strings,
        );
        blockCursor += align4(langLength) || 4;
      }
    } else if (childKey[0] === "VarFileInfo") {
      // VarFileInfo holds a "Translation" child whose value is an array of
      // language:codepage DWORDs.
      const blockEnd = Math.min(cursor + childLength, end);
      let blockCursor = childValueOffset;
      while (blockCursor + 6 <= blockEnd && translations.length < 32) {
        const entryLength = buffer.readUInt16LE(blockCursor);
        if (entryLength < 6 || blockCursor + entryLength > blockEnd) break;
        const entryKey = readWideString(buffer, blockCursor + 6, blockCursor + entryLength);
        if (entryKey === null) break;
        if (entryKey[0] === "Translation") {
          const valueOffset = align4(blockCursor + 6 + entryKey[1]);
          for (let position = valueOffset; position + 4 <= blockCursor + entryLength && position + 4 <= buffer.length; position += 4) {
            const value = buffer.readUInt32LE(position);
            translations.push(`0x${(value & 0xffff).toString(16).padStart(4, "0")}:0x${((value >>> 16) & 0xffff).toString(16)}`);
            if (translations.length >= 32) break;
          }
        }
        blockCursor += align4(entryLength) || 4;
      }
    }
    cursor += align4(childLength) || 4;
  }

  return { fileVersion, productVersion, fileOs, fileType, strings, translations };
}

export async function parsePeResources(workspace: Workspace, userPath: string): Promise<PeResourcesReport> {
  const binary = await inspectBinary(workspace, userPath);
  if (binary.format.kind !== "pe") {
    throw new Error(`pe.resources requires a PE file (detected format: ${binary.format.kind})`);
  }
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const headerSize = Math.min(fileStats.size, 8192);
  const handle = await open(absolutePath, "r");
  const header = Buffer.alloc(headerSize);
  try {
    await handle.read(header, 0, headerSize, 0);
    const peOffset = header.readUInt32LE(0x3c);
    const optionalHeaderOffset = peOffset + 24;
    const optionalMagic = header.readUInt16LE(optionalHeaderOffset);
    const isPe32Plus = optionalMagic === 0x20b;
    const numberOfRvasAndSizes = header.readUInt32LE(optionalHeaderOffset + (isPe32Plus ? 108 : 92));
    if (numberOfRvasAndSizes <= 2) throw new Error("PE optional header has no resource data directory");
    const directoryTableOffset = optionalHeaderOffset + (isPe32Plus ? 112 : 96);
    const rsrcRva = header.readUInt32LE(directoryTableOffset + 16);
    const rsrcDirectorySize = header.readUInt32LE(directoryTableOffset + 20);
    if (rsrcRva === 0 || rsrcDirectorySize === 0) {
      return { types: [], versionInfo: null, manifestPreview: null, manifestTruncated: false, truncated: false };
    }

    const numberOfSections = header.readUInt16LE(peOffset + 6);
    const sizeOfOptionalHeader = header.readUInt16LE(peOffset + 20);
    const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
    let section: { virtualAddress: number; pointerToRawData: number; rawSize: number } | null = null;
    for (let index = 0; index < numberOfSections; index += 1) {
      const entryOffset = sectionTableOffset + index * 40;
      if (entryOffset + 40 > header.length) break;
      const virtualAddress = header.readUInt32LE(entryOffset + 12);
      const virtualSize = Math.max(header.readUInt32LE(entryOffset + 8), 1);
      if (rsrcRva >= virtualAddress && rsrcRva < virtualAddress + virtualSize) {
        section = {
          virtualAddress,
          pointerToRawData: header.readUInt32LE(entryOffset + 20),
          rawSize: header.readUInt32LE(entryOffset + 16),
        };
        break;
      }
    }
    if (section === null) throw new Error("PE resource directory RVA does not fall inside any section");

    const inSectionOffset = section.pointerToRawData + (rsrcRva - section.virtualAddress);
    const available = Math.max(section.rawSize - (rsrcRva - section.virtualAddress), 0);
    const readBytes = Math.min(rsrcDirectorySize, available, PE_RESOURCES_MAX_RSRC_BYTES, fileStats.size - inSectionOffset);
    if (readBytes <= 0) throw new Error("PE resource section has no raw data");
    const truncatedByCap = rsrcDirectorySize > readBytes;
    const rsrc = Buffer.alloc(readBytes);
    await handle.read(rsrc, 0, readBytes, inSectionOffset);

    const context: ResourceContext = { buffer: rsrc, baseRva: rsrcRva, nodesVisited: 0, truncated: truncatedByCap };
    const sink: {
      types: Map<number, { name: string | null; entries: number }>;
      versionPayloads: DataEntry[];
      manifestPayloads: DataEntry[];
    } = { types: new Map(), versionPayloads: [], manifestPayloads: [] };
    walkDirectory(context, 0, 0, null, sink);

    let versionInfo: PeVersionInfo | null = null;
    for (const payload of sink.versionPayloads) {
      versionInfo = parseVersionInfo(context, payload);
      if (versionInfo !== null) break;
    }
    let manifestPreview: string | null = null;
    let manifestTruncated = false;
    const manifestPayload = sink.manifestPayloads[0];
    if (manifestPayload !== undefined) {
      const raw = context.buffer.toString("utf8", manifestPayload.offset, manifestPayload.offset + manifestPayload.size);
      manifestPreview = raw.slice(0, PE_RESOURCES_MAX_MANIFEST_CHARS);
      manifestTruncated = raw.length > PE_RESOURCES_MAX_MANIFEST_CHARS;
    }

    const types = [...sink.types.entries()]
      .sort(([left], [right]) => left - right)
      .map(([typeId, record]) => ({
        typeId,
        typeName: record.name ?? TYPE_NAMES[typeId] ?? null,
        entryCount: record.entries,
      }));
    return { types, versionInfo, manifestPreview, manifestTruncated, truncated: context.truncated };
  } finally {
    await handle.close();
  }
}
