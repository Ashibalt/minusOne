import { open, stat } from "node:fs/promises";
import type { ExtractedString, StringExtractionResult } from "./types.js";
import type { Workspace } from "./workspace.js";

export interface StringExtractionOptions {
  minLength?: number;
  limit?: number;
  maxScanBytes?: number;
}

function isPrintableAscii(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

function extractAscii(buffer: Buffer, minLength: number, output: ExtractedString[], limit: number): void {
  let start = -1;
  for (let index = 0; index <= buffer.length; index += 1) {
    const byte = buffer[index];
    if (byte !== undefined && isPrintableAscii(byte)) {
      if (start === -1) start = index;
      continue;
    }
    if (start !== -1 && index - start >= minLength && output.length < limit) {
      output.push({ offset: start, encoding: "ascii", value: buffer.toString("ascii", start, index) });
    }
    start = -1;
  }
}

function extractUtf16Le(buffer: Buffer, minLength: number, output: ExtractedString[], limit: number): void {
  for (const alignment of [0, 1]) {
    let start = -1;
    let chars = 0;
    for (let index = alignment; index + 1 <= buffer.length; index += 2) {
      const first = buffer[index];
      const second = buffer[index + 1];
      const printable = first !== undefined && second === 0 && isPrintableAscii(first);
      if (printable) {
        if (start === -1) start = index;
        chars += 1;
        continue;
      }
      if (start !== -1 && chars >= minLength && output.length < limit) {
        output.push({
          offset: start,
          encoding: "utf16le",
          value: buffer.toString("utf16le", start, start + chars * 2),
        });
      }
      start = -1;
      chars = 0;
    }
    if (start !== -1 && chars >= minLength && output.length < limit) {
      output.push({
        offset: start,
        encoding: "utf16le",
        value: buffer.toString("utf16le", start, start + chars * 2),
      });
    }
  }
}

export async function extractStrings(
  workspace: Workspace,
  userPath: string,
  options: StringExtractionOptions = {},
): Promise<StringExtractionResult> {
  const minLength = Math.min(Math.max(options.minLength ?? 5, 3), 128);
  // No upper caps: the owner raised them ("как угодно, без ограничений") —
  // the floor keeps nonsense values out, the file size bounds the read.
  const limit = Math.max(options.limit ?? 20_000, 1);
  const maxScanBytes = Math.max(options.maxScanBytes ?? 512 * 1024 * 1024, 1024);
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const scannedBytes = Math.min(fileStats.size, maxScanBytes);
  const buffer = Buffer.alloc(scannedBytes);
  const handle = await open(absolutePath, "r");
  try {
    if (scannedBytes > 0) await handle.read(buffer, 0, scannedBytes, 0);
  } finally {
    await handle.close();
  }

  const strings: ExtractedString[] = [];
  extractAscii(buffer, minLength, strings, limit);
  extractUtf16Le(buffer, minLength, strings, limit);
  strings.sort((left, right) => left.offset - right.offset || left.encoding.localeCompare(right.encoding));

  return {
    path: workspace.relative(absolutePath),
    scannedBytes,
    fileSize: fileStats.size,
    scanTruncated: scannedBytes < fileStats.size,
    resultTruncated: strings.length >= limit,
    strings,
  };
}
