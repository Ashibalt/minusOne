import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import type { BinaryFormat, BinaryInfo, Endianness } from "./types.js";
import type { Workspace } from "./workspace.js";

const ELF_MACHINES: Record<number, string> = {
  3: "x86",
  8: "mips",
  20: "powerpc",
  40: "arm",
  62: "x86_64",
  183: "aarch64",
  243: "riscv",
};

const PE_MACHINES: Record<number, string> = {
  0x014c: "x86",
  0x01c0: "arm",
  0x01c4: "armv7",
  0x8664: "x86_64",
  0xaa64: "aarch64",
};

function readUInt16(buffer: Buffer, offset: number, endianness: Endianness): number | null {
  if (offset + 2 > buffer.length || endianness === "unknown") return null;
  return endianness === "little" ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function detectElf(buffer: Buffer): BinaryFormat | null {
  if (buffer.length < 20 || !buffer.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    return null;
  }

  const bits = buffer[4] === 1 ? 32 : buffer[4] === 2 ? 64 : null;
  const endianness: Endianness = buffer[5] === 1 ? "little" : buffer[5] === 2 ? "big" : "unknown";
  const machine = readUInt16(buffer, 18, endianness);
  return {
    kind: "elf",
    architecture: machine === null ? "unknown" : (ELF_MACHINES[machine] ?? `elf-machine-${machine}`),
    bits,
    endianness,
  };
}

function detectPe(buffer: Buffer): BinaryFormat | null {
  if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null;
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 26 > buffer.length || buffer.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") {
    return null;
  }

  const machine = buffer.readUInt16LE(peOffset + 4);
  const optionalMagic = buffer.readUInt16LE(peOffset + 24);
  const bits = optionalMagic === 0x10b ? 32 : optionalMagic === 0x20b ? 64 : null;
  return {
    kind: "pe",
    architecture: PE_MACHINES[machine] ?? `pe-machine-0x${machine.toString(16)}`,
    bits,
    endianness: "little",
  };
}

function detectMachO(buffer: Buffer): BinaryFormat | null {
  if (buffer.length < 4) return null;
  const magic = buffer.readUInt32BE(0);
  const known: Record<number, { bits: 32 | 64; endianness: Endianness }> = {
    0xfeedface: { bits: 32, endianness: "big" },
    0xfeedfacf: { bits: 64, endianness: "big" },
    0xcefaedfe: { bits: 32, endianness: "little" },
    0xcffaedfe: { bits: 64, endianness: "little" },
  };
  const match = known[magic];
  if (!match) return null;
  return { kind: "mach-o", architecture: "unknown", ...match };
}

export function detectBinaryFormat(buffer: Buffer): BinaryFormat {
  return detectElf(buffer) ?? detectPe(buffer) ?? detectMachO(buffer) ?? {
    kind: "unknown",
    architecture: "unknown",
    bits: null,
    endianness: "unknown",
  };
}

export async function inspectBinary(workspace: Workspace, userPath: string): Promise<BinaryInfo> {
  const absolutePath = await workspace.resolveFile(userPath);
  const fileStats = await stat(absolutePath);
  const handle = await open(absolutePath, "r");
  const header = Buffer.alloc(Math.min(fileStats.size, 4096));
  try {
    await handle.read(header, 0, header.length, 0);
  } finally {
    await handle.close();
  }

  const hash = createHash("sha256");
  const counts = new Uint32Array(256);
  let total = 0;
  for await (const chunk of createReadStream(absolutePath)) {
    const bytes = chunk as Buffer;
    hash.update(bytes);
    total += bytes.length;
    for (const byte of bytes) counts[byte] = (counts[byte] ?? 0) + 1;
  }

  let entropy = 0;
  if (total > 0) {
    for (const count of counts) {
      if (count === 0) continue;
      const probability = count / total;
      entropy -= probability * Math.log2(probability);
    }
  }

  const sha256 = hash.digest("hex");
  return {
    path: workspace.relative(absolutePath),
    sampleId: sha256.slice(0, 16),
    sha256,
    size: fileStats.size,
    entropy: Number(entropy.toFixed(4)),
    format: detectBinaryFormat(header),
  };
}
