/**
 * binary.patch: write bytes at a file offset into a COPY of the sample. The
 * original is never modified — patches land under .minusone/exports/ (or a
 * caller-chosen writable path) and the diff + both sha256 hashes are returned.
 * This is the "act" operation: patch a byte, then run the patched copy via
 * sample.execute (dynamic-gated) to confirm the behavior change. Offset-based
 * patching is portable and needs no PE parser; RVA-based patching is a future
 * LIEF-backed extension.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { inspectBinary } from "./binary.js";
import type { Workspace } from "./workspace.js";

export const PATCH_MAX_BYTES = 16 * 1024 * 1024;
export const PATCH_MAX_PATCHES = 64;

export interface BinaryPatchSpec {
  offset: number;
  bytes: string;
}

export interface BinaryPatchDiff {
  offset: number;
  from: string;
  to: string;
}

export interface BinaryPatchResult {
  patchedPath: string;
  originalSha256: string;
  patchedSha256: string;
  bytes: number;
  patchesApplied: number;
  diff: BinaryPatchDiff[];
}

const HEX = /^[0-9a-fA-F]+$/;

export function parsePatchBytes(hex: string): Buffer {
  const trimmed = hex.trim();
  if (trimmed.length === 0) throw new Error("patch bytes are empty");
  if (trimmed.length % 2 !== 0) {
    throw new Error(`patch bytes length must be even (got ${trimmed.length} hex chars)`);
  }
  if (!HEX.test(trimmed)) throw new Error("patch bytes must be hex (0-9a-f)");
  return Buffer.from(trimmed, "hex");
}

export async function patchBinary(
  workspace: Workspace,
  userPath: string,
  patches: BinaryPatchSpec[],
  outputPath?: string,
): Promise<BinaryPatchResult> {
  if (patches.length === 0) {
    throw new Error("binary.patch: at least one patch is required");
  }
  if (patches.length > PATCH_MAX_PATCHES) {
    throw new Error(`binary.patch: too many patches (${patches.length} > ${PATCH_MAX_PATCHES})`);
  }

  const sample = await inspectBinary(workspace, userPath);
  const original = await readFile(await workspace.resolveFile(userPath));
  if (original.length > PATCH_MAX_BYTES) {
    throw new Error(`binary.patch: sample exceeds ${PATCH_MAX_BYTES} bytes (${original.length})`);
  }
  if (original.length === 0) {
    throw new Error("binary.patch: sample is empty");
  }

  // Validate + bounds-check every patch before writing anything.
  const applied: Array<{ offset: number; bytes: Buffer }> = [];
  for (const spec of patches) {
    if (!Number.isInteger(spec.offset) || spec.offset < 0) {
      throw new Error(`binary.patch: offset must be a non-negative integer (got ${spec.offset})`);
    }
    const bytes = parsePatchBytes(spec.bytes);
    if (spec.offset + bytes.length > original.length) {
      throw new Error(
        `binary.patch: patch at offset ${spec.offset} (length ${bytes.length}) overruns the file size ${original.length}`,
      );
    }
    applied.push({ offset: spec.offset, bytes });
  }

  // Write into a COPY; the original is never touched.
  const ext = path.extname(userPath);
  const stem = path.basename(userPath, ext) || "sample";
  const defaultName = `${stem}-patched-${sample.sha256.slice(0, 8)}${ext}`;
  const target = await workspace.resolveWritablePath(outputPath ?? path.join(".minusone", "exports", defaultName));

  const patched = Buffer.from(original);
  const diff: BinaryPatchDiff[] = [];
  for (const { offset, bytes } of applied) {
    const from = patched.subarray(offset, offset + bytes.length).toString("hex");
    patched.set(bytes, offset);
    diff.push({ offset, from, to: bytes.toString("hex") });
  }
  await writeFile(target, patched);

  return {
    patchedPath: workspace.relative(target),
    originalSha256: sample.sha256,
    patchedSha256: createHash("sha256").update(patched).digest("hex"),
    bytes: patched.length,
    patchesApplied: applied.length,
    diff,
  };
}
