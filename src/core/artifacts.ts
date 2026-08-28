/**
 * Content-addressed artifact store. Analysis outputs are immutable blobs
 * keyed by their SHA-256; metadata lives in a sidecar. Agents read artifacts
 * through bounded offset/limit windows so a multi-megabyte report never
 * lands in the model context in one piece.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Workspace } from "./workspace.js";

export interface ArtifactMetadata {
  id: string;
  sha256: string;
  mediaType: string;
  bytes: number;
  createdAt: number;
  sourceOperation: string;
  sampleId?: string;
  description: string;
  /** Deterministic key (sample digest + options + backend identity) for reuse. */
  cacheKey?: string;
  /** Provider hints surfaced to summaries when replaying a cached artifact. */
  backend?: string;
  projectName?: string;
}

export interface StoredArtifact extends ArtifactMetadata {
  /** Workspace-relative path of the content blob. */
  path: string;
}

export interface ArtifactReadResult {
  id: string;
  sha256: string;
  mediaType: string;
  totalBytes: number;
  offset: number;
  length: number;
  truncated: boolean;
  nextOffset: number | null;
  content: string;
}

export class ArtifactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArtifactError";
  }
}

const ID_PREFIX = "sha256:";
const DEFAULT_READ_LIMIT = 16 * 1024;
const MAX_READ_LIMIT = 256 * 1024;

function isHash(hash: string): boolean {
  return /^[a-f0-9]{64}$/.test(hash);
}

export function parseArtifactId(id: string): string {
  if (!id.startsWith(ID_PREFIX)) {
    throw new ArtifactError(`artifact id must look like "sha256:<64 hex chars>", got ${JSON.stringify(id)}`);
  }
  const hash = id.slice(ID_PREFIX.length);
  if (!isHash(hash)) throw new ArtifactError(`artifact id carries an invalid digest: ${JSON.stringify(id)}`);
  return hash;
}

function contentPath(workspace: Workspace, hash: string): string {
  return path.join(workspace.root, ".minusone", "artifacts", "cas", hash.slice(0, 2), hash);
}

function metadataPath(workspace: Workspace, hash: string): string {
  return path.join(workspace.root, ".minusone", "artifacts", "meta", `${hash}.json`);
}

export async function storeArtifact(
  workspace: Workspace,
  content: string,
  metadata: Omit<ArtifactMetadata, "id" | "sha256" | "bytes" | "createdAt">,
): Promise<StoredArtifact> {
  const buffer = Buffer.from(content, "utf8");
  const hash = createHash("sha256").update(buffer).digest("hex");
  const blob = contentPath(workspace, hash);
  await mkdir(path.dirname(blob), { recursive: true });
  await mkdir(path.dirname(metadataPath(workspace, hash)), { recursive: true });
  await writeFile(blob, buffer);

  const stored: StoredArtifact = {
    ...metadata,
    ...(metadata.sampleId === undefined ? {} : { sampleId: metadata.sampleId }),
    id: `${ID_PREFIX}${hash}`,
    sha256: hash,
    bytes: buffer.byteLength,
    createdAt: Date.now(),
    path: workspace.relative(blob),
  };
  await writeFile(metadataPath(workspace, hash), JSON.stringify(stored, null, 2));
  return stored;
}

export async function getArtifactMetadata(workspace: Workspace, id: string): Promise<StoredArtifact> {
  const hash = parseArtifactId(id);
  try {
    const raw = await readFile(metadataPath(workspace, hash), "utf8");
    return JSON.parse(raw) as StoredArtifact;
  } catch {
    throw new ArtifactError(`artifact ${id} is not in this workspace store`);
  }
}

export async function readArtifact(
  workspace: Workspace,
  id: string,
  options: { offset?: number; limit?: number } = {},
): Promise<ArtifactReadResult> {
  const hash = parseArtifactId(id);
  const metadata = await getArtifactMetadata(workspace, id);
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? DEFAULT_READ_LIMIT)), MAX_READ_LIMIT);
  if (offset >= metadata.bytes) {
    return {
      id,
      sha256: hash,
      mediaType: metadata.mediaType,
      totalBytes: metadata.bytes,
      offset,
      length: 0,
      truncated: false,
      nextOffset: null,
      content: "",
    };
  }
  const buffer = await readFile(contentPath(workspace, hash));
  const slice = buffer.subarray(offset, offset + limit);
  const nextOffset = offset + slice.byteLength < metadata.bytes ? offset + slice.byteLength : null;
  return {
    id,
    sha256: hash,
    mediaType: metadata.mediaType,
    totalBytes: metadata.bytes,
    offset,
    length: slice.byteLength,
    truncated: nextOffset !== null,
    nextOffset,
    content: slice.toString("utf8"),
  };
}

export async function listArtifacts(workspace: Workspace): Promise<StoredArtifact[]> {
  const metaRoot = path.join(workspace.root, ".minusone", "artifacts", "meta");
  let entries: string[];
  try {
    entries = await readdir(metaRoot);
  } catch {
    return [];
  }
  const stored: StoredArtifact[] = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith(".json")) continue;
    try {
      stored.push(JSON.parse(await readFile(path.join(metaRoot, entry), "utf8")) as StoredArtifact);
    } catch {
      // Skip malformed sidecars rather than failing the whole listing.
    }
  }
  return stored;
}

/** Hash an arbitrary cache-key payload into a stable hex digest. */
export function cacheKeyDigest(payload: unknown): string {
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

/**
 * Read an artifact's full content without bounds. For internal replay paths
 * (cache hits); model-facing reads must go through {@link readArtifact}.
 */
export async function readArtifactFull(workspace: Workspace, id: string): Promise<string> {
  const hash = parseArtifactId(id);
  return await readFile(contentPath(workspace, hash), "utf8");
}

/**
 * Materialize an artifact's content as a real workspace file. The content
 * blob is read from the CAS and written (binary-safe) to a caller-chosen
 * writable path so the operator/agent can grab decoded strings, carved
 * files, decompiled code, or a debug transcript as an ordinary file.
 */
export async function exportArtifact(
  workspace: Workspace,
  artifactId: string,
  outputPath: string,
): Promise<{ exportedPath: string; artifactId: string; sha256: string; mediaType: string; bytes: number }> {
  const metadata = await getArtifactMetadata(workspace, artifactId);
  const source = await workspace.resolveFile(metadata.path);
  const buffer = await readFile(source);
  const target = await workspace.resolveWritablePath(outputPath);
  await writeFile(target, buffer);
  return {
    exportedPath: workspace.relative(target),
    artifactId,
    sha256: metadata.sha256,
    mediaType: metadata.mediaType,
    bytes: metadata.bytes,
  };
}

/** Find the newest artifact stored under an exact cache key, if any. */
export async function findArtifactByCacheKey(workspace: Workspace, cacheKey: string): Promise<StoredArtifact | null> {
  const matches = (await listArtifacts(workspace)).filter((artifact) => artifact.cacheKey === cacheKey);
  if (matches.length === 0) return null;
  return matches.reduce((newest, candidate) => (candidate.createdAt > newest.createdAt ? candidate : newest));
}

/**
 * Persist a composite-operation conclusion as a "findings" artifact: the
 * durable case file that survives sessions. Findings carry a title, a
 * severity, the evidence artifact ids they were derived from, and free-form
 * notes — the analyst-facing layer above raw reports.
 */
export interface Finding {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  notes: string;
  evidence: string[];
}

export async function storeFinding(
  workspace: Workspace,
  finding: Finding,
  sourceOperation: string,
): Promise<StoredArtifact> {
  return await storeArtifact(workspace, JSON.stringify(finding, null, 2), {
    mediaType: "application/json",
    sourceOperation,
    description: `finding: ${finding.title} (${finding.severity})`,
  });
}

/** List persisted findings (artifacts whose description carries the marker). */
export async function listFindings(workspace: Workspace): Promise<StoredArtifact[]> {
  const all = await listArtifacts(workspace);
  return all.filter((artifact) => artifact.description.startsWith("finding: "));
}
