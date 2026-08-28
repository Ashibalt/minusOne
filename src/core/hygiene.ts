/**
 * Disk hygiene (D12): `minusOne doctor` shows what .minusone is holding and
 * what is safe to reclaim; `minusOne doctor --clean` reclaims it. The rules
 * are conservative and explicit:
 *
 *   * CLEANABLE: `.minusone/tmp` contents (downloads, the already-installed
 *     torch wheel — 2.6 GB measured), nothing else is deleted;
 *   * KILLABLE: an orphan models sidecar (a python.exe parked with 1.8 GB
 *     VRAM after the session ended) via killExternalModelsSidecar;
 *   * HINT ONLY: docker reclaimable space — `docker system prune` is printed
 *     as a suggestion, never executed (it is system-wide, far beyond
 *     minusone's scope);
 *   * NEVER TOUCHED: artifacts (CAS), outputs (spill files — analyst data),
 *     run (live job directories), datasets, ghidra projects, config.
 *
 * Nothing is removed without the explicit --clean flag.
 */
import { readdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { runBoundedCommand } from "./command.js";
import { killExternalModelsSidecar, probeExternalModelsSidecar } from "./models.js";
import type { Workspace } from "./workspace.js";

export interface HygieneEntry {
  name: string;
  bytes: number;
  cleanable: boolean;
  note?: string;
}

export interface HygieneReport {
  minusoneDir: string;
  present: boolean;
  totalBytes: number;
  entries: HygieneEntry[];
  cleanableBytes: number;
  sidecar: { running: boolean; pid: number | null; detail: string };
  docker: { available: boolean; reclaimable: string | null; suggestion: string | null };
}

export interface HygieneCleanResult {
  freedBytes: number;
  actions: string[];
}

/** Subdirectories of .minusone that --clean may empty (contents, not the dir). */
const CLEANABLE_DIRS: ReadonlyArray<{ name: string; note: string }> = [
  { name: "tmp", note: "downloads and one-shot temp files (e.g. the already-installed torch wheel)" },
];

async function directorySizeBytes(absolute: string): Promise<number> {
  let total = 0;
  let entries;
  try {
    entries = await readdir(absolute, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const full = path.join(absolute, entry.name);
    if (entry.isDirectory()) {
      total += await directorySizeBytes(full);
    } else if (entry.isFile()) {
      const info = await stat(full).catch(() => null);
      total += info?.size ?? 0;
    }
  }
  return total;
}

async function dockerReclaimable(): Promise<HygieneReport["docker"]> {
  // `docker system df --format '{{json .}}'` prints one JSON row per type
  // (Images/Containers/Local Volumes/Build Cache) with a human Reclaimable
  // field; table parsing would be brittle, JSON rows are not.
  const probe = await runBoundedCommand("docker", ["system", "df", "--format", "{{json .}}"], {
    timeoutMs: 20_000,
    maxOutputBytes: 64 * 1024,
  }).catch(() => null);
  if (probe === null || probe.exitCode !== 0) {
    return { available: false, reclaimable: null, suggestion: null };
  }
  const parts: string[] = [];
  for (const line of probe.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      const row = JSON.parse(trimmed) as { Type?: string; Reclaimable?: string };
      if (row.Type !== undefined && row.Reclaimable !== undefined) {
        parts.push(`${row.Type}: ${row.Reclaimable}`);
      }
    } catch {
      // A non-JSON row (old docker): keep what we have, stay honest below.
    }
  }
  if (parts.length === 0) {
    return { available: true, reclaimable: null, suggestion: "docker is available; run 'docker system df' for reclaimable space" };
  }
  return {
    available: true,
    reclaimable: parts.join(", "),
    suggestion: "reclaim with 'docker system prune' (system-wide — minusone never runs this itself)",
  };
}

export async function collectHygiene(workspace: Workspace): Promise<HygieneReport> {
  const minusoneDir = path.join(workspace.root, ".minusone");
  const sidecar = await probeExternalModelsSidecar();
  const docker = await dockerReclaimable();
  let topEntries;
  try {
    topEntries = await readdir(minusoneDir, { withFileTypes: true });
  } catch {
    return { minusoneDir, present: false, totalBytes: 0, entries: [], cleanableBytes: 0, sidecar, docker };
  }
  const entries: HygieneEntry[] = [];
  let totalBytes = 0;
  let cleanableBytes = 0;
  for (const entry of topEntries) {
    const full = path.join(minusoneDir, entry.name);
    const bytes = entry.isDirectory() ? await directorySizeBytes(full) : ((await stat(full).catch(() => null))?.size ?? 0);
    totalBytes += bytes;
    const cleanableSpec = CLEANABLE_DIRS.find((spec) => spec.name === entry.name);
    const cleanable = cleanableSpec !== undefined && entry.isDirectory();
    if (cleanable) cleanableBytes += bytes;
    entries.push({
      name: entry.name,
      bytes,
      cleanable,
      ...(cleanableSpec !== undefined ? { note: cleanableSpec.note } : {}),
    });
  }
  entries.sort((left, right) => right.bytes - left.bytes);
  return { minusoneDir, present: true, totalBytes, entries, cleanableBytes, sidecar, docker };
}

export async function cleanWorkspaceHygiene(workspace: Workspace): Promise<HygieneCleanResult> {
  const minusoneDir = path.join(workspace.root, ".minusone");
  let freedBytes = 0;
  const actions: string[] = [];
  for (const spec of CLEANABLE_DIRS) {
    const target = path.join(minusoneDir, spec.name);
    const bytes = await directorySizeBytes(target);
    let contents;
    try {
      contents = await readdir(target);
    } catch {
      continue; // No such directory — nothing to free.
    }
    for (const name of contents) {
      await rm(path.join(target, name), { recursive: true, force: true }).catch(() => undefined);
    }
    freedBytes += bytes;
    actions.push(`emptied .minusone/${spec.name} (${formatBytes(bytes)} freed — ${spec.note})`);
  }
  const sidecar = await killExternalModelsSidecar();
  actions.push(`sidecar: ${sidecar.detail}${sidecar.pid !== null ? ` (pid ${sidecar.pid})` : ""}`);
  if (freedBytes === 0 && actions.length === 1) {
    actions.unshift("nothing to clean");
  }
  return { freedBytes, actions };
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
