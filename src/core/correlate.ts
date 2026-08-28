/**
 * Evidence correlation: joins artifacts produced by the separate planes —
 * a Procmon CSV trace (postmortem), a persisted Frida call log (dynamic
 * probe), a pe-sieve dump directory (dynamic.unpack), and a debug session
 * transcript artifact — into one bounded report with explicit
 * cross-references: network endpoints, file paths, and persistence points
 * seen by more than one source. Purely static over data that already
 * exists in the workspace; nothing is executed.
 */
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { readArtifactFull } from "./artifacts.js";
import { inspectBinary } from "./binary.js";
import { parsePeTables } from "./peimports.js";
import { extractStrings } from "./strings.js";
import { mineIocs } from "./triage.js";
import { parseProcmonEvents } from "./procmon.js";
import type { Workspace } from "./workspace.js";

export const CORRELATE_DEFAULT_MAX_EVENTS = 100_000;
const MAX_ENDPOINTS = 32;
const MAX_FILE_ENTRIES = 64;
const MAX_PERSISTENCE = 32;
const MAX_DUMPS = 64;
const MAX_TRANSCRIPT_COMMANDS = 50;
const MAX_DUMP_WALK_FILES = 2_000;
const CORRELATE_MAX_STRINGS = 20_000;
/** Default static-string window; overridable via CorrelateOptions (no ceiling). */
const CORRELATE_DEFAULT_SCAN_BYTES = 32 * 1024 * 1024;
const MAX_IOCS = 64;

export interface CorrelateOptions {
  procmonPath?: string;
  fridaLogPath?: string;
  dumpDirPath?: string;
  transcriptArtifactId?: string;
  /** Static anchor: the sample itself (strings/IOCs/imports cross-referenced against the dynamic sources). */
  samplePath?: string;
  /** String-plane scan window for the static anchor (default 32MB, no ceiling). */
  maxScanBytes?: number;
  maxEvents?: number;
}

interface FridaCallEvent {
  api?: unknown;
  path?: unknown;
  sockaddr?: unknown;
  value?: unknown;
  subKey?: unknown;
  data?: unknown;
}

export interface CorrelationReport {
  schema: number;
  sources: Record<string, unknown>;
  networkEndpoints: Array<{ endpoint: string; procmonEvents: number; fridaConnects: number; crossReferenced: boolean }>;
  fileActivity: Array<{ path: string; procmonOperations: string[]; fridaApis: string[]; crossReferenced: boolean }>;
  persistence: Array<{ source: string; detail: string }>;
  dumps: Array<{ file: string; bytes: number }>;
  transcriptCommands: string[];
  /** Static anchors (IOCs/imports mined from the sample) confirmed by a dynamic source. */
  staticDynamic: {
    confirmedIocs: Array<{ value: string; kind: string; seenBy: string[] }>;
    importedApisSeenAtRuntime: Array<{ api: string; dll: string; seenBy: string[] }>;
    unconfirmedIocCount: number;
  } | null;
}

function normalizePath(value: string): string {
  return value.trim().toLowerCase().replace(/\\/g, "/");
}

async function resolveWorkspaceDir(workspace: Workspace, userPath: string): Promise<string> {
  const lexical = path.resolve(workspace.root, userPath);
  const relative = path.relative(workspace.root, lexical);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`path escapes the workspace: ${userPath}`);
  }
  const resolved = await realpath(lexical).catch(() => {
    throw new Error(`directory does not exist: ${userPath}`);
  });
  const stats = await stat(resolved);
  if (!stats.isDirectory()) throw new Error(`not a directory: ${userPath}`);
  return resolved;
}

interface FridaEvidence {
  callEventCount: number;
  truncated: boolean;
  hookedApis: string[];
  endpoints: Map<string, number>;
  fileApis: Map<string, Set<string>>;
  registryWrites: Array<{ value: string; data: string }>;
  registryKeys: string[];
}

function asString(value: unknown, maxChars = 512): string {
  if (typeof value !== "string") return "";
  return value.length <= maxChars ? value : `${value.slice(0, maxChars)}…`;
}

function parseFridaLog(raw: string): { meta: { pid?: unknown; probeSeconds?: unknown; hookedApis?: unknown; callLogTruncated?: unknown }; events: FridaCallEvent[] } {
  const parsed = JSON.parse(raw) as unknown;
  if (Array.isArray(parsed)) return { meta: {}, events: parsed as FridaCallEvent[] };
  if (parsed !== null && typeof parsed === "object") {
    const record = parsed as Record<string, unknown>;
    return {
      meta: record,
      events: Array.isArray(record.callEvents) ? (record.callEvents as FridaCallEvent[]) : [],
    };
  }
  return { meta: {}, events: [] };
}

function collectFridaEvidence(events: FridaCallEvent[]): Omit<FridaEvidence, "callEventCount" | "truncated" | "hookedApis"> {
  const endpoints = new Map<string, number>();
  const fileApis = new Map<string, Set<string>>();
  const registryWrites: Array<{ value: string; data: string }> = [];
  const registryKeys: string[] = [];
  for (const event of events) {
    const api = asString(event.api, 64);
    if (api === "connect") {
      const sockaddr = asString(event.sockaddr, 96);
      const match = sockaddr.match(/^ipv4\s+([0-9.]+:[0-9]+)$/);
      if (match) endpoints.set(match[1] ?? sockaddr, (endpoints.get(match[1] ?? sockaddr) ?? 0) + 1);
      continue;
    }
    if (/^(CreateFile|DeleteFile)/.test(api)) {
      const target = normalizePath(asString(event.path));
      if (target !== "") {
        const apis = fileApis.get(target) ?? new Set<string>();
        apis.add(api);
        fileApis.set(target, apis);
      }
      continue;
    }
    if (/^RegSetValueEx/.test(api)) {
      registryWrites.push({ value: asString(event.value, 256), data: asString(event.data, 256) });
      continue;
    }
    if (/^Reg(Create|Open)KeyEx/.test(api)) {
      const subKey = asString(event.subKey, 256);
      if (subKey !== "") registryKeys.push(subKey);
    }
  }
  return { endpoints, fileApis, registryWrites, registryKeys };
}

const PROCMON_FILE_OPERATIONS = /^(WriteFile|CreateFile|DeleteFile|SetDisposition)/i;
const PROCMON_PERSISTENCE_PATTERN = /(currentversion\\run|\\winlogon|\\services\\)/i;
const ENDPOINT_PATTERN = /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+)/;

export async function correlateEvidence(workspace: Workspace, options: CorrelateOptions): Promise<CorrelationReport> {
  const { procmonPath, fridaLogPath, dumpDirPath, transcriptArtifactId, samplePath } = options;
  if (!procmonPath && !fridaLogPath && !dumpDirPath && !transcriptArtifactId && !samplePath) {
    throw new Error("report.correlate needs at least one source: procmonPath, fridaLogPath, dumpDirPath, transcriptArtifactId, or samplePath");
  }

  const sources: Record<string, unknown> = {};
  const endpoints = new Map<string, { procmonEvents: number; fridaConnects: number }>();
  const fileActivity = new Map<string, { path: string; procmonOperations: Set<string>; fridaApis: Set<string> }>();
  const persistence: Array<{ source: string; detail: string }> = [];
  const dumps: Array<{ file: string; bytes: number }> = [];
  const transcriptCommands: string[] = [];

  if (procmonPath !== undefined) {
    const { events, truncated } = await parseProcmonEvents(workspace, procmonPath, {
      maxEvents: Math.min(options.maxEvents ?? CORRELATE_DEFAULT_MAX_EVENTS, CORRELATE_DEFAULT_MAX_EVENTS),
    });
    let firstTime = "";
    let lastTime = "";
    const processes = new Set<string>();
    for (const event of events) {
      if (event.time !== "") {
        if (firstTime === "") firstTime = event.time;
        lastTime = event.time;
      }
      if (event.process !== "") processes.add(event.process);
      if (event.category === "network") {
        const match = event.path.match(ENDPOINT_PATTERN);
        if (match) {
          const endpoint = match[1] as string;
          const record = endpoints.get(endpoint) ?? { procmonEvents: 0, fridaConnects: 0 };
          record.procmonEvents += 1;
          endpoints.set(endpoint, record);
        }
      }
      if (PROCMON_FILE_OPERATIONS.test(event.operation) && event.path !== "") {
        const key = normalizePath(event.path);
        const record = fileActivity.get(key) ?? { path: event.path, procmonOperations: new Set<string>(), fridaApis: new Set<string>() };
        record.procmonOperations.add(event.operation);
        fileActivity.set(key, record);
      }
      if (/^RegSetValue/i.test(event.operation) && PROCMON_PERSISTENCE_PATTERN.test(event.path)) {
        persistence.push({ source: "procmon", detail: `${event.operation} ${event.path}`.slice(0, 512) });
      }
    }
    sources.procmon = {
      path: procmonPath,
      eventCount: events.length,
      truncated,
      processes: [...processes].slice(0, 20),
      ...(firstTime === "" ? {} : { timeRange: { first: firstTime, last: lastTime } }),
    };
  }

  if (fridaLogPath !== undefined) {
    const absolute = await workspace.resolveFile(fridaLogPath);
    const { meta, events } = parseFridaLog(await readFile(absolute, "utf8"));
    const evidence = collectFridaEvidence(events);
    for (const [endpoint, count] of evidence.endpoints) {
      const record = endpoints.get(endpoint) ?? { procmonEvents: 0, fridaConnects: 0 };
      record.fridaConnects += count;
      endpoints.set(endpoint, record);
    }
    for (const [key, apis] of evidence.fileApis) {
      const record = fileActivity.get(key) ?? { path: key, procmonOperations: new Set<string>(), fridaApis: new Set<string>() };
      for (const api of apis) record.fridaApis.add(api);
      fileActivity.set(key, record);
    }
    for (const write of evidence.registryWrites.slice(0, MAX_PERSISTENCE)) {
      persistence.push({ source: "frida", detail: `RegSetValueEx value=${write.value || "(default)"} data=${write.data || "(none)"}` });
    }
    sources.frida = {
      path: fridaLogPath,
      callEventCount: events.length,
      callLogTruncated: Boolean((meta as Record<string, unknown>).callLogTruncated),
      hookedApis: Array.isArray((meta as Record<string, unknown>).hookedApis)
        ? ((meta as Record<string, unknown>).hookedApis as string[]).slice(0, 32)
        : [],
      registryKeysObserved: evidence.registryKeys.slice(0, 32),
    };
  }

  if (dumpDirPath !== undefined) {
    const directory = await resolveWorkspaceDir(workspace, dumpDirPath);
    let walked = 0;
    let totalBytes = 0;
    const walk = async (current: string, prefix: string): Promise<void> => {
      for (const entry of await readdir(current, { withFileTypes: true })) {
        if (walked >= MAX_DUMP_WALK_FILES || dumps.length >= MAX_DUMPS) return;
        const absolute = path.join(current, entry.name);
        const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
        if (entry.isDirectory()) {
          await walk(absolute, relative);
          continue;
        }
        if (!entry.isFile()) continue;
        walked += 1;
        const stats = await stat(absolute);
        totalBytes += stats.size;
        dumps.push({ file: relative, bytes: stats.size });
      }
    };
    await walk(directory, "");
    sources.dumps = { path: dumpDirPath, fileCount: dumps.length, totalBytes };
  }

  if (transcriptArtifactId !== undefined) {
    let raw: string;
    try {
      raw = await readArtifactFull(workspace, transcriptArtifactId);
    } catch (error) {
      throw new Error(`transcript artifact ${transcriptArtifactId} is not readable in this workspace: ${error instanceof Error ? error.message : String(error)}`);
    }
    const parsed = JSON.parse(raw) as { transcript?: Array<{ command?: unknown }> };
    const commands = Array.isArray(parsed.transcript)
      ? parsed.transcript.map((entry) => asString(entry.command, 256)).filter((command) => command !== "" && command !== "<create>")
      : [];
    transcriptCommands.push(...commands.slice(0, MAX_TRANSCRIPT_COMMANDS));
    sources.transcript = { artifactId: transcriptArtifactId, commandsTotal: commands.length };
  }

  // ---- static anchor: mine the sample, cross-reference against dynamics ----
  let staticDynamic: CorrelationReport["staticDynamic"] = null;
  if (samplePath !== undefined) {
    const binary = await inspectBinary(workspace, samplePath);
    const strings = await extractStrings(workspace, samplePath, {
      limit: CORRELATE_MAX_STRINGS,
      maxScanBytes: Math.max(1024, Math.floor(options.maxScanBytes ?? CORRELATE_DEFAULT_SCAN_BYTES)),
    });
    const iocs = mineIocs(strings.strings.map((entry) => entry.value));
    const tables = binary.format.kind === "pe" ? await parsePeTables(workspace, samplePath) : null;

    // Every dynamic observation, flattened to text for the static↔dynamic match.
    const dynamicText: string[] = [];
    const seenByIndex = new Map<string, Set<string>>();
    const recordSeen = (value: string, seen: string): void => {
      const key = value.toLowerCase();
      const set = seenByIndex.get(key) ?? new Set<string>();
      set.add(seen);
      seenByIndex.set(key, set);
    };
    for (const endpoint of endpoints.keys()) {
      dynamicText.push(endpoint);
      recordSeen(endpoint, "endpoints");
    }
    for (const file of fileActivity.keys()) {
      dynamicText.push(file);
      recordSeen(file, "file-activity");
    }
    for (const entry of persistence) {
      dynamicText.push(entry.detail);
      recordSeen(entry.detail.toLowerCase(), "persistence");
    }
    for (const command of transcriptCommands) {
      dynamicText.push(command);
      recordSeen(command.toLowerCase(), "transcript");
    }
    const dynamicBlob = dynamicText.join("\n").toLowerCase();

    const confirmedIocs: Array<{ value: string; kind: string; seenBy: string[] }> = [];
    let confirmedCount = 0;
    for (const [kind, values] of Object.entries(iocs) as Array<[string, string[]]>) {
      for (const value of values) {
        const hit = dynamicBlob.includes(value.toLowerCase());
        if (hit) {
          confirmedCount += 1;
          if (confirmedIocs.length < MAX_IOCS) {
            confirmedIocs.push({ value, kind, seenBy: [...(seenByIndex.get(value.toLowerCase()) ?? ["endpoints"])] });
          }
        }
      }
    }
    const totalIocs =
      iocs.urls.length + iocs.ips.length + iocs.registry.length + iocs.pdbPaths.length + iocs.uncPaths.length;

    const importedApisSeenAtRuntime: Array<{ api: string; dll: string; seenBy: string[] }> = [];
    if (tables !== null) {
      for (const entry of tables.imports) {
        // Frida call logs record the API name; endpoints/transcripts rarely do.
        if (dynamicBlob.includes(entry.name.toLowerCase())) {
          importedApisSeenAtRuntime.push({ api: entry.name, dll: entry.dll, seenBy: ["dynamic-observation"] });
          if (importedApisSeenAtRuntime.length >= MAX_IOCS) break;
        }
      }
    }

    staticDynamic = {
      confirmedIocs,
      importedApisSeenAtRuntime,
      unconfirmedIocCount: Math.max(0, totalIocs - confirmedCount),
    };
    sources.staticAnchor = {
      path: samplePath,
      sha256: binary.sha256,
      stringCount: strings.strings.length,
      iocCount: totalIocs,
      importCount: tables === null ? 0 : tables.imports.length,
    };
  }

  const rankedEndpoints = [...endpoints.entries()]
    .map(([endpoint, record]) => ({
      endpoint,
      procmonEvents: record.procmonEvents,
      fridaConnects: record.fridaConnects,
      crossReferenced: record.procmonEvents > 0 && record.fridaConnects > 0,
    }))
    .sort((left, right) => Number(right.crossReferenced) - Number(left.crossReferenced) || (right.procmonEvents + right.fridaConnects) - (left.procmonEvents + left.fridaConnects))
    .slice(0, MAX_ENDPOINTS);

  const rankedFiles = [...fileActivity.values()]
    .map((record) => ({
      path: record.path,
      procmonOperations: [...record.procmonOperations].sort(),
      fridaApis: [...record.fridaApis].sort(),
      crossReferenced: record.procmonOperations.size > 0 && record.fridaApis.size > 0,
    }))
    .sort((left, right) => Number(right.crossReferenced) - Number(left.crossReferenced) || right.path.localeCompare(left.path))
    .slice(0, MAX_FILE_ENTRIES);

  return {
    schema: 2,
    sources,
    networkEndpoints: rankedEndpoints,
    fileActivity: rankedFiles,
    persistence: persistence.slice(0, MAX_PERSISTENCE),
    dumps,
    transcriptCommands,
    staticDynamic,
  };
}
