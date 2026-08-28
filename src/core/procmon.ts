import { open, stat } from "node:fs/promises";
import type { Workspace } from "./workspace.js";

/**
 * Offline Process Monitor (Procmon) CSV trace parsing — postmortem plane.
 * Procmon exports a quoted CSV whose exact column set varies across
 * versions and localizations; the parser detects the header row, maps
 * known column names (aliases included), and produces a bounded summary:
 * process/operation/result histograms, path-category buckets, and the
 * busiest paths. Purely static: a trace file is data, never executed.
 * Bounds: 128 MiB file cap, a hard row cap, and top-N summary lists, so a
 * hostile or merely huge export cannot exhaust memory.
 */
export const PROCMON_MAX_TRACE_BYTES = 128 * 1024 * 1024;
export const PROCMON_HARD_MAX_EVENTS = 1_000_000;
export const PROCMON_DEFAULT_MAX_EVENTS = 250_000;
const PROCMON_TOP_PROCESSES = 20;
const PROCMON_TOP_PATHS = 50;
const PROCMON_TOP_RESULTS = 16;
const PROCMON_TOP_OPERATIONS = 64;
const PROCMON_MAX_PATH_CHARS = 512;

const COLUMN_ALIASES: Record<string, string> = {
  "time of day": "time",
  time: "time",
  timestamp: "time",
  "process name": "process",
  process: "process",
  pid: "pid",
  "process id": "pid",
  tid: "tid",
  "thread id": "tid",
  operation: "operation",
  op: "operation",
  path: "path",
  result: "result",
  detail: "detail",
  details: "detail",
  duration: "duration",
  category: "category",
  "event class": "eventClass",
  "image path": "imagePath",
  "user name": "user",
  session: "session",
};

const REQUIRED_HEADER_COLUMNS = ["time", "process", "operation"];

export interface ProcmonTraceOptions {
  maxEvents?: number;
  filterProcess?: string;
  filterOperation?: string;
  filterPath?: string;
}

export interface ProcmonTraceReport {
  eventCount: number;
  scannedEvents: number;
  parseErrors: number;
  truncated: boolean;
  timeRange: { first: string; last: string } | null;
  processes: Array<{ name: string; pid: string; events: number; imagePath: string }>;
  operations: Array<{ operation: string; events: number }>;
  results: Array<{ result: string; events: number }>;
  pathCategories: Array<{ category: string; events: number }>;
  topPaths: Array<{ path: string; category: string; events: number }>;
}

interface TokenizeResult {
  rows: string[][];
  truncated: boolean;
}

/**
 * Streaming-ish RFC-4180 tokenizer: quoted fields may contain commas,
 * escaped quotes ("") and newlines. Stops after rowCap data rows and
 * reports the cut.
 */
function tokenizeCsv(text: string, rowCap: number): TokenizeResult {
  const rows: string[][] = [];
  let fields: string[] = [];
  let field = "";
  let inQuotes = false;
  let rowComplete = false;
  for (let position = 0; position < text.length; position += 1) {
    const character = text[position] ?? "";
    if (inQuotes) {
      if (character === '"') {
        if (text[position + 1] === '"') {
          field += '"';
          position += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += character;
      }
      continue;
    }
    if (character === '"') {
      inQuotes = true;
    } else if (character === ",") {
      fields.push(field);
      field = "";
    } else if (character === "\r") {
      if (text[position + 1] === "\n") position += 1;
      rowComplete = true;
    } else if (character === "\n") {
      rowComplete = true;
    } else {
      field += character;
    }
    if (rowComplete) {
      fields.push(field);
      if (fields.some((value) => value !== "")) {
        if (rows.length >= rowCap) return { rows, truncated: true };
        rows.push(fields);
      }
      fields = [];
      field = "";
      rowComplete = false;
    }
  }
  // Final unterminated row (possible when the byte cap cut mid-line).
  fields.push(field);
  if (fields.some((value) => value !== "")) {
    if (rows.length < rowCap) rows.push(fields);
    else return { rows, truncated: true };
  }
  return { rows, truncated: rows.length >= rowCap };
}

interface ColumnIndex {
  time: number;
  process: number;
  pid: number;
  tid: number;
  operation: number;
  path: number;
  result: number;
  detail: number;
  duration: number;
  category: number;
  eventClass: number;
  imagePath: number;
  user: number;
  session: number;
}

function mapHeader(row: string[]): Map<string, number> | null {
  const mapping = new Map<string, number>();
  for (let index = 0; index < row.length; index += 1) {
    const canonical = COLUMN_ALIASES[(row[index] ?? "").trim().toLowerCase()];
    if (canonical !== undefined && !mapping.has(canonical)) mapping.set(canonical, index);
  }
  for (const required of REQUIRED_HEADER_COLUMNS) {
    if (!mapping.has(required)) return null;
  }
  return mapping;
}

function columnIndex(mapping: Map<string, number>, name: string, rowCount: number): number {
  const index = mapping.get(name);
  return index !== undefined && index < rowCount ? index : -1;
}

function categorizePath(operation: string, path: string): string {
  const lowered = operation.toLowerCase();
  if (lowered.startsWith("tcp") || lowered.startsWith("udp")) return "network";
  if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+$/.test(path)) return "network";
  if (lowered.includes("process") || lowered.includes("thread") || lowered.includes("image")) return "process";
  if (/^HKLM[\\/]|^HKCU[\\/]|^HKCR[\\/]|^HKU[\\/]|^HKCC[\\/]|^HKPD[\\/]|^HKDD[\\/]/.test(path)) return "registry";
  if (/^[A-Za-z]:[\\/]/.test(path)) return "filesystem";
  if (/^\\\\[^\\]/.test(path)) return "unc";
  if (path === "") return "empty";
  return "other";
}

function rank<T extends { events: number }>(entries: T[]): T[] {
  return entries.sort((left, right) => right.events - left.events || left.toString().localeCompare(right.toString()));
}

async function readTraceText(absolutePath: string): Promise<{ text: string; size: number; readBytes: number }> {
  const fileStats = await stat(absolutePath);
  const readBytes = Math.min(fileStats.size, PROCMON_MAX_TRACE_BYTES);
  const handle = await open(absolutePath, "r");
  const data = Buffer.alloc(readBytes);
  try {
    await handle.read(data, 0, readBytes, 0);
  } finally {
    await handle.close();
  }
  let text = data.toString("utf8");
  if (text.startsWith("\uFEFF")) text = text.slice(1);
  return { text, size: fileStats.size, readBytes };
}

function locateHeader(rows: string[][]): { columns: ColumnIndex; headerRows: number } {
  for (let index = 0; index < Math.min(rows.length, 10); index += 1) {
    const mapping = mapHeader(rows[index] ?? []);
    if (mapping === null) continue;
    const rowCount = (rows[index] ?? []).length;
    return {
      columns: {
        time: columnIndex(mapping, "time", rowCount),
        process: columnIndex(mapping, "process", rowCount),
        pid: columnIndex(mapping, "pid", rowCount),
        tid: columnIndex(mapping, "tid", rowCount),
        operation: columnIndex(mapping, "operation", rowCount),
        path: columnIndex(mapping, "path", rowCount),
        result: columnIndex(mapping, "result", rowCount),
        detail: columnIndex(mapping, "detail", rowCount),
        duration: columnIndex(mapping, "duration", rowCount),
        category: columnIndex(mapping, "category", rowCount),
        eventClass: columnIndex(mapping, "eventClass", rowCount),
        imagePath: columnIndex(mapping, "imagePath", rowCount),
        user: columnIndex(mapping, "user", rowCount),
        session: columnIndex(mapping, "session", rowCount),
      },
      headerRows: index + 1,
    };
  }
  throw new Error(
    "not a recognizable Procmon CSV export: no header row with Time of Day / Process Name / Operation columns",
  );
}

export async function parseProcmonTrace(
  workspace: Workspace,
  userPath: string,
  options: ProcmonTraceOptions = {},
): Promise<ProcmonTraceReport> {
  const absolutePath = await workspace.resolveFile(userPath);
  const { text, size, readBytes } = await readTraceText(absolutePath);

  const maxEvents = Math.min(
    Math.max(Math.trunc(options.maxEvents ?? PROCMON_DEFAULT_MAX_EVENTS), 1),
    PROCMON_HARD_MAX_EVENTS,
  );
  const { rows, truncated: tokenTruncated } = tokenizeCsv(text, maxEvents + 10);

  const { columns, headerRows } = locateHeader(rows);

  const filterProcess = options.filterProcess?.toLowerCase().trim() || "";
  const filterOperation = options.filterOperation?.toLowerCase().trim() || "";
  const filterPath = options.filterPath?.toLowerCase().trim() || "";

  const processes = new Map<string, { name: string; pid: string; events: number; imagePath: string }>();
  const operations = new Map<string, number>();
  const results = new Map<string, number>();
  const categories = new Map<string, number>();
  const paths = new Map<string, { category: string; events: number }>();
  let scannedEvents = 0;
  let eventCount = 0;
  let parseErrors = 0;
  let firstTime = "";
  let lastTime = "";
  let cappedByMaxEvents = false;

  const fieldAt = (row: string[], index: number): string => (index >= 0 && index < row.length ? (row[index] ?? "") : "");

  for (let index = headerRows; index < rows.length; index += 1) {
    const row = rows[index] ?? [];
    const time = fieldAt(row, columns.time);
    const process = fieldAt(row, columns.process);
    const pid = fieldAt(row, columns.pid);
    const operation = fieldAt(row, columns.operation);
    const path = fieldAt(row, columns.path);
    const result = fieldAt(row, columns.result);
    const imagePath = fieldAt(row, columns.imagePath);
    if (process === "" && operation === "" && path === "" && result === "") continue;
    if (operation === "") {
      parseErrors += 1;
      continue;
    }
    scannedEvents += 1;
    if (
      (filterProcess !== "" && !process.toLowerCase().includes(filterProcess)) ||
      (filterOperation !== "" && !operation.toLowerCase().includes(filterOperation)) ||
      (filterPath !== "" && !path.toLowerCase().includes(filterPath))
    ) {
      continue;
    }
    eventCount += 1;
    if (eventCount === 1 && time !== "") firstTime = time;
    lastTime = time;
    const processKey = `${process}\u0000${pid}`;
    const record = processes.get(processKey) ?? { name: process, pid, events: 0, imagePath };
    record.events += 1;
    if (record.imagePath === "" && imagePath !== "") record.imagePath = imagePath;
    if (record.name === "") record.name = process;
    processes.set(processKey, record);
    operations.set(operation, (operations.get(operation) ?? 0) + 1);
    results.set(result === "" ? "(empty)" : result, (results.get(result === "" ? "(empty)" : result) ?? 0) + 1);
    const category = categorizePath(operation, path);
    categories.set(category, (categories.get(category) ?? 0) + 1);
    const clipped = path.slice(0, PROCMON_MAX_PATH_CHARS);
    const pathRecord = paths.get(clipped) ?? { category, events: 0 };
    pathRecord.events += 1;
    paths.set(clipped, pathRecord);
    if (scannedEvents >= maxEvents) {
      if (index + 1 < rows.length || tokenTruncated) cappedByMaxEvents = true;
      break;
    }
  }

  const truncated = tokenTruncated || cappedByMaxEvents || size > readBytes;
  return {
    eventCount,
    scannedEvents,
    parseErrors,
    truncated,
    timeRange: eventCount > 0 ? { first: firstTime, last: lastTime } : null,
    processes: rank([...processes.values()]).slice(0, PROCMON_TOP_PROCESSES),
    operations: rank(
      [...operations.entries()].map(([operation, events]) => ({ operation, events })),
    ).slice(0, PROCMON_TOP_OPERATIONS),
    results: rank(
      [...results.entries()].map(([result, events]) => ({ result, events })),
    ).slice(0, PROCMON_TOP_RESULTS),
    pathCategories: rank(
      [...categories.entries()].map(([category, events]) => ({ category, events })),
    ),
    topPaths: rank(
      [...paths.entries()].map(([path, record]) => ({ path, category: record.category, events: record.events })),
    ).slice(0, PROCMON_TOP_PATHS),
  };
}

export interface ProcmonEvent {
  time: string;
  process: string;
  pid: string;
  operation: string;
  path: string;
  result: string;
  category: string;
}

/**
 * Raw row-level access to a trace for cross-source correlation
 * (report.correlate). Same bounds and header detection as the summary
 * parser; events stop at maxEvents and the cut is reported.
 */
export async function parseProcmonEvents(
  workspace: Workspace,
  userPath: string,
  options: { maxEvents?: number } = {},
): Promise<{ events: ProcmonEvent[]; scannedEvents: number; truncated: boolean }> {
  const absolutePath = await workspace.resolveFile(userPath);
  const { text, size, readBytes } = await readTraceText(absolutePath);
  const maxEvents = Math.min(
    Math.max(Math.trunc(options.maxEvents ?? PROCMON_DEFAULT_MAX_EVENTS), 1),
    PROCMON_HARD_MAX_EVENTS,
  );
  const { rows, truncated: tokenTruncated } = tokenizeCsv(text, maxEvents + 10);
  const { columns, headerRows } = locateHeader(rows);

  const fieldAt = (row: string[], index: number): string => (index >= 0 && index < row.length ? (row[index] ?? "") : "");
  const events: ProcmonEvent[] = [];
  let scannedEvents = 0;
  let cappedByMaxEvents = false;
  for (let index = headerRows; index < rows.length; index += 1) {
    const row = rows[index] ?? [];
    const operation = fieldAt(row, columns.operation);
    if (operation === "") continue;
    scannedEvents += 1;
    const path = fieldAt(row, columns.path);
    events.push({
      time: fieldAt(row, columns.time),
      process: fieldAt(row, columns.process),
      pid: fieldAt(row, columns.pid),
      operation,
      path: path.slice(0, PROCMON_MAX_PATH_CHARS),
      result: fieldAt(row, columns.result),
      category: categorizePath(operation, path),
    });
    if (scannedEvents >= maxEvents) {
      if (index + 1 < rows.length || tokenTruncated) cappedByMaxEvents = true;
      break;
    }
  }
  return {
    events,
    scannedEvents,
    truncated: tokenTruncated || cappedByMaxEvents || size > readBytes,
  };
}