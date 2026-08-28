import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, open, writeFile } from "node:fs/promises";
import path from "node:path";
import { killProcessTree } from "./dynamic.js";
import { resolveSampleLaunch } from "./dllhost.js";
import { parsePeTablesFromBuffer } from "./peimports.js";
import { readFile } from "node:fs/promises";
import type { Workspace } from "./workspace.js";

/**
 * Scriptable dynamic bridge (Frida runtime, node bindings) for the armed
 * LOCAL plane: spawns the sample, attaches an agent that enumerates
 * modules and hooks the classic behavioral API surface — file, registry,
 * and network entry points — for a bounded probe window, then detaches
 * and kills the process tree. Every result is labeled target "local":
 * no VM boundary or network isolation applies. The frida package is a
 * native runtime dependency and is probed lazily, so hosts without it
 * boot fine and report the gap honestly.
 */
export const FRIDA_MAX_PROBE_SECONDS = 120;
export const FRIDA_DEFAULT_PROBE_SECONDS = 8;
export const FRIDA_MAX_CALL_EVENTS = 400;
export const FRIDA_MAX_MODULES = 64;

export interface FridaAvailability {
  available: boolean;
  version: string | null;
  error: string | null;
}

interface FridaSessionBinding {
  pid: number;
  createScript(source: string): Promise<FridaScriptBinding>;
  detach(): Promise<void>;
}

interface FridaScriptBinding {
  load(): Promise<void>;
  unload(): Promise<void>;
  /** Streamed agent events (send() from the agent survives process exit — post-exit RPC does not). */
  message: { connect(handler: (message: { payload?: unknown }) => void): void };
  exports: {
    stop(): Promise<void>;
    snapshot(): Promise<{ hookedApis: string[]; events: unknown[]; truncated: boolean }>;
    modules(): Promise<Array<{ name: string; base: string; size: number; path: string }>>;
  };
}

interface FridaChildEventBinding {
  pid: number;
}

/** Windows trap encoded in the type: the ARRAY argv form is silently
 * ignored on Windows (argc stays 1) — only the OBJECT form delivers. */
type FridaSpawnOptions = string[] | { argv?: string[]; envp?: Record<string, string> };

interface FridaDeviceBinding {
  attach(pid: number): Promise<FridaSessionBinding>;
  spawn(program: string, options?: FridaSpawnOptions): Promise<number>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
  enableSpawnGating(): Promise<void>;
  disableSpawnGating(): Promise<void>;
  childAdded: { connect(handler: (child: FridaChildEventBinding) => void): void; disconnect(handler: (child: FridaChildEventBinding) => void): void };
}

interface FridaModuleBinding {
  attach(pid: number): Promise<FridaSessionBinding>;
  spawn(program: string, options?: FridaSpawnOptions): Promise<number>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
  version?: string;
  getLocalDevice(): Promise<FridaDeviceBinding>;
}

interface FridaSpawnOutcome {
  pid: number;
  /** spawn-gated (agent loads before the first instruction) or legacy attach. */
  mode: "spawn-gate" | "spawn-fallback" | "attach";
  note: string | null;
  cleanup: () => Promise<void>;
}

/**
 * Launch a sample for instrumentation with the SPAWN GATE: frida.spawn()
 * starts the process SUSPENDED before its first instruction, we attach and
 * load the agent, then resume. Fast-exit samples (the crackme that prints
 * and exits in milliseconds) are the reason this exists: the legacy
 * spawn-then-attach race loses them every time — the process is gone
 * before the agent lands. DLLs still need the rundll32 host and fall back
 * to the legacy attach race (spawn-gating rundll32 hooks the HOST, which
 * works but delays DLL load; the fallback keeps current behavior honest).
 */
async function launchForFrida(
  binding: FridaModuleBinding,
  launch: { command: string; args: string[]; host: "direct" | "rundll32"; entryExport: string | null },
  runDir: string,
  legacySpawn: (launch: { command: string; args: string[] }, runDir: string) => { pid: number },
): Promise<FridaSpawnOutcome> {
  const cleanup = async (): Promise<void> => {
    try { await binding.kill(-1); } catch { /* no pid yet */ }
  };
  if (launch.host === "direct") {
    try {
      const pid = await binding.spawn(launch.command, launch.args.length > 1 ? launch.args.slice(1) : []);
      return {
        pid,
        mode: "spawn-gate",
        note: "spawn-gated: the agent loads while the sample is suspended at its first instruction (fast-exit safe)",
        cleanup: async () => {
          try { await binding.kill(pid); } catch { /* already gone */ }
        },
      };
    } catch (error) {
      return {
        pid: -1,
        mode: "spawn-fallback",
        note: `frida spawn failed (${error instanceof Error ? error.message : String(error)}); falling back to legacy attach`,
        cleanup: async () => undefined,
      };
    }
  }
  // rundll32 hosting keeps the legacy race: spawn the host, sleep, attach.
  const spawned = legacySpawn(launch, runDir);
  return {
    pid: spawned.pid,
    mode: "attach",
    note: "rundll32 host: legacy attach (DLL load happens inside the host after resume)",
    cleanup: async () => undefined,
  };
}

export async function probeFridaAvailability(): Promise<FridaAvailability> {
  try {
    const binding = (await import("frida")) as unknown as FridaModuleBinding;
    return { available: true, version: binding.version ?? null, error: null };
  } catch (error) {
    return {
      available: false,
      version: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Agent-side payload. Hooks are resolved per module export, so APIs inside
 * NOT-yet-loaded DLLs are skipped rather than failing the probe; the hooked
 * set is reported back so the caller can see what was actually observed.
 * Argument previews are bounded reads wrapped per hook, so an invalid
 * pointer degrades one event instead of killing the agent.
 *
 * Events are streamed via send() the moment they happen: on a fast-exit
 * sample the process dies long before any post-hoc RPC snapshot could run
 * ("Script is destroyed"), but send() messages already in flight arrive.
 */
const FRIDA_AGENT_SOURCE = `
"use strict";
var MAX_EVENTS = ${FRIDA_MAX_CALL_EVENTS};
var startedAt = Date.now();
var events = [];
var truncated = false;
var running = true;

function record(ev) {
  if (!running) return;
  if (events.length >= MAX_EVENTS) { truncated = true; return; }
  events.push(ev);
  send(ev);
}

function readString(ptr, wide) {
  if (ptr.isNull()) return null;
  try {
    var value = wide ? ptr.readUtf16String(512) : ptr.readUtf8String(512);
    if (value === null) return null;
    return value.length >= 512 ? value.slice(0, 512) + "..." : value;
  } catch (e) { return null; }
}

function readData(ptr, count) {
  if (ptr.isNull()) return null;
  try {
    var length = Math.min(count, 64);
    return hexdump(ptr, { length: length, ansi: true, header: false });
  } catch (e) { return "<unreadable>"; }
}

function describeSockaddr(ptr) {
  if (ptr.isNull()) return null;
  try {
    var family = ptr.readU16();
    if (family === 2) {
      var a = ptr.add(4).readU8();
      var b = ptr.add(5).readU8();
      var c = ptr.add(6).readU8();
      var d = ptr.add(7).readU8();
      var port = (ptr.add(2).readU8() << 8) | ptr.add(3).readU8();
      return "ipv4 " + a + "." + b + "." + c + "." + d + ":" + port;
    }
    return "family " + family;
  } catch (e) { return null; }
}

var handlers = {};
handlers["CreateFileW"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, path: readString(args[0], true) });
};
handlers["CreateFileA"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, path: readString(args[0], false) });
};
handlers["DeleteFileW"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, path: readString(args[0], true) });
};
handlers["DeleteFileA"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, path: readString(args[0], false) });
};
handlers["WriteFile"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, bytes: args[2].toInt32(), data: readData(args[1], args[2].toInt32()) });
};
handlers["RegSetValueExW"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, value: readString(args[1], true), type: args[3].toInt32(), data: args[4].isNull() ? null : (args[3].toInt32() === 1 ? readString(args[4], true) : readData(args[4], Math.min(args[5].toInt32(), 64))) });
};
handlers["RegSetValueExA"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, value: readString(args[1], false), type: args[3].toInt32(), data: args[4].isNull() ? null : (args[3].toInt32() === 1 ? readString(args[4], false) : readData(args[4], Math.min(args[5].toInt32(), 64))) });
};
handlers["RegCreateKeyExW"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, subKey: readString(args[1], true) });
};
handlers["RegCreateKeyExA"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, subKey: readString(args[1], false) });
};
handlers["RegOpenKeyExW"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, subKey: readString(args[1], true) });
};
handlers["RegOpenKeyExA"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, subKey: readString(args[1], false) });
};
handlers["connect"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, sockaddr: describeSockaddr(args[1]) });
};
handlers["send"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, bytes: args[2].toInt32(), data: readData(args[1], args[2].toInt32()) });
};
handlers["recv"] = function (args, hook) {
  hook.record({ api: hook.name, atMs: hook.elapsed(), module: hook.module, capacity: args[2].toInt32() });
};

var hooked = {};
var targets = Object.keys(handlers);
// Frida 17 removed the per-module findExportByName shim; resolve through
// the global export table (with a per-module fallback for older runtimes).
function resolveExport(module, name) {
  try {
    var global = Module.getGlobalExportByName(name);
    if (global !== null && global !== undefined) {
      var owner = Process.findModuleByAddress(global);
      return { address: global, module: owner ? owner.name : module.name };
    }
  } catch (e) { /* fall through */ }
  try {
    var local = module.findExportByName(name);
    if (local !== null && local !== undefined) return { address: local, module: module.name };
  } catch (e) { /* unavailable on this runtime */ }
  return null;
}
Process.enumerateModules().forEach(function (m) {
  targets.forEach(function (name) {
    if (hooked[name]) return;
    var resolved = resolveExport(m, name);
    if (resolved === null) return;
    var address = resolved.address;
    var hookModule = resolved.module;
    hooked[name] = true;
    try {
      Interceptor.attach(address, {
        onEnter: function (args) {
          var hook = {
            name: name,
            module: hookModule,
            elapsed: function () { return Date.now() - startedAt; },
            record: record
          };
          handlers[name](args, hook);
        }
      });
    } catch (e) {
      hooked[name] = false;
    }
  });
});

rpc.exports.stop = function () { running = false; };
rpc.exports.snapshot = function () {
  return { hookedApis: Object.keys(hooked).filter(function (k) { return hooked[k]; }).sort(), events: events, truncated: truncated };
};
rpc.exports.modules = function () {
  return Process.enumerateModules().sort(function (a, b) { return b.size - a.size; })
    .slice(0, ${FRIDA_MAX_MODULES})
    .map(function (m) { return { name: m.name, base: "0x" + m.base.toString(16), size: m.size, path: m.path ? String(m.path) : "" }; });
};
`;

/**
 * Source-trace agent: hooks the TARGET APIs (resolved across modules like
 * the behavioral probe), but instead of just recording the call it captures
 * the caller's backtrace — every frame resolved to module + offset. This is
 * the runtime→static bridge: an offset inside the sample module IS the RVA,
 * so the TS side converts it to a static VA through the PE tables and the
 * agent learns WHICH FUNCTION made the call without touching a debugger.
 * An optional needle filters events to calls whose primary string argument
 * contains it (e.g. the C2 host or the dropped filename).
 */
export interface SourceTraceTarget {
  name: string;
  /** Index of the primary string argument, when the API has one. */
  argIndex?: number;
  /** True when the primary argument is UTF-16 (W APIs). */
  wide?: boolean;
  /** "sockaddr" for connect-style args (structure, not a string). */
  style?: "sockaddr";
}

export const SOURCE_TRACE_DEFAULT_TARGETS: SourceTraceTarget[] = [
  { name: "CreateFileW", argIndex: 0, wide: true },
  { name: "CreateFileA", argIndex: 0 },
  { name: "DeleteFileW", argIndex: 0, wide: true },
  { name: "DeleteFileA", argIndex: 0 },
  { name: "CopyFileW", argIndex: 0, wide: true },
  { name: "CopyFileA", argIndex: 0 },
  { name: "MoveFileW", argIndex: 0, wide: true },
  { name: "MoveFileA", argIndex: 0 },
  { name: "WriteFile" },
  { name: "RegSetValueExW", argIndex: 1, wide: true },
  { name: "RegSetValueExA", argIndex: 1 },
  { name: "RegCreateKeyExW", argIndex: 1, wide: true },
  { name: "RegCreateKeyExA", argIndex: 1 },
  { name: "RegOpenKeyExW", argIndex: 1, wide: true },
  { name: "RegOpenKeyExA", argIndex: 1 },
  { name: "WinHttpConnect", argIndex: 1, wide: true },
  { name: "WinHttpOpenRequest", argIndex: 2, wide: true },
  { name: "InternetConnectW", argIndex: 1, wide: true },
  { name: "InternetConnectA", argIndex: 1 },
  { name: "InternetOpenUrlW", argIndex: 1, wide: true },
  { name: "InternetOpenUrlA", argIndex: 1 },
  { name: "URLDownloadToFileW", argIndex: 1, wide: true },
  { name: "URLDownloadToFileA", argIndex: 1 },
  { name: "connect", argIndex: 1, style: "sockaddr" },
  { name: "send" },
  { name: "WSASend" },
  { name: "CreateProcessW", argIndex: 0, wide: true },
  { name: "CreateProcessA", argIndex: 0 },
  { name: "CreateProcessInternalW", argIndex: 1, wide: true },
  { name: "VirtualAllocEx" },
  { name: "WriteProcessMemory" },
  { name: "CreateRemoteThread" },
  { name: "CreateRemoteThreadEx" },
  { name: "SetWindowsHookExW" },
  { name: "CryptUnprotectData" },
  { name: "CryptEncrypt" },
  { name: "CryptDecrypt" },
  { name: "StartServiceW", argIndex: 0, wide: true },
  { name: "CreateServiceW", argIndex: 1, wide: true },
];

export const SOURCE_TRACE_MAX_EVENTS = 128;
const SOURCE_TRACE_MAX_FRAMES = 16;

function buildSourceTraceAgent(targets: SourceTraceTarget[], needle: string | null): string {
  return `
"use strict";
var TARGETS = ${JSON.stringify(targets)};
var NEEDLE = ${JSON.stringify(needle === null ? null : needle.toLowerCase())};
var MAX_EVENTS = ${SOURCE_TRACE_MAX_EVENTS};
var MAX_FRAMES = ${SOURCE_TRACE_MAX_FRAMES};
var startedAt = Date.now();
var events = [];
var truncated = false;
var running = true;

function record(ev) {
  if (!running) return;
  if (events.length >= MAX_EVENTS) { truncated = true; return; }
  events.push(ev);
  send(ev);
}

function readString(ptr, wide) {
  if (ptr.isNull()) return null;
  try {
    var value = wide ? ptr.readUtf16String(512) : ptr.readUtf8String(512);
    if (value === null) return null;
    return value.length >= 512 ? value.slice(0, 512) + "..." : value;
  } catch (e) { return null; }
}

function describeSockaddr(ptr) {
  if (ptr.isNull()) return null;
  try {
    var family = ptr.readU16();
    if (family === 2) {
      var a = ptr.add(4).readU8(), b = ptr.add(5).readU8(), c = ptr.add(6).readU8(), d = ptr.add(7).readU8();
      var port = (ptr.add(2).readU8() << 8) | ptr.add(3).readU8();
      return "ipv4 " + a + "." + b + "." + c + "." + d + ":" + port;
    }
    return "family " + family;
  } catch (e) { return null; }
}

var hooked = {};
// Frida 17 removed the per-module findExportByName shim; resolve through
// the global export table (with a per-module fallback for older runtimes).
function resolveExport(module, name) {
  try {
    var global = Module.getGlobalExportByName(name);
    if (global !== null && global !== undefined) {
      var owner = Process.findModuleByAddress(global);
      return { address: global, module: owner ? owner.name : module.name };
    }
  } catch (e) { /* fall through */ }
  try {
    var local = module.findExportByName(name);
    if (local !== null && local !== undefined) return { address: local, module: module.name };
  } catch (e) { /* unavailable on this runtime */ }
  return null;
}
Process.enumerateModules().forEach(function (m) {
  TARGETS.forEach(function (t) {
    if (hooked[t.name]) return;
    var resolved = resolveExport(m, t.name);
    if (resolved === null) return;
    var address = resolved.address;
    hooked[t.name] = true;
    try {
      Interceptor.attach(address, {
        onEnter: function (args) {
          if (!running) return;
          var argText = null;
          if (t.style === "sockaddr") {
            argText = describeSockaddr(args[t.argIndex === undefined ? 1 : t.argIndex]);
          } else if (t.argIndex !== undefined) {
            argText = readString(args[t.argIndex], t.wide === true);
          }
          if (NEEDLE !== null) {
            if (argText === null) return;
            if (argText.toLowerCase().indexOf(NEEDLE) === -1) return;
          }
          var bt = [];
          try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE); } catch (e) { bt = []; }
          var sites = [];
          for (var i = 0; i < bt.length && i < MAX_FRAMES; i++) {
            var addr = bt[i];
            var mod = null;
            try { mod = Process.findModuleByAddress(addr); } catch (e) { mod = null; }
            sites.push({
              runtime: "0x" + addr.toString(16),
              module: mod ? mod.name : null,
              // NativePointer.toNumber() does not exist on current runtimes;
              // Number() converts a pointer-sized value losslessly here.
              offset: mod ? Number(addr.sub(mod.base)) : null
            });
          }
          record({ api: t.name, atMs: Date.now() - startedAt, arg: argText, sites: sites });
        }
      });
    } catch (e) {
      hooked[t.name] = false;
    }
  });
});

rpc.exports.stop = function () { running = false; };
rpc.exports.snapshot = function () {
  return { hookedApis: Object.keys(hooked).filter(function (k) { return hooked[k]; }).sort(), events: events, truncated: truncated };
};
rpc.exports.modules = function () {
  return Process.enumerateModules().sort(function (a, b) { return b.size - a.size; })
    .slice(0, ${FRIDA_MAX_MODULES})
    .map(function (m) { return { name: m.name, base: "0x" + m.base.toString(16), size: m.size, path: m.path ? String(m.path) : "" }; });
};
`;
}

export interface FridaSourceTraceOptions {
  targets?: SourceTraceTarget[];
  /** Case-insensitive substring the primary string argument must contain. */
  needle?: string;
  probeSeconds?: number;
  /** Command-line arguments for the sample (drives branchy validators). */
  args?: string[];
  entryExport?: string;
  signal?: AbortSignal;
}

export interface FridaSourceTraceResult {
  pid: number;
  runDir: string;
  probeSeconds: number;
  /** How the sample was launched (direct spawn, or rundll32 hosting a DLL). */
  launchedVia: string;
  /** spawn-gate (fast-exit safe) or attach (legacy race). */
  launchMode: string;
  moduleCount: number;
  modules: Array<{ name: string; base: string; size: number; path: string }>;
  hookedApis: string[];
  events: Array<{ api: string; atMs: number; arg: string | null; sites: Array<{ runtime: string; module: string | null; offset: number | null }> }>;
  truncated: boolean;
  attachFailed: string | null;
  notes: string[];
}

export async function runFridaSourceTrace(
  workspace: Workspace,
  userPath: string,
  options: FridaSourceTraceOptions = {},
): Promise<FridaSourceTraceResult> {
  const binding = (await import("frida")) as unknown as FridaModuleBinding;
  const absolutePath = await workspace.resolveFile(userPath);
  const targets = options.targets !== undefined && options.targets.length > 0 ? options.targets : SOURCE_TRACE_DEFAULT_TARGETS;
  const needle = options.needle === undefined || options.needle.trim() === "" ? null : options.needle.trim();
  const probeSeconds = Math.min(FRIDA_MAX_PROBE_SECONDS, Math.max(1, options.probeSeconds ?? FRIDA_DEFAULT_PROBE_SECONDS));
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });

  const launch = await resolveSampleLaunch(workspace, userPath, options.entryExport);
  const launchedVia = launch.host === "rundll32"
    ? `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}`
    : "direct";
  const notes: string[] = [];

  // Spawn-gate for EXEs: the process starts SUSPENDED, the agent lands, and
  // only then does the first instruction run — a fast-exit sample can no
  // longer outrun the instrumentation.
  let pid: number;
  let launchMode: string;
  let fridaPid: number | null = null;
  if (launch.host === "direct") {
    try {
      const userArgs = options.args ?? [];
      pid = await binding.spawn(absolutePath, userArgs.length > 0 ? { argv: [path.basename(absolutePath), ...userArgs] } : []);
      fridaPid = pid;
      launchMode = "spawn-gate";
      notes.push("spawn-gated: agent installed while the sample was suspended (fast-exit safe)");
    } catch (error) {
      const fallbackArgs = launch.host === "direct" ? [launch.args[0] ?? launch.command, ...(options.args ?? [])] : launch.args;
      const child = spawn(launch.command, fallbackArgs, { cwd: runDir, stdio: "ignore", windowsHide: true });
      child.on("error", () => undefined);
      pid = child.pid ?? -1;
      launchMode = "spawn-fallback";
      notes.push(`frida spawn failed (${error instanceof Error ? error.message : String(error)}); legacy attach race`);
    }
  } else {
    const child = spawn(launch.command, launch.args, { cwd: runDir, stdio: "ignore", windowsHide: true });
    child.on("error", () => undefined);
    pid = child.pid ?? -1;
    launchMode = "attach";
    notes.push("rundll32 host: legacy attach (the DLL loads inside the host)");
  }

  const base = {
    pid,
    runDir: workspace.relative(runDir),
    probeSeconds,
    launchedVia,
    launchMode,
    moduleCount: 0,
    modules: [] as FridaSourceTraceResult["modules"],
    hookedApis: [] as string[],
    events: [] as FridaSourceTraceResult["events"],
    truncated: false,
    notes,
  };
  if (pid === -1) {
    return { ...base, attachFailed: `failed to spawn ${userPath}` };
  }

  let session: FridaSessionBinding | null = null;
  let script: FridaScriptBinding | null = null;
  try {
    if (launchMode !== "spawn-gate") await sleep(800);
    try {
      session = await binding.attach(pid);
    } catch (error) {
      return {
        ...base,
        attachFailed: `frida attach failed (the sample may have exited): ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    script = await session.createScript(buildSourceTraceAgent(targets, needle));
    const streamed: unknown[] = [];
    const seen = new Set<unknown>();
    script.message.connect((message) => {
      const payload = message.payload;
      if (payload !== undefined && !seen.has(payload)) {
        seen.add(payload);
        streamed.push(payload);
      }
    });
    await script.load();
    if (launchMode === "spawn-gate") {
      await binding.resume(pid);
    }

    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, probeSeconds * 1000);
      options.signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
    });
    let hookedApis: string[] = [];
    let snapshotEvents: unknown[] = [];
    let truncated = false;
    let modules: FridaSourceTraceResult["modules"] = [];
    try {
      await script.exports.stop();
      const snapshot = await script.exports.snapshot();
      hookedApis = snapshot.hookedApis;
      snapshotEvents = snapshot.events;
      truncated = snapshot.truncated;
      modules = await script.exports.modules();
    } catch {
      // Fast-exit: streamed events are the record; modules stay empty.
    }
    const events: unknown[] = [...streamed];
    for (const event of snapshotEvents) {
      if (!seen.has(event)) events.push(event);
    }
    return {
      ...base,
      moduleCount: modules.length,
      modules,
      hookedApis,
      events: events as FridaSourceTraceResult["events"],
      truncated,
      attachFailed: null,
    };
  } catch (error) {
    return { ...base, attachFailed: error instanceof Error ? error.message : String(error) };
  } finally {
    await script?.unload().catch(() => undefined);
    await session?.detach().catch(() => undefined);
    if (fridaPid !== null) {
      try { await binding.kill(fridaPid); } catch { /* already gone */ }
    }
    if (!options.signal?.aborted) await killProcessTree(pid);
  }
}

export interface FridaProbeOptions {
  probeSeconds?: number;
  /** Command-line arguments for the sample (drives branchy validators). */
  args?: string[];
  /** Export for rundll32 to call when the sample is a DLL. */
  entryExport?: string;
  signal?: AbortSignal;
}

export interface FridaProbeResult {
  pid: number;
  runDir: string;
  probeSeconds: number;
  /** How the sample was launched (direct spawn, or rundll32 hosting a DLL). */
  launchedVia: string;
  /** spawn-gate (fast-exit safe) or attach (legacy race). */
  launchMode: string;
  moduleCount: number;
  modules: Array<{ name: string; base: string; size: number; path: string }>;
  hookedApis: string[];
  callEvents: unknown[];
  callLogTruncated: boolean;
  /** Workspace-relative frida-call-events.json persisted in runDir, when the probe succeeded. */
  callLogPath: string | null;
  attachFailed: string | null;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function runFridaProbe(
  workspace: Workspace,
  userPath: string,
  options: FridaProbeOptions = {},
): Promise<FridaProbeResult> {
  const binding = (await import("frida")) as unknown as FridaModuleBinding;
  const absolutePath = await workspace.resolveFile(userPath);
  const probeSeconds = Math.min(FRIDA_MAX_PROBE_SECONDS, Math.max(1, options.probeSeconds ?? FRIDA_DEFAULT_PROBE_SECONDS));
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });

  // DLLs go through rundll32 so DllMain (where packers unpack) executes.
  // EXEs use the spawn gate: agent first, first instruction later.
  const launch = await resolveSampleLaunch(workspace, userPath, options.entryExport);
  const launchedVia = launch.host === "rundll32"
    ? `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}`
    : "direct";
  let pid: number;
  let launchMode: string;
  let fridaPid: number | null = null;
  if (launch.host === "direct") {
    try {
      const userArgs = options.args ?? [];
      pid = await binding.spawn(absolutePath, userArgs.length > 0 ? { argv: [path.basename(absolutePath), ...userArgs] } : []);
      fridaPid = pid;
      launchMode = "spawn-gate";
    } catch {
      const fallbackArgs = launch.host === "direct" ? [launch.args[0] ?? launch.command, ...(options.args ?? [])] : launch.args;
      const child = spawn(launch.command, fallbackArgs, { cwd: runDir, stdio: "ignore", windowsHide: true });
      child.on("error", () => undefined);
      pid = child.pid ?? -1;
      launchMode = "spawn-fallback";
    }
  } else {
    const child = spawn(launch.command, launch.args, { cwd: runDir, stdio: "ignore", windowsHide: true });
    child.on("error", () => undefined);
    pid = child.pid ?? -1;
    launchMode = "attach";
  }
  const baseResult = (extra: Partial<FridaProbeResult> = {}): FridaProbeResult => ({
    pid,
    runDir: workspace.relative(runDir),
    probeSeconds,
    launchedVia,
    launchMode,
    moduleCount: 0,
    modules: [],
    hookedApis: [],
    callEvents: [],
    callLogTruncated: false,
    callLogPath: null,
    attachFailed: null,
    ...extra,
  });
  if (pid === -1) {
    await sleep(500).catch(() => undefined);
    return baseResult({
      attachFailed: `failed to spawn ${userPath}${launch.host === "rundll32" ? " via rundll32" : ""}`,
    });
  }

  let session: FridaSessionBinding | null = null;
  let script: FridaScriptBinding | null = null;
  try {
    if (launchMode !== "spawn-gate") await sleep(800);
    try {
      session = await binding.attach(pid);
    } catch (error) {
      return baseResult({
        attachFailed: `frida attach failed (the sample may have exited): ${error instanceof Error ? error.message : String(error)}`,
      });
    }
    script = await session.createScript(FRIDA_AGENT_SOURCE);
    // Streamed events: the agent send()s every event the moment it fires, so
    // a fast-exit sample's calls arrive even though post-exit RPC is dead.
    const streamed: unknown[] = [];
    const seen = new Set<unknown>();
    script.message.connect((message) => {
      const payload = message.payload;
      if (payload !== undefined && !seen.has(payload)) {
        seen.add(payload);
        streamed.push(payload);
      }
    });
    await script.load();
    if (launchMode === "spawn-gate") {
      await binding.resume(pid);
    }

    // Probe window: the sample runs, events stream in. After the window (or
    // once the process dies and RPC starts failing) we take the best
    // snapshot we can: RPC snapshot if the script is still alive, otherwise
    // the streamed events we already hold.
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, probeSeconds * 1000);
      options.signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
    });
    let hookedApis: string[] = [];
    let snapshotEvents: unknown[] = [];
    let truncated = false;
    try {
      await script.exports.stop();
      const snapshot = await script.exports.snapshot();
      hookedApis = snapshot.hookedApis;
      snapshotEvents = snapshot.events;
      truncated = snapshot.truncated;
    } catch {
      // Process exited: the streamed events ARE the record.
      snapshotEvents = [];
    }
    const modules = await script.exports.modules().catch(() => [] as FridaProbeResult["modules"]) as FridaProbeResult["modules"];
    // Merge, dedup by identity: streamed first (they survive exit), then any
    // extra events only a live RPC snapshot could see.
    const events: unknown[] = [...streamed];
    for (const event of snapshotEvents) {
      if (!seen.has(event)) events.push(event);
    }
    if (events.length === 0 && hookedApis.length === 0 && streamed.length === 0 && snapshotEvents.length === 0) {
      return baseResult({ attachFailed: "no probe events captured (the sample may have exited before any hooked call)" });
    }
    await script.unload().catch(() => undefined);
    script = null;
    await session.detach().catch(() => undefined);
    session = null;
    // Persist the call log so later operations (report.correlate) can join
    // probe evidence with traces and dumps without rerunning the sample.
    const callLogAbsolute = path.join(runDir, "frida-call-events.json");
    await writeFile(
      callLogAbsolute,
      JSON.stringify(
        {
          pid,
          probeSeconds,
          launchMode,
          hookedApis,
          callLogTruncated: truncated,
          callEvents: events,
        },
        null,
        2,
      ),
    );
    return {
      pid,
      runDir: workspace.relative(runDir),
      probeSeconds,
      launchedVia,
      launchMode,
      moduleCount: modules.length,
      modules,
      hookedApis,
      callEvents: events,
      callLogTruncated: truncated,
      callLogPath: workspace.relative(callLogAbsolute),
      attachFailed: null,
    };
  } catch (error) {
    return baseResult({ attachFailed: error instanceof Error ? error.message : String(error) });
  } finally {
    await script?.unload().catch(() => undefined);
    await session?.detach().catch(() => undefined);
    if (fridaPid !== null) {
      try { await binding.kill(fridaPid); } catch { /* already gone */ }
    }
    if (!options.signal?.aborted) await killProcessTree(pid);
  }
}
// ---------------------------------------------------------------------------
// frida.script — the persistent instrumentation plane.
// ---------------------------------------------------------------------------

export const FRIDA_SCRIPT_MAX_SOURCE_CHARS = 64 * 1024;
export const FRIDA_SCRIPT_MAX_PROBE_SECONDS = 120;
export const FRIDA_SCRIPT_DEFAULT_PROBE_SECONDS = 15;
const FRIDA_SCRIPT_MAX_EVENTS = 2000;

export interface FridaScriptOptions {
  /** Agent JavaScript source (Frida runtime: Interceptor, Stalker, rpc...). */
  source: string;
  /** Command-line arguments for the sample (drives branchy validators). */
  args?: string[];
  probeSeconds?: number;
  entryExport?: string;
  /** Attach to spawned children too (nanomite self-debug schemes). */
  childGating?: boolean;
  /**
   * ATTACH MODE: instrument an already-running process instead of spawning
   * (the driven-TUI pattern: console_launch's pid). The process is NOT
   * resumed (it is already running) and NOT killed at teardown — the caller
   * owns its lifecycle. args/entryExport are spawn-only and ignored here.
   */
  pid?: number;
  signal?: AbortSignal;
}

export interface FridaScriptEvent {
  atMs: number;
  pid: number | null;
  payload: unknown;
}

export interface FridaScriptResult {
  pid: number;
  runDir: string;
  launchedVia: string;
  launchMode: string;
  probeSeconds: number;
  childGating: boolean;
  /** Processes the agent was attached to (root + gated children). */
  attachedPids: number[];
  events: FridaScriptEvent[];
  eventLogTruncated: boolean;
  /** Workspace-relative JSONL event log, appended live during the run. */
  eventLogPath: string | null;
  attachFailed: string | null;
  notes: string[];
}

/**
 * Run a CUSTOM Frida agent against the sample for a bounded window. This is
 * the persistent-instrumentation upgrade over the canned probes: the agent
 * source is the analyst's (Interceptor.attach, Stalker.follow, whatever),
 * events sent via send() are streamed to the returned JSONL log AS THEY
 * HAPPEN, and with childGating the device watches for spawned children
 * (nanomite self-debugging schemes: the parent spawns a debugger child)
 * and attaches the same agent to them before resuming.
 */
export async function runFridaScript(
  workspace: Workspace,
  userPath: string,
  options: FridaScriptOptions,
): Promise<FridaScriptResult> {
  const binding = (await import("frida")) as unknown as FridaModuleBinding;
  const device = await binding.getLocalDevice();
  const absolutePath = await workspace.resolveFile(userPath);
  const source = options.source.slice(0, FRIDA_SCRIPT_MAX_SOURCE_CHARS);
  if (source.trim() === "") {
    throw new Error("agent source is empty — pass the Frida agent JavaScript");
  }
  const probeSeconds = Math.min(FRIDA_SCRIPT_MAX_PROBE_SECONDS, Math.max(2, options.probeSeconds ?? FRIDA_SCRIPT_DEFAULT_PROBE_SECONDS));
  const childGating = options.childGating === true;
  const attachPid = options.pid;
  if (attachPid !== undefined && (!Number.isInteger(attachPid) || attachPid <= 0)) {
    throw new Error(`pid must be a positive integer (got ${attachPid}) — attach mode instruments an already-running process`);
  }
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });
  const eventLogPath = path.join(runDir, "frida-agent-events.jsonl");
  const notes: string[] = [];

  const launch = attachPid === undefined
    ? await resolveSampleLaunch(workspace, userPath, options.entryExport)
    : { command: absolutePath, args: [], host: "direct" as const, entryExport: null };
  const launchedVia = attachPid === undefined
    ? launch.host === "rundll32"
      ? `rundll32${launch.entryExport === null ? "" : ` (${launch.entryExport})`}`
      : "direct"
    : `external pid ${attachPid}`;

  const startedAt = Date.now();
  const events: FridaScriptEvent[] = [];
  let eventLogTruncated = false;
  let logHandle: import("node:fs/promises").FileHandle | null = null;

  const attachAgent = async (pid: number, label: string): Promise<void> => {
    const session = await device.attach(pid);
    const script = await session.createScript(source);
    script.message.connect((message: { payload?: unknown }) => {
      if (events.length >= FRIDA_SCRIPT_MAX_EVENTS) {
        eventLogTruncated = true;
        return;
      }
      const event: FridaScriptEvent = {
        atMs: Date.now() - startedAt,
        pid,
        payload: message.payload ?? message,
      };
      events.push(event);
      logHandle?.write(`${JSON.stringify(event)}\n`).catch(() => undefined);
    });
    await script.load();
    // Track for orderly teardown AFTER the probe window: unloading early
    // kills in-flight send() delivery (fast-exit samples lose their last
    // events to exactly that race).
    activeScripts.push({ script, session });
    notes.push(`agent attached to ${label} (pid ${pid})`);
  };

  const attachedPids: number[] = [];
  const activeScripts: Array<{ script: FridaScriptBinding; session: FridaSessionBinding }> = [];
  let pid = -1;
  let launchMode = "spawn-gate";
  let fridaPid: number | null = null;

  const childHandler = async (child: { pid: number }): Promise<void> => {
    if (childGating !== true) return;
    try {
      await attachAgent(child.pid, "gated child");
      attachedPids.push(child.pid);
      await device.resume(child.pid).catch(() => undefined);
    } catch {
      // Child died before the agent landed — resume anyway if possible.
      await device.resume(child.pid).catch(() => undefined);
    }
  };
  const childConnector = (child: unknown): void => {
    const pidValue = (child as { pid?: number } | null)?.pid;
    if (typeof pidValue === "number") void childHandler({ pid: pidValue });
  };

  try {
    logHandle = await open(eventLogPath, "w");

    if (attachPid !== undefined) {
      // Attach mode: the process is already running elsewhere (driven TUI,
      // accumulated state) — no spawn, no resume, no kill at teardown.
      pid = attachPid;
      launchMode = "attach-pid";
      notes.push(`attach mode: instrumenting live pid ${attachPid}; the process is left running at teardown (caller owns it)`);
    } else if (launch.host === "direct") {
      // The ARRAY form of spawn()'s argv is silently IGNORED on Windows
      // (argc stays 1) — the OBJECT form delivers both argv and envp.
      pid = await device.spawn(absolutePath, (options.args ?? []).length > 0 ? { argv: [path.basename(absolutePath), ...(options.args ?? [])] } : []);
      fridaPid = pid;
      launchMode = "spawn-gate";
    } else {
      const child = spawn(absolutePath, options.args ?? [], { cwd: runDir, stdio: "ignore", windowsHide: true });
      child.on("error", () => undefined);
      pid = child.pid ?? -1;
      launchMode = "attach";
      if (pid !== -1) await sleep(400);
    }
    if (pid === -1) {
      return {
        pid,
        runDir: workspace.relative(runDir),
        launchedVia,
        launchMode,
        probeSeconds,
        childGating,
        attachedPids: [],
        events,
        eventLogTruncated,
        eventLogPath: null,
        attachFailed: `failed to spawn ${userPath}`,
        notes,
      };
    }

    if (childGating) {
      device.childAdded.connect(childConnector);
      await device.enableSpawnGating().catch(() => undefined);
      notes.push("spawn gating enabled: children are held suspended until the agent lands");
    }

    await attachAgent(pid, "sample");
    attachedPids.push(pid);
    // resume() only applies to frida-spawned (suspended) processes —
    // resuming an already-running one throws Invalid PID and kills the
    // whole probe window.
    if (launchMode === "spawn-gate") {
      await device.resume(pid);
    }

    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, probeSeconds * 1000);
      options.signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
    });

    return {
      pid,
      runDir: workspace.relative(runDir),
      launchedVia,
      launchMode,
      probeSeconds,
      childGating,
      attachedPids,
      events,
      eventLogTruncated,
      eventLogPath: workspace.relative(eventLogPath),
      attachFailed: null,
      notes,
    };
  } catch (error) {
    return {
      pid,
      runDir: workspace.relative(runDir),
      launchedVia,
      launchMode,
      probeSeconds,
      childGating,
      attachedPids,
      events,
      eventLogTruncated,
      eventLogPath: events.length > 0 ? workspace.relative(eventLogPath) : null,
      attachFailed: error instanceof Error ? error.message : String(error),
      notes,
    };
  } finally {
    if (childGating) {
      try { device.childAdded.disconnect(childConnector); } catch { /* already disconnected */ }
      await device.disableSpawnGating().catch(() => undefined);
    }
    await logHandle?.close().catch(() => undefined);
    for (const entry of activeScripts) {
      await entry.script.unload().catch(() => undefined);
      await entry.session.detach().catch(() => undefined);
    }
    if (fridaPid !== null) {
      try { await device.kill(fridaPid); } catch { /* already gone */ }
    }
    // Attach mode never kills: the caller owns the process it pointed us at.
    if (attachPid === undefined && !options.signal?.aborted) await killProcessTree(pid);
  }
}

// ---------------------------------------------------------------------------
// trace.diff — the Stalker execution diff.
// ---------------------------------------------------------------------------

export interface TraceDiffOptions {
  /** argv for run A (the input that distinguishes the runs). */
  argsA?: string[];
  /** argv for run B. */
  argsB?: string[];
  probeSeconds?: number;
  signal?: AbortSignal;
}

export interface TraceDiffBlock {
  /** Sample-module RVA (hex) of the basic block entry. */
  rva: string;
  firstSeenMs?: number;
}

export interface TraceDiffSummary {
  counts: { runA: number; runB: number; shared: number; onlyA: number; onlyB: number };
  /** Earliest block (by first-seen time) executed by exactly one run — the
   * branch-point proxy. seenIn says which run executed it. */
  firstDivergence: { rva: string; firstSeenMs: number; seenIn: "A" | "B" } | null;
  /** Shared blocks first executed AFTER the first divergence in both runs —
   * where the runs met again (earliest first, up to 5). */
  reconvergences: Array<{ rva: string; firstSeenMsA: number; firstSeenMsB: number }>;
}

export interface TraceDiffResult {
  status: "ok" | "error";
  runA: { pid: number; blockCount: number };
  runB: { pid: number; blockCount: number };
  /** Earliest-diverging blocks per side (up to TRACE_DIFF_TOP_N each). */
  blocksOnlyInA: TraceDiffBlock[];
  blocksOnlyInB: TraceDiffBlock[];
  sharedBlockCount: number;
  summary: TraceDiffSummary;
  /** Workspace-relative path of the full diff JSON when the lists were
   * truncated to the top-N; null when everything fits inline. */
  fullDiffFile: string | null;
  notes: string[];
  error?: string;
}

/** Blocks per side kept inline in the trace.diff answer (earliest first). */
export const TRACE_DIFF_TOP_N = 50;

function blockTime(firstSeenMs: number | undefined): number {
  return firstSeenMs === undefined ? Number.POSITIVE_INFINITY : firstSeenMs;
}

/**
 * Pure summary over the two coverage sets: counts, the earliest diverging
 * block (the branch point), and the reconvergence points. Exported for tests.
 */
export function summarizeTraceDiff(
  blocksA: Map<number, number>,
  blocksB: Map<number, number>,
): TraceDiffSummary {
  let shared = 0;
  let firstDivergence: TraceDiffSummary["firstDivergence"] = null;
  for (const [rva, seenA] of blocksA) {
    if (blocksB.has(rva)) {
      shared += 1;
      continue;
    }
    if (firstDivergence === null || seenA < firstDivergence.firstSeenMs) {
      firstDivergence = { rva: `0x${rva.toString(16)}`, firstSeenMs: seenA, seenIn: "A" };
    }
  }
  for (const [rva, seenB] of blocksB) {
    if (blocksA.has(rva)) continue;
    if (firstDivergence === null || seenB < firstDivergence.firstSeenMs) {
      firstDivergence = { rva: `0x${rva.toString(16)}`, firstSeenMs: seenB, seenIn: "B" };
    }
  }
  const reconvergences: TraceDiffSummary["reconvergences"] = [];
  if (firstDivergence !== null) {
    const candidates: Array<{ rva: string; firstSeenMsA: number; firstSeenMsB: number }> = [];
    for (const [rva, seenA] of blocksA) {
      const seenB = blocksB.get(rva);
      if (seenB === undefined) continue;
      if (seenA > firstDivergence.firstSeenMs && seenB > firstDivergence.firstSeenMs) {
        candidates.push({ rva: `0x${rva.toString(16)}`, firstSeenMsA: seenA, firstSeenMsB: seenB });
      }
    }
    candidates.sort((left, right) => Math.max(left.firstSeenMsA, left.firstSeenMsB) - Math.max(right.firstSeenMsA, right.firstSeenMsB));
    reconvergences.push(...candidates.slice(0, 5));
  }
  return {
    counts: { runA: blocksA.size, runB: blocksB.size, shared, onlyA: blocksA.size - shared, onlyB: blocksB.size - shared },
    firstDivergence,
    reconvergences,
  };
}

/**
 * The Stalker agent for trace.diff: follows the main thread, records the
 * ENTRY of every basic block executed INSIDE the sample module (RVA only),
 * throttled to block granularity — the set of executed blocks is the run's
 * fingerprint, and the diff of two runs localizes the branch that the two
 * inputs took differently.
 */
function buildStalkerAgentSource(entryRva: number | null): string {
  return `
"use strict";
var mainModule = Process.enumerateModules()[0];
var base = mainModule.base;
var size = mainModule.size;
var blocks = {};
var STARTED_AT = Date.now();
// Windows stalker traps, all three field-tested: (1) follow() from the
// agent thread traces frida-agent itself — start from a hook on the
// module ENTRY so this.threadId is the sample's thread; (2) the transform
// callback never fires on frida 17 — exec events do; (3) a post-hoc RPC
// snapshot dies with a fast-exit sample — stream the set every 400ms and
// let the caller keep the last one.
function onStalkerEvents(events) {
  var parsed = Stalker.parse(events, { stringify: false, annotate: false });
  for (var i = 0; i < parsed.length; i++) {
    var entry = parsed[i];
    var loc = Array.isArray(entry) ? entry[0] : entry;
    if (loc === undefined || loc === null) continue;
    if (typeof loc.compare === "function" && loc.compare(base) >= 0 && loc.compare(base.add(size)) < 0) {
      var rva = loc.sub(base).toInt32();
      if (!blocks[rva]) blocks[rva] = Date.now() - STARTED_AT;
    }
  }
}
var ENTRY_RVA = ${entryRva === null ? "null" : entryRva};
if (ENTRY_RVA !== null) {
  Interceptor.attach(base.add(ENTRY_RVA), {
    onEnter: function () {
      Stalker.follow(this.threadId, {
        events: { exec: true },
        onReceive: onStalkerEvents
      });
    }
  });
}
function snapshot() {
  var out = [];
  for (var rva in blocks) out.push({ rva: parseInt(rva, 10), firstSeenMs: blocks[rva] });
  return out;
}
setInterval(function () { send({ stalkerSnapshot: snapshot() }); }, 400);
rpc.exports.stop = function () { Stalker.unfollow(); };
`;
}

/** Resolve the PE entrypoint RVA for the stalker entry hook. */
async function resolveEntrypointRva(absolutePath: string): Promise<number | null> {
  try {
    const buffer = await readFile(absolutePath);
    const tables = await parsePeTablesFromBuffer(buffer);
    if (process.env.MINUSONE_DEBUG_ENTRYRVA) console.error(`minusone: entryRva(${absolutePath}) = ${tables === null ? null : tables.entrypointRva}`);
    return tables === null ? null : tables.entrypointRva;
  } catch (error) {
    if (process.env.MINUSONE_DEBUG_ENTRYRVA) console.error(`minusone: entryRva failed: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

async function runStalkerProfile(
  device: FridaDeviceBinding,
  absolutePath: string,
  args: string[],
  runDir: string,
  probeSeconds: number,
  entryRva: number | null,
): Promise<{ pid: number; blocks: Map<number, number> }> {
  // The distinguishing input rides argv through the OBJECT spawn form
  // (the array form is ignored on Windows). Spawn-gate keeps the agent
  // ahead of the first instruction, so Stalker sees every block. stdin is
  // NOT an option: frida-spawn opens no stdin, the sample blocks in the
  // kernel on fgets, and a blocked main thread stops Stalker's event
  // queue AND the agent's send() delivery entirely (field-tested).
  const pid = await device.spawn(absolutePath, { argv: [path.basename(absolutePath), ...args] });
  void runDir;
  const session = await device.attach(pid);
  const script = await session.createScript(buildStalkerAgentSource(entryRva));
  let blocks = new Map<number, number>();
  script.message.connect((message: { payload?: unknown }) => {
    const payload = message.payload as { stalkerSnapshot?: Array<{ rva: number; firstSeenMs: number }> } | undefined;
    if (payload === undefined || !Array.isArray(payload.stalkerSnapshot)) return;
    // Last streamed snapshot wins — later snapshots are supersets.
    blocks = new Map(payload.stalkerSnapshot.map((entry) => [entry.rva, entry.firstSeenMs]));
  });
  await script.load();
  await device.resume(pid);
  await new Promise<void>((resolve) => setTimeout(resolve, probeSeconds * 1000));
  await script.exports.stop().catch(() => undefined);
  // Snapshot delivery is batched and asynchronous: give in-flight send()
  // events a moment to land before unload kills the pipe.
  await new Promise<void>((resolve) => setTimeout(resolve, 600));
  await script.unload().catch(() => undefined);
  await session.detach().catch(() => undefined);
  try { await device.kill(pid); } catch { /* already gone */ }
  await killProcessTree(pid).catch(() => undefined);
  return { pid, blocks };
}

/**
 * Assemble the trace.diff answer from two coverage sets: symmetric
 * difference, summary, earliest-top-N inline, full lists spilled to a file
 * when they exceed the top-N. The answer carries the EARLIEST diverging
 * blocks per side (closest to the branch point); a 65%-of-90K-blocks diff
 * would otherwise be a 4.5M-char reply (measured on the license-gate
 * crackme). Exported for tests — no frida involved at this stage.
 */
export async function composeTraceDiffResult(
  workspace: Workspace,
  runA: { pid: number; blocks: Map<number, number> },
  runB: { pid: number; blocks: Map<number, number> },
  notes: string[],
): Promise<TraceDiffResult> {
  const onlyInA: TraceDiffBlock[] = [];
  const onlyInB: TraceDiffBlock[] = [];
  let shared = 0;
  for (const [rva, firstSeenMs] of runA.blocks) {
    if (runB.blocks.has(rva)) shared += 1;
    else onlyInA.push({ rva: `0x${rva.toString(16)}`, ...(firstSeenMs === undefined ? {} : { firstSeenMs }) });
  }
  for (const [rva, firstSeenMs] of runB.blocks) {
    if (!runA.blocks.has(rva)) onlyInB.push({ rva: `0x${rva.toString(16)}`, ...(firstSeenMs === undefined ? {} : { firstSeenMs }) });
  }
  const byTime = (left: TraceDiffBlock, right: TraceDiffBlock) => blockTime(left.firstSeenMs) - blockTime(right.firstSeenMs);
  const byRva = (left: TraceDiffBlock, right: TraceDiffBlock) => Number.parseInt(left.rva, 16) - Number.parseInt(right.rva, 16);
  const fullA = [...onlyInA].sort(byRva);
  const fullB = [...onlyInB].sort(byRva);
  onlyInA.sort(byTime);
  onlyInB.sort(byTime);
  const summary = summarizeTraceDiff(runA.blocks, runB.blocks);
  let fullDiffFile: string | null = null;
  if (onlyInA.length > TRACE_DIFF_TOP_N || onlyInB.length > TRACE_DIFF_TOP_N) {
    const { writeOutputSpill } = await import("./outputbudget.js");
    fullDiffFile = await writeOutputSpill(
      workspace,
      "trace_diff",
      JSON.stringify({ blocksOnlyInA: fullA, blocksOnlyInB: fullB, sharedBlockCount: shared }, null, 2),
    );
    notes.push(
      `diff truncated to the earliest ${TRACE_DIFF_TOP_N} blocks per side (${onlyInA.length} only-in-A, ${onlyInB.length} only-in-B total); full diff saved to ${fullDiffFile}`,
    );
  }
  if (runA.blocks.size === 0 && runB.blocks.size === 0) {
    notes.push("no blocks recorded in either run — the sample may have exited before Stalker saw any execution");
  }
  return {
    status: "ok",
    runA: { pid: runA.pid, blockCount: runA.blocks.size },
    runB: { pid: runB.pid, blockCount: runB.blocks.size },
    blocksOnlyInA: onlyInA.slice(0, TRACE_DIFF_TOP_N),
    blocksOnlyInB: onlyInB.slice(0, TRACE_DIFF_TOP_N),
    sharedBlockCount: shared,
    summary,
    fullDiffFile,
    notes,
  };
}

export async function runTraceDiff(
  workspace: Workspace,
  userPath: string,
  options: TraceDiffOptions = {},
): Promise<TraceDiffResult> {
  const binding = (await import("frida")) as unknown as FridaModuleBinding;
  const device = await binding.getLocalDevice();
  const absolutePath = await workspace.resolveFile(userPath);
  const probeSeconds = Math.min(60, Math.max(2, options.probeSeconds ?? 10));
  void binding;
  const argsA = options.argsA ?? [];
  const argsB = options.argsB ?? [];
  const runDir = path.join(workspace.root, ".minusone", "run", randomUUID().slice(0, 8));
  await mkdir(runDir, { recursive: true });
  const notes: string[] = [
    "blocks are sample-module RVAs at basic-block entry — feed the differing RVAs to function.decompile.range or disassembly_dump",
  ];

  try {
    const entryRva = await resolveEntrypointRva(absolutePath);
    const runA = await runStalkerProfile(device, absolutePath, argsA, runDir, probeSeconds, entryRva);
    const runB = await runStalkerProfile(device, absolutePath, argsB, runDir, probeSeconds, entryRva);
    return await composeTraceDiffResult(workspace, runA, runB, notes);
  } catch (error) {
    return {
      status: "error",
      runA: { pid: -1, blockCount: 0 },
      runB: { pid: -1, blockCount: 0 },
      blocksOnlyInA: [],
      blocksOnlyInB: [],
      sharedBlockCount: 0,
      summary: { counts: { runA: 0, runB: 0, shared: 0, onlyA: 0, onlyB: 0 }, firstDivergence: null, reconvergences: [] },
      fullDiffFile: null,
      notes,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
