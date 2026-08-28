/**
 * Interactive console plane (Windows): the last mile of TUI crackmes.
 * Console apps that draw a full-screen UI (ratatui/crossterm, ncurses ports)
 * read INPUT_RECORDs from the console input buffer — stdin pipes are dead
 * for them, which is exactly what stalled combat sessions for hours. This
 * module talks the native console protocol instead:
 *
 *   send  — WriteConsoleInputW synthetic key events into the target console
 *   read  — ReadConsoleOutputCharacterW the screen buffer back as text rows
 *
 * Driver model: a PowerShell host (Add-Type compiled once to a content-hash
 * named DLL, reused afterwards) attaches to the target console via
 * FreeConsole() + AttachConsole(pid). Field lessons baked in: FreeConsole
 * MUST run before AttachConsole or the attach silently returns false, and
 * the driver must be a .ps1 file — inline PS escapes break.
 *
 * Key markers in `text` map to real virtual-key events ({UP}, {ENTER},
 * {CTRL+C}, ...), plain characters ride as Unicode key events — the same
 * records a physical keyboard produces.
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { runBoundedCommand } from "./command.js";
import type { Workspace } from "./workspace.js";

export const CONSOLE_MAX_TEXT_CHARS = 2000;
export const CONSOLE_MAX_ROWS = 200;
export const CONSOLE_DEFAULT_KEY_DELAY_MS = 15;
export const CONSOLE_DEFAULT_SETTLE_MS = 400;
const CONSOLE_DRIVER_DIR = path.join(".minusone", "console");
const CONSOLE_DRIVER_TIMEOUT_MS = 90_000;

/** C# side of the driver: console attach, key synthesis, screen reading. */
const CONSOLE_CSHARP = String.raw`
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class MConsole {
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll")] public static extern bool FreeConsole();
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool WriteConsoleInputW(IntPtr h, INPUT_RECORD[] buf, uint len, out uint written);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ReadConsoleOutputCharacterW(IntPtr h, StringBuilder buf, int len, COORD origin, out int read);
  [DllImport("kernel32.dll")] private static extern bool GetConsoleScreenBufferInfo(IntPtr h, out SB info);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern short VkKeyScanW(char ch);

  private static readonly IntPtr INVALID = new IntPtr(-1);

  // CONIN$/CONOUT$ always refer to the console the process is CURRENTLY
  // attached to. GetStdHandle is the trap here: AttachConsole does not
  // refresh the cached std handles, so they still point at the console we
  // freed (or at startup pipes) and every console API fails on them.
  private static IntPtr OpenCon(string name, uint access) {
    IntPtr h = CreateFileW(name, access, 0x00000003, IntPtr.Zero, 3, 0, IntPtr.Zero);
    return h == INVALID ? IntPtr.Zero : h;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT_RECORD { public ushort EventType; public KEY_EVENT_RECORD Event; }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct KEY_EVENT_RECORD { public bool down; public ushort repeat; public ushort vk; public ushort scan; public char ch; public uint state; }
  [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X; public short Y; }
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public short L; public short T; public short R; public short B; }
  [StructLayout(LayoutKind.Sequential)] public struct SB { public COORD Size; public COORD Cursor; public ushort Attr; public RECT Window; public COORD Max; }

  private const uint LEFT_CTRL_PRESSED = 0x0008;

  private static readonly Dictionary<string, ushort[]> KEYS = new Dictionary<string, ushort[]> {
    {"ENTER", new ushort[]{0x0D, 0x1C}}, {"ESC", new ushort[]{0x1B, 0x01}},
    {"TAB", new ushort[]{0x09, 0x0F}}, {"BACKSPACE", new ushort[]{0x08, 0x0E}},
    {"DELETE", new ushort[]{0x2E, 0x53}}, {"DEL", new ushort[]{0x2E, 0x53}},
    {"INSERT", new ushort[]{0x2D, 0x52}}, {"INS", new ushort[]{0x2D, 0x52}},
    {"HOME", new ushort[]{0x24, 0x47}}, {"END", new ushort[]{0x23, 0x4F}},
    {"PGUP", new ushort[]{0x21, 0x49}}, {"PGDN", new ushort[]{0x22, 0x51}},
    {"UP", new ushort[]{0x26, 0x48}}, {"DOWN", new ushort[]{0x28, 0x50}},
    {"LEFT", new ushort[]{0x25, 0x4B}}, {"RIGHT", new ushort[]{0x27, 0x4D}},
    {"F1", new ushort[]{0x70, 0x3B}}, {"F2", new ushort[]{0x71, 0x3C}},
    {"F3", new ushort[]{0x72, 0x3D}}, {"F4", new ushort[]{0x73, 0x3E}},
    {"F5", new ushort[]{0x74, 0x3F}}, {"F6", new ushort[]{0x75, 0x40}},
    {"F7", new ushort[]{0x76, 0x41}}, {"F8", new ushort[]{0x77, 0x42}},
    {"F9", new ushort[]{0x78, 0x43}}, {"F10", new ushort[]{0x79, 0x44}},
    {"F11", new ushort[]{0x7A, 0x57}}, {"F12", new ushort[]{0x7B, 0x58}},
    {"SPACE", new ushort[]{0x20, 0x39}},
  };

  private static void Rec(IntPtr h, bool down, ushort vk, ushort scan, char c, uint state) {
    var r = new INPUT_RECORD { EventType = 1, Event = new KEY_EVENT_RECORD { down = down, repeat = 1, vk = vk, scan = scan, ch = c, state = state } };
    uint w; WriteConsoleInputW(h, new INPUT_RECORD[] { r }, 1, out w);
  }

  private static void Tap(IntPtr h, ushort vk, ushort scan, char c, uint state, int delayMs) {
    Rec(h, true, vk, scan, c, state);
    Rec(h, false, vk, scan, c, state);
    if (delayMs > 0) Thread.Sleep(delayMs);
  }

  public static int Send(string text, int keyDelayMs) {
    IntPtr h = OpenCon("CONIN$", 0xC0000000);
    if (h == IntPtr.Zero) return -1;
    int sent = 0;
    int i = 0;
    while (i < text.Length) {
      char c = text[i];
      if (c == '{') {
        int close = text.IndexOf('}', i + 1);
        if (close > i) {
          string name = text.Substring(i + 1, close - i - 1);
          string upper = name.ToUpperInvariant();
          ushort[] kv;
          if (upper.StartsWith("CTRL+") && upper.Length == 6) {
            char letter = upper[5];
            if (letter >= 'A' && letter <= 'Z') {
              ushort vk = letter;
              ushort scan = (ushort)(letter - 'A' + 0x1E);
              Tap(h, vk, scan, char.ToLowerInvariant(letter), LEFT_CTRL_PRESSED, keyDelayMs);
              i = close + 1; sent++; continue;
            }
          }
          if (KEYS.TryGetValue(upper, out kv)) {
            char evc = '\0';
            if (upper == "ENTER") evc = '\r';
            else if (upper == "TAB") evc = '\t';
            else if (upper == "ESC") evc = (char)27;
            else if (upper == "BACKSPACE") evc = (char)8;
            else if (upper == "SPACE") evc = ' ';
            Tap(h, kv[0], kv[1], evc, 0, keyDelayMs);
            i = close + 1; sent++; continue;
          }
        }
      }
      if (c == '\n' || c == '\r') Tap(h, 0x0D, 0x1C, '\r', 0, keyDelayMs);
      else if (c == '\t') Tap(h, 0x09, 0x0F, '\t', 0, keyDelayMs);
      else if (c == '\b') Tap(h, 0x08, 0x0E, (char)8, 0, keyDelayMs);
      else if (c == '\x1b') Tap(h, 0x1B, 0x01, (char)27, 0, keyDelayMs);
      else {
        // Plain characters MUST carry their real virtual-key code: _getch()
        // treats a key event with vk==0 as an extended/prefix key and eats
        // the next event — characters typed as vk=0 never reach the app.
        // VkKeyScanW depends on the calling thread's keyboard layout, which
        // is unreliable in a headless service context, so ASCII gets its VK
        // computed directly (0x41..5A / 0x30..39) and everything else falls
        // back to VkKeyScanW.
        ushort vk = 0;
        if (c >= 'a' && c <= 'z') vk = (ushort)(c - 'a' + 0x41);
        else if (c >= 'A' && c <= 'Z') vk = (ushort)c;
        else if (c >= '0' && c <= '9') vk = (ushort)c;
        else {
          short vkScan = VkKeyScanW(c);
          if (vkScan >= 0) vk = (ushort)(vkScan & 0xFF);
        }
        Tap(h, vk, 0, c, 0, keyDelayMs);
      }
      i++; sent++;
    }
    return sent;
  }

  public static int W, H, CX, CY;

  public static List<string> ReadRows(int maxRows) {
    // Screen-buffer APIs need the OUTPUT console (CONOUT$), not CONIN$.
    IntPtr h = OpenCon("CONOUT$", 0x80000000);
    if (h == IntPtr.Zero) return null;
    SB info;
    if (!GetConsoleScreenBufferInfo(h, out info)) return null;
    W = info.Size.X;
    H = info.Window.B - info.Window.T + 1;
    CX = info.Cursor.X;
    CY = info.Cursor.Y - info.Window.T;
    var rows = new List<string>();
    int count = Math.Min(H, maxRows);
    for (int row = 0; row < count; row++) {
      var sb = new StringBuilder(W);
      int read;
      COORD origin = new COORD { X = 0, Y = (short)(info.Window.T + row) };
      if (ReadConsoleOutputCharacterW(h, sb, W, origin, out read)) rows.Add(sb.ToString(0, read));
      else rows.Add("");
    }
    return rows;
  }
}
`.trim();

/** The PowerShell wrapper around the C# driver (mode: send | read | roundtrip). */
const CONSOLE_DRIVER_PS = String.raw`
param(
  [Parameter(Mandatory=$true)][int]$TargetPid,
  [ValidateSet('send','read','roundtrip')][string]$Mode = 'send',
  [string]$B64 = '',
  [string]$DllPath = '',
  [int]$KeyDelayMs = 15,
  [int]$SettleMs = 400,
  [int]$MaxRows = 200
)
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$source = @'
__CSHARP__
'@
try {
  if ($DllPath -ne '' -and (Test-Path $DllPath)) {
    Add-Type -Path $DllPath
  } else {
    if ($DllPath -ne '') {
      try { Add-Type -TypeDefinition $source -OutputAssembly $DllPath } catch {}
    }
    if ($DllPath -ne '' -and (Test-Path $DllPath)) { Add-Type -Path $DllPath }
    else { Add-Type -TypeDefinition $source }
  }
} catch {
  @{ attached = $false; error = "driver compile failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress
  exit 0
}
$out = [ordered]@{ attached = $false; keysSent = 0 }
try {
  [MConsole]::FreeConsole() | Out-Null
  if (-not [MConsole]::AttachConsole([uint32][Math]::Abs($TargetPid))) {
    $out.error = "AttachConsole($TargetPid) failed: no such process, not a console process, or it is attached to this console already"
  } else {
    $out.attached = $true
    if ($Mode -ne 'read' -and $B64 -ne '') {
      $text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($B64))
      $out.keysSent = [MConsole]::Send($text, $KeyDelayMs)
      if ($out.keysSent -lt 0) { $out.error = 'opening CONIN$ failed after attach' }
    }
    if ($Mode -ne 'send' -and $out.attached) {
      if ($Mode -eq 'roundtrip' -and $SettleMs -gt 0) { Start-Sleep -Milliseconds $SettleMs }
      $rows = [MConsole]::ReadRows($MaxRows)
      if ($null -ne $rows) {
        $out.width = [MConsole]::W
        $out.height = [MConsole]::H
        $out.cursorX = [MConsole]::CX
        $out.cursorY = [MConsole]::CY
        $out.rows = @($rows)
      } else {
        $out.readError = 'GetConsoleScreenBufferInfo failed'
      }
    }
  }
} finally {
  [MConsole]::FreeConsole() | Out-Null
}
$out | ConvertTo-Json -Compress
`.trim().replace("__CSHARP__", CONSOLE_CSHARP);

export interface ConsoleScreen {
  width: number;
  height: number;
  cursorX: number;
  cursorY: number;
  rows: string[];
  text: string;
}

export interface ConsoleSendResult {
  pid: number;
  attached: boolean;
  keysSent: number;
  screen?: ConsoleScreen;
  error?: string;
}

export interface ConsoleReadResult {
  pid: number;
  attached: boolean;
  screen?: ConsoleScreen;
  error?: string;
}

interface DriverOutcome {
  attached?: boolean;
  keysSent?: number;
  error?: string;
  readError?: string;
  width?: number;
  height?: number;
  cursorX?: number;
  cursorY?: number;
  rows?: string[];
}

async function ensureDriver(workspace: Workspace): Promise<string> {
  const directory = path.join(workspace.root, CONSOLE_DRIVER_DIR);
  await mkdir(directory, { recursive: true });
  const script = path.join(directory, "console-driver.ps1");
  await writeFile(script, CONSOLE_DRIVER_PS, "utf8");
  return script;
}

function driverDllPath(workspace: Workspace): string {
  // Content-hash naming: a changed C# source compiles to a new DLL, a stale
  // one can never be picked up, and concurrent runs never fight over it.
  const hash = createHash("sha256").update(CONSOLE_CSHARP).digest("hex").slice(0, 8);
  return path.join(workspace.root, CONSOLE_DRIVER_DIR, `mconsole-${hash}.dll`);
}

function toScreen(outcome: DriverOutcome): ConsoleScreen | undefined {
  if (outcome.rows === undefined || outcome.width === undefined || outcome.height === undefined) return undefined;
  const rows = outcome.rows.map((row) => row.replace(/\s+$/, ""));
  return {
    width: outcome.width,
    height: outcome.height,
    cursorX: outcome.cursorX ?? 0,
    cursorY: outcome.cursorY ?? 0,
    rows,
    text: rows.join("\n").trim(),
  };
}

async function runDriver(
  workspace: Workspace,
  pid: number,
  mode: "send" | "read" | "roundtrip",
  text: string | undefined,
  options: { keyDelayMs?: number; settleMs?: number; maxRows?: number },
): Promise<DriverOutcome> {
  const script = await ensureDriver(workspace);
  const b64 = text === undefined || text === "" ? "" : Buffer.from(text, "utf16le").toString("base64");
  const keyDelayMs = options.keyDelayMs ?? CONSOLE_DEFAULT_KEY_DELAY_MS;
  const settleMs = options.settleMs ?? CONSOLE_DEFAULT_SETTLE_MS;
  const maxRows = Math.min(Math.max(options.maxRows ?? CONSOLE_MAX_ROWS, 1), CONSOLE_MAX_ROWS);
  const estimateMs = 8_000 + (text?.length ?? 0) * (keyDelayMs + 10) + (mode === "send" ? 0 : settleMs + 2_000);
  const result = await runBoundedCommand(
    "powershell",
    [
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
      "-TargetPid", String(pid),
      "-Mode", mode,
      "-B64", b64,
      "-DllPath", driverDllPath(workspace),
      "-KeyDelayMs", String(keyDelayMs),
      "-SettleMs", String(settleMs),
      "-MaxRows", String(maxRows),
    ],
    { timeoutMs: Math.min(estimateMs, CONSOLE_DRIVER_TIMEOUT_MS), maxOutputBytes: 512 * 1024 },
  );
  const stdout = result.stdout.trim();
  if (stdout === "") {
    throw new Error(`console driver produced no output (exit ${result.exitCode}${result.timedOut ? ", timed out" : ""}): ${result.stderr.trim().slice(0, 500)}`);
  }
  const jsonLine = stdout.split(/\r?\n/).at(-1) ?? "";
  let outcome: DriverOutcome;
  try {
    outcome = JSON.parse(jsonLine) as DriverOutcome;
  } catch {
    throw new Error(`console driver output is not JSON: ${jsonLine.slice(0, 500)}`);
  }
  return outcome;
}

export interface ConsoleSendOptions {
  /** Append one ENTER after the text (default false; `\n` in text also types Enter). */
  enter?: boolean;
  /** Read the screen back in the same driver call (the TUI round-trip loop). */
  readBack?: boolean;
  keyDelayMs?: number;
  settleMs?: number;
  maxRows?: number;
}

export async function sendConsoleInput(
  workspace: Workspace,
  pid: number,
  text: string,
  options: ConsoleSendOptions = {},
): Promise<ConsoleSendResult> {
  if (process.platform !== "win32") {
    throw new Error("console.send is Windows-only: it drives the Win32 console plane (WriteConsoleInputW)");
  }
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`invalid pid ${JSON.stringify(pid)}`);
  }
  if (text.length > CONSOLE_MAX_TEXT_CHARS) {
    throw new Error(`text is ${text.length} chars; the cap is ${CONSOLE_MAX_TEXT_CHARS} (split across calls)`);
  }
  const full = options.enter === true && !/\n$/.test(text) ? `${text}\n` : text;
  const mode = options.readBack === true ? "roundtrip" : "send";
  const outcome = await runDriver(workspace, pid, mode, full, {
    ...(options.keyDelayMs === undefined ? {} : { keyDelayMs: options.keyDelayMs }),
    ...(options.settleMs === undefined ? {} : { settleMs: options.settleMs }),
    ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
  });
  const screen = toScreen(outcome);
  const errors = [outcome.error, outcome.readError].filter((entry): entry is string => typeof entry === "string");
  return {
    pid,
    attached: outcome.attached === true,
    keysSent: outcome.keysSent ?? 0,
    ...(screen === undefined ? {} : { screen }),
    ...(errors.length > 0 ? { error: errors.join("; ") } : {}),
  };
}

export async function readConsoleScreen(
  workspace: Workspace,
  pid: number,
  options: { maxRows?: number } = {},
): Promise<ConsoleReadResult> {
  if (process.platform !== "win32") {
    throw new Error("console.read is Windows-only: it reads the Win32 console screen buffer (ReadConsoleOutputCharacterW)");
  }
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`invalid pid ${JSON.stringify(pid)}`);
  }
  const outcome = await runDriver(workspace, pid, "read", undefined, {
    ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
  });
  const screen = toScreen(outcome);
  const errors = [outcome.error, outcome.readError].filter((entry): entry is string => typeof entry === "string");
  return {
    pid,
    attached: outcome.attached === true,
    ...(screen === undefined ? {} : { screen }),
    ...(errors.length > 0 ? { error: errors.join("; ") } : {}),
  };
}

/** Exposed for tests: the driver script content, so the field lessons stay locked in. */
export function consoleDriverScript(): string {
  return CONSOLE_DRIVER_PS;
}
