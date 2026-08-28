/**
 * Anti-anti-debug hardening for gdb sessions (ScyllaHide-style, gdb-python).
 *
 * The classic block: a protected sample under a debugger reads its own PEB
 * (BeingDebugged, NtGlobalFlag), the process-heap flags, or calls
 * CheckRemoteDebuggerPresent / OutputDebugStringA and silently exits. The
 * fix is to neutralize the OBSERVABLE debug state:
 *
 *   - PEB.BeingDebugged = 0
 *   - PEB.NtGlobalFlag = 0 (the FLG_HEAP_* triple debug heaps set)
 *   - PEB.ProcessHeap flags: debug-heap signature (0x50000061) normalized to
 *     the release value (0x40000061), ForceFlags cleared — a classic check
 *
 * PEB discovery: gdb's $gs_base convenience register is NOT populated by the
 * MSYS2 gdb on native Windows ("$1 = void"), so the script resolves the PEB
 * through NtQueryInformationProcess(ProcessBasicInformation) from the gdb
 * python process itself (ctypes) and then reads/writes the target through
 * gdb's inferior memory API. The script re-applies itself at every stop
 * (gdb stop-events): packers re-poll these fields in loops, a one-time
 * patch is not enough.
 *
 * What this does NOT cover (honest limits): hardware-breakpoint DR-register
 * scans, timing checks (RDTSC deltas), self-debugging parent checks,
 * CloseHandle invalid-handle tricks, and CRC of the debugged code pages.
 * Those need per-sample work; the session report says so.
 */

/** gdb python executed right after starti and re-run at every stop. */
export const GDB_ANTI_ANTI_DEBUG_PY = `
import ctypes
import gdb
import struct

_peb = [0]

def _resolve_peb():
    inf = gdb.selected_inferior()
    h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, inf.pid)
    if not h:
        return 0
    pbi = ctypes.create_string_buffer(64)
    ok = ctypes.windll.ntdll.NtQueryInformationProcess(h, 0, pbi, 48, None)
    ctypes.windll.kernel32.CloseHandle(h)
    if ok != 0:
        return 0
    return struct.unpack("<Q", pbi.raw[8:16])[0]

def _poke(inf, addr, size, value):
    try:
        cur = int.from_bytes(inf.read_memory(addr, size).tobytes(), "little")
        if cur == value:
            return True
        inf.write_memory(addr, value.to_bytes(size, "little"))
        return True
    except Exception:
        return False

def _apply():
    inf = gdb.selected_inferior()
    if _peb[0] == 0:
        _peb[0] = _resolve_peb()
    peb = _peb[0]
    if peb == 0:
        print("minusOne-antiantidebug: PEB not resolved (inferior not started?)")
        return
    results = []
    results.append(("BeingDebugged=0", _poke(inf, peb + 2, 1, 0)))
    results.append(("NtGlobalFlag=0", _poke(inf, peb + 0xBC, 4, 0)))
    try:
        heap = struct.unpack("<Q", inf.read_memory(peb + 0x30, 8).tobytes())[0]
        if heap:
            flags = struct.unpack("<I", inf.read_memory(heap + 0x70, 4).tobytes())[0]
            if (flags & 0x10000000) != 0:
                results.append(("HeapFlags normalized", _poke(inf, heap + 0x70, 4, 0x40000061)))
            force = struct.unpack("<I", inf.read_memory(heap + 0x74, 4).tobytes())[0]
            if force != 0:
                results.append(("HeapForceFlags=0", _poke(inf, heap + 0x74, 4, 0)))
    except Exception:
        pass
    for name, ok in results:
        print("minusOne-antiantidebug: %s %s" % (name, "ok" if ok else "FAILED"))

class MinusOneAntiAntiDebug(gdb.Command):
    def __init__(self):
        super(MinusOneAntiAntiDebug, self).__init__("minusOne-antiantidebug", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        _apply()

MinusOneAntiAntiDebug()

def _on_stop(event):
    try:
        gdb.execute("minusOne-antiantidebug", to_string=True)
    except Exception:
        pass

try:
    gdb.events.stop.connect(_on_stop)
    print("minusOne-antiantidebug: armed (re-applied at every stop)")
except Exception:
    print("minusOne-antiantidebug: armed (one-shot; stop events unavailable)")

gdb.execute("minusOne-antiantidebug")
`;

/** Honest capability statement surfaced to the model in session create. */
export const ANTI_ANTI_DEBUG_LIMITS = [
  "harden neutralizes PEB.BeingDebugged, NtGlobalFlag and process-heap debug flags at every stop (gdb-python)",
  "NOT covered: DR-register hardware-breakpoint scans, RDTSC timing checks, self-debugging parents, CRC integrity checks",
];

export function antiAntiDebugSummary(applied: boolean): { applied: boolean; what: string[]; limits: string[] } {
  return {
    applied,
    what: applied
      ? ["PEB.BeingDebugged = 0", "PEB.NtGlobalFlag = 0", "process-heap ForceFlags cleared, debug signature flags normalized", "PEB resolved via NtQueryInformationProcess (gdb $gs_base is not populated on MSYS2)", "re-applied at every stop (packers re-poll in loops)"]
      : [],
    limits: applied ? ANTI_ANTI_DEBUG_LIMITS : [],
  };
}
