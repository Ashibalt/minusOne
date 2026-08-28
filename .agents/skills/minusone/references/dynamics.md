# minusOne dynamic plane — in depth

The dynamic plane is where engagements are won, and also where the most
surprising contracts live. Read this before your first live run.

## Gating

Dynamic operations execute the sample on the owner's machine, so they are gated:
`minusOne arm` once per machine writes `.minusone/config.json`
(`dynamic: "local"`), after which every session just works. Unarmed refusal is
the designed default, not an error. Static operations are never gated.

## Spawn vs attach — the property that decides usefulness

| Operation | Instance lifecycle |
|---|---|
| `sample_execute`, `dynamic_frida`, `frida_script`, `trace_source`, `trace_diff`, `dynamic_unpack`, `unpack_chain`, `dynamic_recon`, `debug_session_create` (gdb/x64dbg), `trace_record` | **Spawn their own instance.** You get no say over which process it is, and for a TUI/GUI the spawned instance may be undrivable (no console you own) |
| `console_launch` | Spawns the instance AND hands you its pid + drivable console — the entry point of the one-live-instance pattern |
| `console_send`, `console_read`, `process_kill` | **Attach by pid** to any live process |
| Raw frida (`frida.attach(pid)`), raw `TTD.exe -attach <pid>` | Attach by pid — currently via hand-rolled scripts; native attach modes are being added to `frida_script` / `trace_record` |

**The one-live-instance pattern** (the shape that won every interactive
engagement): `console_launch` once → drive with `console_send` → attach every
other instrument to the same pid (frida attach, TTD attach, pe-sieve /pid) →
`process_kill` when done. Spawning a second instance loses accumulated state,
and for self-relaunching samples can fork into a cascade of copies.

## TUI driving recipe

1. `console_launch` (hidden by default; the screen buffer is fully readable).
2. `console_read` to see the screen; `console_send` with `readBack:true` for
   type→settle→read round-trips. `{ENTER}` and other special keys ride as INPUT_RECORDs.
3. Send exactly one Enter per field — queued input events outlive the current
   screen and can feed a re-launched copy (self-restarting samples cascade).
4. A verdict screen that vanishes in milliseconds is normal: hook
   `ExitProcess`/`RtlExitUserProcess`/`TerminateProcess` with frida and replace
   them with a stall (see frida recipe) — the frozen process keeps its console
   and memory available for reading and dumping at leisure.
5. If a launched process exits before you finished reading: the console buffer
   dies with the last attached process, so hook writes (`WriteConsoleW`) to log
   text as it is produced instead of reading the screen post-mortem.

## TTD recipe (time travel — the backward question answered)

Recording requires ELEVATION. `tools/ttd/TTD.exe` ships with the toolchain.

1. Record: `trace_record` (launch mode) or, for an already-driven instance,
   `TTD.exe -attach <pid> -out <dir>` (attach mode; minusOne attach mode is being
   added). Drive the scenario while recording (console_send works on the
   recorded pid). Killing the process finalizes the trace cleanly.
2. Replay: `trace_replay` with a command batch. **The client call times out long
   before the replay ends — poll `replay-out.txt` beside the trace file for the
   real output** (`.logopen` wrapping captures every command's answer there).
3. Backward-walk pattern that works: end of trace (`!tt <end>` or `!tt 100`) →
   set a READ breakpoint on the artifact you care about (a verdict string, an
   input buffer: `ba r4 <addr>`) → `g-` steps BACK to the last code that read it
   → `k` shows the full call chain → repeat `g-` to walk from render → decision
   → comparison → the birth of the compared value. `!positions` lists thread
   positions; `r`, `u`, `db/dq` inspect state at any stop.
4. TTD is a recorder, not a debugger: PEB-based anti-debug checks pass, and
   timing checks see real execution. Heavier samples slow 10-100× while
   recording — plan drive-input timing accordingly.

## Frida agent recipes (frida 17)

minusOne's `frida_script` runs your agent JS against a spawned instance; raw
`frida.attach(pid)` attaches to a driven one. Field-proven details:

- **Export resolution**: `Module.getExportAddress` is GONE in frida 17. Use
  `Process.getModuleByName("kernel32.dll").getExportByName("ExitProcess")`
  (guard with try/catch across kernel32/KernelBase/ntdll).
- **Getting bytes out**: `new File()` is removed. `send(payload, arrayBuffer)`
  streams binary to the host script — write the file there.
- **Exit-freeze**: `Interceptor.replace(ExitProcess, new NativeCallback(function
  (code) { /* dump, then */ while (true) { Thread.sleep(3600); } }, "void",
  ["uint"]))` — the process stays alive with all state intact. Also replace
  `RtlExitUserProcess` and `TerminateProcess` (each is a separate exit path).
- **MemoryAccessMonitor vs VEH**: guard-page monitoring collides with a sample's
  own vectored exception handler (the event loop dies silently — CPU 0, UI
  frozen). Use Interceptor hooks or TTD on VEH-protected samples.
- **Stalker**: the raw Stalker API on Windows has a series of traps (thread
  lifetime, event delivery). The canned `trace_source` / `trace_diff` planes
  already encode the working recipe — prefer them over hand-rolled Stalker.
- **Anti-debug**: frida attaches via remote thread — no debug port, no
  BeingDebugged, no QPC slowdown. Samples that hang under gdb often run clean
  under frida.

## gdb on Windows (MSYS2) — facts

- `info proc mappings` is unsupported; get the image base from `info files`
  (section runtime ranges) and compute the slide once.
- `harden: true` neutralizes PEB.BeingDebugged, NtGlobalFlag and heap flags at
  every stop. It does NOT cover CheckRemoteDebuggerPresent (debug port),
  QueryPerformanceCounter timing gates, DR-register scans, or self-debugging
  parents — a sample that still stalls under a hardened gdb is detecting one of
  those; switch to frida or TTD, or (when the engagement rules allow) patch the
  anti-debug battery in a scratch copy and debug that.
- `debug_kill` recovers a wedged `continue` without losing breakpoints.
- For string-argument breakpoints (call X only when arg contains Y) use
  `debug_break` — raw gdb conditions on untyped registers abort.

## Which plane survives which anti-analysis

| Defense | gdb+harden | frida | TTD | Patch battery (if rules allow) |
|---|---|---|---|---|
| IsDebuggerPresent / PEB flags | survives | survives | survives | survives |
| CheckRemoteDebuggerPresent (debug port) | detected | survives | survives | survives |
| QPC/timing gates | detected (when stopped mid-gate) | survives | slows but real-time | patch the gate |
| Tool-name blacklist scans | depends on tool name | frida rarely blacklisted | TTD rarely blacklisted | n/a |
| Guard-page-based tricks | — | conflicts (own VEH) | survives | n/a |

## Cleanup

`process_kill` detached instances, `debug_session_close` debugger sessions,
`job_kill` runaway jobs. A graveyard of half-driven sample copies pollutes
console reads, process lists, and your own mental model of which pid is which.
