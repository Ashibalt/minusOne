# minusOne operation cards

One card per operation: the question it answers, sync vs job, execution mode, and
maturity. This is the full index behind the SKILL.md backbone — consult it when
you suspect a purpose-built operation exists for your current question (it
probably does).

**Maturity labels**
- **combat** — fired successfully in real engagements; its behavior is known from
  field use, not just tests.
- **tested** — covered by automated contract/unit/smoke tests; has not yet been
  the decisive tool in a real engagement.

**Execution modes**
- **static** — the sample is data; it never executes.
- **spawn** — the operation launches its own instance of the sample. Useless when
  you must drive one specific live instance (TUI, accumulated state).
- **attach** — the operation targets an already-running PID.
- **postmortem** — operates on captured data (dumps, traces, CSV); nothing live.

Jobs return a job id immediately — poll `job_output(wait: true)`; the finished
output often carries an artifact id to page with `artifact_read`.

## First look & structure (static)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `binary_triage` | What is this file — format, entropy, imports by risk, packer verdict, IOCs, capabilities? The first call on any unknown binary | static, sync | combat |
| `signature_verify` | Is the Authenticode chain + digest valid? A VALID signature kills any "packed/patched" entropy verdict | static, sync | tested |
| `packer_detect` | Which packer/compiler/protector (DIE) + per-section entropy? | static, sync | combat |
| `batch_survey` | The complete structural table (sections, imports, exports, entrypoint, symbols) of up to 8 binaries as JSON | static, sync | tested |
| `binary_inspect` | SHA-256, entropy, basic format of one file | static, sync | tested |
| `pe_resources` | Version info + manifest from the PE resource directory | static, sync | tested |
| `capabilities_detect` | capa: capabilities + MITRE ATT&CK techniques | static, JOB | combat |
| `analysis_baseline` | Legacy baseline — use `binary_triage` instead | static, sync | legacy |

## Strings & search (static)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `strings_find` | ONE plane, four modes: multi-plane needle fan-out (`leading-window`), exhaustive whole-file search (`whole-file`), plain string dump (`plain-strings`), FLOSS deobfuscation (`deep-floss`, job) | static, sync/JOB by mode | combat |
| `binary_find` / `binary_search` | Where is this needle (text/bytes/regex/imports/symbols)? — aliases of strings_find modes, kept for compatibility | static, sync | combat |
| `strings_extract` / `strings_extract_deep` | Plain dump / FLOSS job — aliases of strings_find modes | static, sync/JOB | combat |
| `dumps_floss` | FLOSS every module in a pe-sieve dump directory in one call | static, JOB | combat |
| `config_extract` | The malware-config harvest: C2, mutexes, persistence keys, campaign IDs, XOR keys — decoded strings first | static, sync | combat |
| `rules_scan` | Does this YARA ruleset (source or precompiled) match, and where? | static, JOB | tested |
| `embedded_scan` | What archives/filesystems/payloads are embedded, at which offsets (binwalk signatures)? | static, sync | tested |
| `embedded_extract` | Carve those embedded objects out (carve-only — no extractor ever runs) | static, JOB | tested |

## Navigation & decompilation (static)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `binary_explain` | Who uses this needle and what does that code do — search→xrefs→decompile of referrers in ONE call | static, sync | tested |
| `xref_query` | Who references this VA/RVA/offset (cached r2 session, ms-fast after first analysis) | static, sync | combat |
| `disassembly_functions` | Enumerate functions in a stripped binary (r2 aaa, job) | static, JOB | combat |
| `disassembly_dump` | Disassembly or hex at an address/symbol, analysis-backed names | static, sync | combat |
| `disassembly_list` | objdump disassembly or raw section dump (`section:` for .rdata etc.) | static, sync | combat |
| `function_decompile` | Ghidra pseudocode for chosen functions (job; auto-falls back to range slicing on megaprocedures) | static, JOB | combat |
| `function_decompile_range` | The megaprocedure slicer: decompile a VA range with short budgets + disassembly fallback | static, sync | combat |
| `function_deobfuscate` | d810 microcode rewriting: collapse MBA, kill opaque predicates, unflatten — side-by-side with baseline | static, sync | combat |
| `ida_functions` | IDA headless function list (FLIRT/DWARF recovery beats r2 on complex binaries) | static, JOB | combat |
| `ida_decompile` | Hex-Rays pseudocode for chosen functions | static, JOB | combat |
| `model_rank_pseudocode` | BinSeek: rank decompiled snippets against a plain-language query — first navigation step on decompilable binaries | static, sync | tested |
| `model_rank_assembly` | CLAP: rank RAW disassembly when the decompiler died — the megaprocedure/obfuscated domain | static, sync | combat |

## Address & data plane (static)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `memory_read` | Bytes/decoded values at a VA/RVA/offset with zero manual arithmetic; `chasePointers` walks pointer tables; also reads LIVE memory of a debug session | static (+live), sync | combat |
| `binary_diff` | What changed between two builds — byte-level diff with section context + Ghidra decompile of changed regions | static, sync | tested |
| `annotate_symbol` | Persist VA→name(+comment); every later operation shows your names — the compounding loop | static, sync | tested |
| `artifact_list` / `artifact_read` | Page large stored outputs (decompiler reports, scans) | static, sync | combat |
| `artifact_export` | Materialize an artifact (decoded strings, carved files, code) as a real file | static, sync | tested |

## Dynamic — spawning the sample (gated, owner-armed)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `sample_execute` | Run a CLI sample with args/stdin in an isolated run dir — exit code, output, dropped files. stdin is dead for INPUT_RECORD TUIs | spawn, JOB | combat |
| `dynamic_frida` | Canned behavioral probe: modules + file/registry/network API calls with argument previews | spawn, JOB | combat |
| `frida_script` | YOUR frida agent against the sample (Interceptor/Stalker/rpc), events streamed to a JSONL log; `childGating` counters self-debug spawn schemes | spawn, sync | combat |
| `trace_source` | Behavior→function bridge: hooks the behavioral API catalog, converts backtraces to static VAs, decompiles hot sites | spawn, JOB | tested |
| `trace_diff` | Execution diff of two runs (args A vs B): first divergence, reconvergences, diverging block lists | spawn, sync | tested |
| `dynamic_unpack` | Run + pe-sieve memory scan → dumped modules (unpacked payloads) | spawn, JOB | combat |
| `unpack_chain` | Packed-sample workflow as one call: triage → UPX fast-path → run&dump → LIEF rebuild → re-triage | spawn, JOB | combat |
| `dynamic_recon` | Behavioral recon as one call: frida probe → unpack → FLOSS dumps → correlate | spawn, JOB | tested |
| `debug_session_create` | gdb interactive session (harden option neutralizes PEB anti-debug); cdb for postmortem dumps; x64dbg headless batch | spawn (gdb/x64dbg) / postmortem (cdb), sync | combat |
| `trace_record` | Record a TTD time-travel trace of a run (args, children, ring cap) | spawn (launch), sync | combat |

## Dynamic — attaching to a live instance

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `console_launch` | Launch a console/TUI sample detached with its own (hidden) console — the instance you then drive | spawn+attach-plane, sync | combat |
| `console_send` | Type into the live instance's console (INPUT_RECORDs — the only input TUIs accept); readBack option round-trips | attach, sync | combat |
| `console_read` | Read the live instance's screen buffer (rows, cursor) | attach, sync | combat |
| `process_kill` | Kill a process tree — the cleanup path for detached launches | attach, sync | combat |

## Time travel (TTD)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `trace_replay` | Replay a .run trace headless under WinDbg: jump `!tt`, step back `g-`, breakpoints forward. Output lands in `replay-out.txt` beside the trace — poll it (the client call times out long before the replay finishes) | replay-of-record, sync (file-polled) | combat |

## Debugger session verbs

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `debug_command` | Send any gdb/cdb command to an active session; honest watchpoint verdicts | session, sync | combat |
| `debug_break` | Conditional breakpoint dereferencing a pointer-to-string register (the syntax raw gdb gets wrong) | session, sync | tested |
| `debug_kill` | Un-wedge a hung run without losing the session/breakpoints | session, sync | combat |
| `debug_session_close` | Kill session, archive the transcript as an artifact | session, sync | combat |

## Symbolic & emulation (never executes the sample)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `symbolic_solve` | WHICH INPUTS reach this target address (angr concolic; argv or stdin modeling) — the keygen/reachability question. Verify solutions by running the sample with them | static (docker), sync | tested |
| `symbolic_simplify` | Collapse an MBA expression and PROVE the simpler form equivalent for all inputs (z3 ForAll) | static, sync | tested |
| `emu_run` | Emulate a carved code snippet (Unicorn) with mapped data — decryptors, shellcode triage, hypothesis checks | static (docker), sync | combat |
| `emu_chain` | Stateful multi-step emulation — memory/registers carry across steps; the "init → key schedule → encrypt" crypto-chain shape in one call | static (docker), sync | tested |
| `emu_diff` | Reconstruction oracle — THEIR carved function vs YOUR python reimplementation, first diverging byte named; the "components verify but the composed result fails" closer | static (docker), sync | tested |
| `devirt_survey` | VM-obfuscation detection/localization: dispatcher, handler table, bytecode regions | static, sync | tested |
| `devirt_classify` | Classify a carved VM handler (COMPUTE/LOAD/STORE/junk) by differential emulation | static, sync | tested |

## Unpack & rebuild

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `unpack_static` | UPX decompression in seconds, no execution; also the "is it UPX" probe | static, sync | combat |
| `pe_rebuild` | Reconstruct a loadable PE from a pe-sieve dump (LIEF import transplant + section normalization). Best-effort by design | static, sync | combat |

## Write / act

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `binary_patch` | Write bytes at offsets into a COPY (original untouched) + per-patch diff; run the copy to confirm | static, sync | tested |

## Captured-data analysis (postmortem, ungated)

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `dump_inspect` | Minidump anatomy offline: modules, threads, memory regions, exception record | postmortem, sync | tested |
| `trace_procmon` | Procmon CSV summary: histograms, path buckets, busiest paths; filters | postmortem, sync | tested |
| `memory_volatility` | Volatility 3 read-only plugins on a RAM capture (pslist, netscan, malfind, hives…) | postmortem, JOB | tested |
| `report_correlate` | Fuse procmon + frida log + dump dir + debug transcript + static IOCs into one cross-referenced report | postmortem, sync | combat |

## Case file & infrastructure

| Operation | Answers | Mode | Maturity |
|---|---|---|---|
| `report_findings` | Persist/list findings (title, severity, evidence artifact ids) across sessions | workspace, sync | tested |
| `provider_report` | Which providers are available + dynamic-analysis policy | infrastructure, sync | combat |
| `job_output` / `job_kill` | Poll / cancel background jobs | infrastructure | combat |
