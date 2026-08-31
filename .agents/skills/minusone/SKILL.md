---
name: minusone
description: Usage doctrine for the minusOne reverse-engineering MCP toolset (mcp__minusone-re__* operations). Use whenever the work involves analyzing a binary — PE/ELF triage, malware or firmware analysis, unpacking, deobfuscation (MBA / control-flow flattening / VM protection), decompilation, dynamic instrumentation with frida or debuggers, TTD time-travel, symbolic execution, binary patching — even when the user just says "take a look at this exe" without naming any tool. It explains which operation answers which question, which behaviors are contracts and NOT bugs (30s client timeouts, rankers, spawn-vs-attach, gating), and the probe-spiral anti-patterns that waste hours.
---

# minusOne doctrine

minusOne is one MCP server exposing ~70 semantic operations across the whole
reverse-engineering workflow: static triage, strings, disassembly, decompilation,
ranking models, dynamic instrumentation, symbolic execution, and write/act
operations. Every operation exists because it is the shortest path to some
concrete answer. The skill of using minusOne is picking the operation that matches
the question you currently have — not the one that feels "strongest", and not the
cheapest-looking probe. Do not ration calls: one relevant operation is always
cheaper than three speculative probes around the same question, and a "heavy"
operation (TTD, symbolic execution, deep FLOSS) used at the right moment saves
hours compared to tiptoeing toward the same answer.

## Three contracts — accept once, never re-litigate

1. **Rankers, not oracles.** `model_rank_pseudocode` (BinSeek) and
   `model_rank_assembly` (CLAP) return ranked candidates with scores. Their job is
   to cut 90% of the noise so you verify a handful of functions instead of reading
   hundreds. A wrong top-1 is not a malfunction — verify the top candidates with
   decompilation and xrefs, as with any retrieval system.
2. **Long operations are jobs or file-polled.** The ~30s MCP client cap is a
   transport limit, not a verdict on the work. Job-based operations return a job
   id — poll `job_output(wait:true)`. File-polled operations (trace_replay) state
   their output path in their description — poll that file. **An empty or
   timed-out client response carries zero information about success or failure.**
   Concluding "it's broken" from a 30s timeout is the single most expensive
   mistake made with this toolset in the field.
3. **Write operations never touch the original.** `binary_patch` and `pe_rebuild`
   write copies; `artifact_export` materializes store content; `annotate_symbol`
   writes a sidecar map. If you need the patched copy executed, run the copy.

## "This is NOT a bug" — the list that prevents false dead-ends

| Observation | Reality | Correct move |
|---|---|---|
| Client call timed out (~30s) on a long operation | Work continues server-side | Poll `job_output` (jobs) or the stated output file (e.g. trace_replay's `replay-out.txt` beside the trace) |
| Ranker's top candidate is wrong | Retrieval cuts noise, it does not issue verdicts | Verify top-3..5 with decompile + xref |
| `function_decompile` fails/times out on a huge function | Expected on control-flow-flattened megaprocedures | `function_decompile_range` on the zone, then `model_rank_assembly` on the raw listing. Never retry the decompiler with bigger budgets |
| `xref_query` shows 0 references to a string/data | References built as immediates or on the stack are not collected | `binary_find` the pointer/value bytes, or `binary_explain` the needle |
| Dynamic operation refuses: "not armed" | Owner-gated by design | `minusOne arm` once per machine; then dynamic ops just work |
| Static providers run in docker with `--network none`, read-only mounts | Doctrine — they never execute the sample | Nothing to fix |
| `pe_rebuild` output is partial | IAT reconstruction after unpacking is best-effort by definition | Use the report of what was repaired; manual IAT work for the rest |
| DIE says "MSVC C++" but the binary is Rust | Compiler-ID heuristics misfire | Trust crate-path strings and capa over the compiler label |
| Frida `MemoryAccessMonitor` freezes a target that has its own exception handler (VEH) | Guard-page exceptions collide with the sample's VEH | Use `Interceptor` hooks or TTD instead |
| A static dump's `.text` lacks lazily self-patched bytes (nanomite-style protections) | Patching happens transiently in a scratch area at runtime, never in `.text` | Capture live: hook the patch dispatcher with frida, or record with TTD. Diffing dump `.text` vs file is the wrong instrument |
| `sample_execute` stdin never reaches a full-screen TUI | TUIs read console INPUT_RECORDs, not stdin bytes | `console_launch` + `console_send` |
| `ida_decompile` / Ghidra both time out on one function | The function is a flattened megaprocedure | Slicer + CLAP (see above); `function_deobfuscate` (d810) if MBA/opaque predicates dominate |

## The workflow backbone

Not a ritual — the order in which questions naturally arise. Skip steps that your
sample already answers.

1. **What is this file?** `binary_triage` (format, entropy, imports by risk,
   packer verdict, IOCs, capa when cached). If a large legitimate-looking binary
   scores "packed" on entropy, run `signature_verify` before believing it — a
   valid Authenticode kills the packed hypothesis instantly.
2. **Is it packed?** UPX → `unpack_static` (seconds, no execution). Anything else
   → `dynamic_unpack` or the full `unpack_chain`. Then `dumps_floss` the dump
   directory and re-triage the payload.
3. **What's inside?** `strings_find` plain modes first; `deep-floss` mode when
   strings are decoded at runtime. When the question is C2/mutex/campaign/key
   shaped, `config_extract` harvests it with evidence trails.
4. **Where is the logic I care about?** Decompile a batch of candidate functions,
   then `model_rank_pseudocode` with a plain-language query ("which function
   validates the license") — this is the mandatory first navigation step on
   decompilable binaries; reading functions one by one is the expensive
   alternative. For a concrete needle (a string, constant, API), `binary_explain`
   chains search → xrefs → decompilation of the referring functions in one call.
5. **This function defeats the decompiler.** `function_decompile_range` slices the
   VA range with short budgets; for whatever still will not decompile,
   `model_rank_assembly` classifies the raw disassembly (crypto? VM dispatcher?
   comparison loop?). This is the CLAP trigger rule — reach for it the moment a
   decompile comes back failed, not after retries.
6. **What does this address hold, and who points here?** `memory_read` resolves
   VA/RVA/offset with no manual arithmetic and `chasePointers` walks pointer
   tables; `xref_query` lists code/data references from the cached r2 session.
7. **I need to see it run.** Choose by target shape, not by habit:
   - CLI batch behavior → `sample_execute` (args/stdin).
   - Interactive console / full-screen TUI → `console_launch`, then
     `console_send`/`console_read` — the only plane that feeds INPUT_RECORDs.
   - "Which function performs behavior B (writes this file, connects this host)?"
     → `trace_source` maps the API call back to the static site with pseudocode.
   - Custom instrumentation (hook this address, log these buffers, stall ExitProcess)
     → `frida_script` with your own agent JS.
   - "How did this value come to exist?" → `trace_record` + `trace_replay`:
     time-travel backward from the consumption point to the birth of the value.
   - "What differs between run A and run B?" → `trace_diff` (first divergence,
     reconvergences).
8. **Which inputs reach this address?** `symbolic_solve` explores concolically and
   returns concrete solutions — the keygen/CRCE question. MBA expression walls in
   pseudocode → `symbolic_simplify` proves the collapsed form for all inputs, not
   by eyeballing. Whole-function MBA / opaque predicates / flattening →
   `function_deobfuscate` (d810).
9. **I need to change it.** `binary_patch` writes a copy (run the copy to confirm
   behavior). After memory dumps, `pe_rebuild` reconstructs a loadable PE.
   `artifact_export` turns any stored artifact (decoded strings, carved files,
   decompiled code) into a real workspace file.
10. **I learned something.** `annotate_symbol` persists VA→name so every later
    operation (find hits, explain sites, decompile targets) shows your names —
    the compounding loop. `report_findings` keeps the case file across sessions.

## Campaign mode (v2): the stateful layer for MULTI-FILE and LONG engagements

WHEN to enter campaign mode — the threshold is the FILE COUNT and the
number of tool calls, not how "serious" the task feels:

- **One sample, a handful of questions → call the operations DIRECTLY.**
  A plan for a single file is overhead: you serialize what the operations
  already do in one call. `plan_run` for one binary is an anti-pattern.
- **A corpus (2+ files — e.g. 40 binaries, some DLL some EXE) or a
  long multi-stage engagement → campaign mode.** The whole point: you
  describe the SAME operations once (triage on every file, strings on
  every file, unpack where triage says packed...) and the executor runs
  them across the batch — parallel where the files are independent, later
  stages only where earlier results warrant (decompile the DLLs, skip the
  EXEs — expressed with `dependsOn`), instead of you hand-calling each
  operation per file and drowning your context in tool results.

The state lives in `.minusone/campaign/` (plan.json, notes.md, dossier/,
index/) and survives restarts and context compaction; you read it back
instead of re-deriving.

1. **Start of every session (and after ANY compaction):** `notes_read` and
   `campaign_status` FIRST. The notes carry hypotheses with statuses and
   WHY they died, the address table, dead ends, open questions; the status
   answers "which tasks are done". Re-deriving any of that is wasted work.
2. **Write the plan.** `plan_run` with a plan object: `goal` (the contract
   the campaign answers to), `tasks` with `dependsOn` (parallel where
   independent — across FILES the tasks are independent by nature), `fallback`
   (alternate ops on error, or `true` for the built-in map), `onFailure`
   (`skip` default / `stop` / `ask`). It runs as a job; dependency-ready
   tasks run in parallel, the dynamic plane stays exclusive. Every settled
   task lands in the dossier immediately — assembled (structured,
   per-family) + raw (CAS pointer).
3. **Write notes CONTINUOUSLY, not at the end.** Every verified finding →
   `notes_update` log. A hypothesis dies → kill it WITH the reason. A path
   fails → dead_end, so no one (including future-you) re-walks it. Context
   compaction is unpredictable; unrecorded findings die with it.
4. **Resume = edit + re-run.** A task fails? Fix the plan (drop the task,
   or swap its operation) and call `plan_run` again — completed tasks skip
   from the dossier. Progress is never lost unless you delete it. A failed
   task's dependents come back as `blocked`, never fed with missing input.
   `ask` halts with `needs-decision` and hands the choice to you.
5. **Ask the field you already plowed.** With the models plane on,
   `knowledge_index` embeds the dossier (incremental), then
   `knowledge_query` answers "where is the X" with ranked chunks and source
   pointers — a retrieval list to open, not a verdict.

## Anti-patterns — each of these cost real hours in the field

- **A single-file plan.** `plan_run` for one binary serializes and wraps
  what the operations already do in one direct call — plan overhead
  without batch benefit. Campaign mode is for corpora (2+ files) and
  long multi-stage engagements; enter it when the FILE COUNT or the
  number of tool calls makes hand-driving the batch worse than writing
  the plan once.

- **Probe spirals.** Writing N one-off instrumentation rounds that each answer a
  narrow question, while the decisive question stays unasked. If three probes in
  a row answer small questions without changing your main hypothesis, stop and
  pick the instrument that answers the decisive question directly (usually TTD or
  symbolic execution). And before instrumenting any code path, confirm statically
  that your input actually reaches it — an hour of "silent hooks" usually means
  the path never executed, not that the hooks failed.
- **Concluding "broken" from an empty 30s response.** See contract 2. Poll the
  job or the file. In the field this mistake cost an agent its only decisive
  tool.
- **Spawning fresh instances of a target you must drive.** If the sample is a
  TUI/GUI or keeps state you built up, launching new copies loses the state and
  can fork into cascades. Launch once, then attach: `console_send` by PID, frida
  attach by PID, TTD attach by PID. Kill what you launched (`process_kill`).
- **Retrying the decompiler with bigger budgets.** A flattened megaprocedure does
  not care about your budget. Slicer + CLAP.
- **Running dynamics before reading the gate.** Before ANY dynamic run on a
  validator/unpacker/protected binary, statically decompile the input-submit
  handler and enumerate every cheap check (length, charset, format) FIRST. A
  wrong-shaped input dies at an early gate — every "silent hook" downstream
  (VM never entered, crypto untouched, VEH never fired) then means "the path
  never executed", and hours get spent instrumenting dead code. In the field
  this single unread gate cost a full 2-hour session; reading it takes
  minutes.
- **Re-verifying algorithms when the data is wrong.** When every component
  verifies in isolation (the decryptor emulates cleanly, the keystream
  matches) but the composed result fails, the fault is almost always ONE
  data address or offset mis-derived — not the algorithm. Re-derive every
  address/offset from the binary from scratch (memory_read resolves
  VA/RVA/offset with no manual arithmetic — use it instead of hex math by
  hand); do NOT re-verify already-proven algorithms. In the field an agent
  verified a correct crypto chain three times while one hex-arithmetic slip
  in a blob offset was the entire failure.
- **Brute-forcing inputs** when `symbolic_solve` can prove reachability and hand
  you a concrete solution.
- **Believing a "packed" entropy verdict on a signed binary** without
  `signature_verify`.
- **Unbounded reads.** Heavy outputs belong to the `max_output` budget; the spill
  file under `.minusone/outputs/` is there to be paged with `artifact_read`-style
  follow-ups, not dumped into context.

## Session hygiene

Kill what you launch: `process_kill` for detached processes,
`debug_session_close` for debugger sessions, `job_kill` for runaway jobs. One
live instance with many instruments attached beats a graveyard of half-driven
copies. When a debugger run wedges, `debug_kill` resets the inferior without
losing your breakpoints.

## References

- `references/operations.md` — every operation on one card: the question it
  answers, sync vs job, spawn vs attach, and an honest maturity label
  (proven in combat / tested / situational).
- `references/dynamics.md` — the dynamic plane in depth: the spawn-vs-attach
  table, the TUI driving recipe, the TTD record→replay recipe, frida agent
  recipes and traps (frida 17 API changes, MemoryAccessMonitor vs VEH, Stalker).
