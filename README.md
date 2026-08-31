# minusOne

minusOne is an MCP server for reverse engineering. It exposes 77 semantic
operations covering static triage, unpacking, decompilation, dynamic
instrumentation, emulation, symbolic execution, time-travel debugging, and
evidence handling — each call does the multi-step work an analyst would
otherwise glue together by hand. It plugs into any MCP-compatible agent host
(Claude Code, Cursor, Cline, Continue, VS Code, opencode, dsh) over stdio or
HTTP.

Analysis runs on your machine. Static backends execute in Docker containers
with no network access; the dynamic plane (running samples, debuggers, frida)
is armed explicitly by the owner. Optional local ML models (CLAP + BinSeek)
rank candidates for the agent — everything works without them.

## What it can do

**Campaign orchestration (v2)**
- Plan-driven engagements: write a plan (goal + tasks with dependencies,
  fallbacks, failure modes) and `plan_run` orchestrates it — parallel
  static tasks, exclusive dynamic plane, every settled task checkpointed
  to the dossier immediately.
- Resume without progress loss: edit `plan.json`, re-run `plan_run` —
  completed tasks skip from the dossier.
- Investigation notes as a first-class file: hypotheses with statuses and
  reasons, address table, dead ends, open questions, append-only log —
  read at session start, written continuously.
- Campaign knowledge index (opt-in, models plane): the dossier embedded
  per-function/per-section/per-field; plain-language queries return ranked
  chunks with source pointers.

**Static analysis**
- One-call triage: format, sections/entropy, imports classified by API risk,
  IOC mining, packer verdict, embedded-object scan, capa capabilities —
  with honest "analysis incomplete" verdicts instead of confident guesses.
- Whole-file search (text / UTF-16 / hex / regex) with no size ceiling; hits
  carry file offset, section, RVA/VA, and the containing function.
- "Who uses this and what does the code do" in one call: needle →
  cross-references → decompiled callers.
- PE structural surveys (up to 8 files per call), resource/version parsing,
  Authenticode signature verification, YARA-X scanning.
- Heuristic malware-config extraction (C2, mutexes, campaign IDs, keys) with
  evidence trails; FLOSS deep string deobfuscation.
- Patch diffing between two builds with decompiled changed regions.

**Decompilation and deobfuscation**
- Ghidra headless, including a range slicer that walks control-flow-flattened
  megaprocedures no whole-function decompile survives.
- IDA Pro headless (`idat` + Hex-Rays); a licensed local install is detected
  automatically and is never bundled.
- D810-ng microcode rewriting (MBA collapse, OLLVM unflattening) with
  baseline-vs-deobfuscated output side by side.

**Unpacking and PE rebuild**
- UPX static decompression — seconds, no execution.
- Run-and-dump via pe-sieve → LIEF-based PE reconstruction (import transplant,
  section normalization) → re-triage of the unpacked payload.
- binwalk carving of embedded objects (carve-only — no extractor ever runs).

**Emulation and symbolic execution**
- Unicorn emulation of carved code snippets (shellcode, decryptors): mapped
  memory, initial registers, post-run memory read-back — nothing executes on
  the host.
- Stateful multi-step emulation: memory and registers carry across steps
  ("init → key schedule → encrypt" chains in one call).
- Reconstruction oracle: their carved function vs your reimplementation, with
  the first diverging byte named.
- angr symbolic solving ("which inputs reach this address") and z3 MBA
  equivalence proofs, in Docker.

**Dynamic analysis (owner-armed)**
- Sample execution with argv/stdin; frida probes of file/registry/network
  calls; custom frida agents with spawn-gating for self-debugging schemes.
- Execution diff of two runs: the first diverging basic block localizes the
  validator branch without breakpoints.
- Runtime→static bridge: an observed API call is mapped back to the function
  that made it, with decompiled pseudocode.
- TTD time-travel record + headless backward replay (WinDbg) — walk from the
  verdict back to the value's origin.
- Interactive TUI driving (console launch/send/read) and scriptable
  gdb / cdb / x64dbg sessions, with anti-anti-debug hardening.
- Offline analysis of minidumps, Procmon traces, and full memory captures
  (Volatility 3).

**Model ranking (optional, off by default)**
- CLAP: zero-shot crypto/algorithm identification on raw assembly — works
  where the decompiler gives up.
- BinSeek: retrieval over pseudocode ("find the license validator") — cuts
  the library noise before any deep reading.
- Ranked candidate lists with scores, never verdicts. Disabled or missing
  dependencies return `status: unavailable`; the pipeline does not depend
  on them.

**Evidence and workflow**
- Content-addressed artifact store; identical analyses are cached by sample
  digest, options, and backend identity.
- Cross-plane correlation: Procmon traces, frida logs, memory dumps, debug
  transcripts, and static anchors fused into confirmed findings.
- Durable findings file and VA→name annotation that later operations
  resolve — understanding compounds across a session.
- Background jobs for long operations, bounded output with spill files,
  abort/cancel support.

## Requirements

| Requirement | Needed for |
| --- | --- |
| Node.js 20+ | host runtime |
| Docker Desktop | container backends (Ghidra, capa, FLOSS, angr, Unicorn, LIEF, ...) |
| Windows 10/11 x64 | dynamic plane, console driving, TTD (static analysis runs wherever Docker runs) |
| gcc (MinGW-w64) | compiling test fixtures (development) |
| Python 3.12+ with torch | model ranking (optional) |
| IDA Pro 9.x | IDA operations (licensed, owner-installed, optional) |

## Quick start

```sh
git clone <repo-url>
cd minusOne
npm install
npm run build
npm run setup
```

`npm run setup` builds (or reuses) every pinned Docker image, installs the
TTD stack, probes the native toolchain, and prints what each missing piece
would unlock. Use `--skip-build` to only print the report.

To verify the install:

```sh
npm test
```

319 tests — unit, integration, and live; live tests skip gracefully when a
backend (image, debugger, GPU, model) is not present.

## Connecting an agent host

```sh
node dist/cli/main.js mcp --for claude    # prints a copy-pasteable config snippet
node dist/cli/main.js mcp --for vscode --http
node dist/mcp/server.js                   # stdio transport
node dist/mcp/server.js --transport http --port 3080   # HTTP transport
```

Supported `--for` targets: `claude`, `cursor`, `cline`, `continue`,
`vscode`, `dsh`, `opencode`.

Give the agent the usage doctrine: [`.agents/skills/minusone/SKILL.md`](.agents/skills/minusone/SKILL.md).
It explains which operation answers which question, the behaviors that are
contracts and not bugs (30s client timeouts on long jobs, rankers-not-oracles,
spawn-vs-attach), and the anti-patterns that waste hours. The MCP server also
sends a distilled version in its initialize instructions.

## Operational posture

- **Static by default.** Static providers run containerized with
  `--network none`, read-only sample mounts, CPU/memory caps. The sample is
  never executed by a static operation.
- **The dynamic plane is armed explicitly.** `node dist/cli/main.js arm
  <workspace>` once per workspace (or `MINUSONE_ALLOW_DYNAMIC=1
  MINUSONE_DYNAMIC_TARGET=local` per session) — this host becomes the
  execution target for `sample.execute`, debuggers, frida, and TTD. Unarmed
  calls return a structured refusal, not a fake result.
- **Write operations never touch the original.** Patching, carving, and
  exports write copies under the workspace; the artifact store is
  content-addressed.
- **External read-only roots.** `node dist/cli/main.js trust <dir>`
  authorizes reading samples outside the workspace without copying them;
  writes never leave the workspace.

## Backend selection

Every containerized provider pins a default image
(`src/core/backends.ts`); `MINUSONE_<PROVIDER>_IMAGE` overrides it and
`MINUSONE_<PROVIDER>_BIN` points at a local binary instead. An explicitly
empty image disables that provider. See [docs/docker.md](docs/docker.md).

## Documentation

- [docs/installation.md](docs/installation.md) — install and first run
- [docs/docker.md](docs/docker.md) — container backends and isolation
- [docs/models.md](docs/models.md) — CLAP/BinSeek ranking models
- [docs/scripts.md](docs/scripts.md) — scripts and tools reference

## Repository layout

- `src/core/` — operation table, providers, evidence pipeline
- `src/mcp/server.ts` — MCP facade (stdio + HTTP)
- `src/cli/` — the `minusOne` CLI (arm/disarm, doctor, config emitters)
- `docker/` — pinned backend Dockerfiles
- `tools/` — pinned host tools and scripts (pe-sieve, UPX, IDA exporter,
  model sidecar)
- `test/` — unit, integration, and live tests
- `.agents/skills/minusone/` — the usage doctrine

## License

MIT
