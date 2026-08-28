# minusOne — Reference: scripts and tool files

What lives in `scripts/` and `tools/`, what each file does, and when to run
it.

## scripts/ — setup automation

Setup automation only. No "useful utilities" — everything the agent needs
in daily work lives in the operations (see the README and the operation
table).

### scripts/setup.mjs — one-command setup

```sh
npm run setup          # = node scripts/setup.mjs
```

Full automatic setup of a new environment:

1. **Docker images**: builds every pinned backend (see
   [docs/docker.md](docker.md)); existing ones are skipped.
2. **TTD stack**: installs WinDbg via `winget` (idempotent) and extracts
   the TTD binaries from the MSIX package into `tools/ttd/` (MSIX paths
   under WindowsApps are not directly executable — hence the extraction).
   Enables `trace.record` / `trace.replay`.
3. **Readiness report**: which backends/tools are alive, which are missing,
   and which operations they would unlock.

Flags: `--images-only` (build images only), `--report-only` (report only),
`--skip-build` (report against existing images).

### scripts/bootstrap.mjs — the setup engine

`setup.mjs` is a thin wrapper; all the logic lives here (images + TTD +
report). Direct invocation: `node scripts/bootstrap.mjs`.

### scripts/fetch-volatility-data.mjs — dataset for memory.volatility

```sh
npm run datasets:fetch
```

Downloads the public Volatility Foundation memory capture (XP corpus),
verifies sha256, and unpacks it into `tools/volatility-dataset/`. Only
needed for the `memory.volatility` tests/demo — on real work you point the
operation at your own image.

## tools/ — host tools

| Path | What it is | Used by |
| --- | --- | --- |
| `tools/pe-sieve64.exe` | pe-sieve (memory scanner, dumps unpacked modules) | `dynamic.unpack`, `unpack.chain` |
| `tools/upx.exe` | UPX | `unpack.static` |
| `tools/ttd/` | TTD stack: TTD.exe (recorder), TTDInject/TTDLoader/TTDRecord*.dll, cdb.exe + dbgeng (extracted from the WinDbg MSIX by setup) | `trace.record` (recorder); replay goes through the WinDbgX alias |
| `tools/ida/export.py` | headless exporter for idat (functions/imports/Hex-Rays pseudocode/xrefs) | `ida.functions`, `ida.decompile`, `binary.explain`, `trace.source` |
| `tools/ida/d810_smoke.py` | headless D810-ng activation recipe under idat (registry rule scan → D810State → ollvm profile) | `function.deobfuscate` |
| `tools/models/sidecar.py` | CLAP+BinSeek python sidecar (JSONL over stdio) | `model.rank.*` |
| `tools/volatility-symbols/` | offline kernel symbol cache | `memory.volatility` |
| `tools/volatility-dataset/` | test memory capture (after datasets:fetch) | `memory.volatility` tests |

`tools/ttd/` is created by `npm run setup` and is intentionally not part of
the repository (Microsoft binaries, extracted locally).

## docker/ — pinned images

One `*.Dockerfile` per backend plus python entrypoint scripts:
`emu-run.py` (Unicorn — single/chain/diff modes), `symbolic-run.py`
(angr/claripy — `solve`/`simplify` modes), `pe-rebuild.py` (LIEF). Contents
and isolation model: [docs/docker.md](docker.md).

## ghidra_scripts/

`ExportAnalysis.java` — bounded headless Ghidra export: plain mode
(address-scoped), `--references` (functions referencing an address), and
`--range` (the megaprocedure slicer: functions intersecting a VA range with
a short per-function decompile budget and an annotated disassembly
fallback).

## src/core/ — operation providers (file map)

| File | Plane |
| --- | --- |
| `operations.ts` | the full operation table (contracts, schemas, gating) |
| `triage.ts` / `find.ts` / `search.ts` / `explain.ts` / `survey.ts` | static-analysis intent operations |
| `ghidra.ts` / `radare.ts` / `ida.ts` / `d810.ts` | decompilers and the deobfuscator |
| `symbolic.ts` | angr/claripy (solve/simplify) |
| `emu.ts` | Unicorn emulation (single / chain / diff) |
| `frida.ts` | dynamic.frida, trace.source, frida.script, trace.diff |
| `ttd.ts` | trace.record / trace.replay |
| `console.ts` / `dynamic.ts` | Win32 console (TUI loop) / dynamic plane |
| `debugger.ts` / `cdb.ts` / `x64dbg.ts` | debugger backends |
| `models.ts` | python sidecar + verification constant pairs |
| `artifacts.ts` / `correlate.ts` | CAS store / evidence fusion |
| `workspace.ts` / `config.ts` | workspace containment / `.minusone/config.json` |
