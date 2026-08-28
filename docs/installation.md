# minusOne — Installation and first run

minusOne is a reverse-engineering MCP server that runs on the analyst's own
machine. Containerized backends come as a second layer (see
[docs/docker.md](docker.md)); the ranking models are optional (see
[docs/models.md](models.md)).

## Prerequisites

| Requirement | Needed for | Check |
| --- | --- | --- |
| Node.js 20+ | host runtime | `node --version` |
| Git | cloning | `git --version` |
| Docker Desktop | container backends (Ghidra, capa, FLOSS, angr, Unicorn, LIEF...) | `docker --version` |
| Windows 10/11 x64 | the dynamic plane, console driving, TTD | — |
| gcc (MinGW-w64 / MSYS2) | compiling test fixtures | `gcc --version` |

The static analysis planes run wherever Docker runs; the dynamic plane
(running samples, TUI driving, TTD recording) is Windows-only.

## Install

```sh
git clone <repo-url>
cd minusOne
npm install
npm run build
```

## One-command setup

```sh
npm run setup
```

(`scripts/setup.mjs`, same as `npm run bootstrap` — see
[docs/scripts.md](scripts.md)). The command:

1. builds every pinned docker image (or reuses cached ones);
2. installs WinDbg via `winget` (idempotent) and extracts the TTD stack into
   `tools/ttd/` — this enables `trace.record` / `trace.replay`;
3. prints a readiness report: which backends and tools are present, which
   are missing, and what each missing piece would unlock.

Nothing needs manual configuration: whatever is absent shows up honestly as
`missing` in the report, and the corresponding operations return a
structured refusal — the rest of the pipeline keeps working.

## Health check

```sh
node dist/cli/main.js doctor <path-to-workspace>
```

`doctor` reports: container backends, native tools (gdb, gcc, frida), IDA
(licensed, auto-detected), the D810 plugin, the python model stack, TTD —
and the dynamic-plane policy state.

## Arming the dynamic plane (optional, once per workspace)

By default samples are NEVER executed. The dynamic plane (`sample.execute`,
`dynamic.unpack`, `debug.session.create`, launch-mode `trace.*`) is enabled
by an explicit owner decision:

```sh
node dist/cli/main.js arm <path-to-workspace>      # enable
node dist/cli/main.js disarm <path-to-workspace>   # disable
```

One-off per session, without writing a config:
`MINUSONE_ALLOW_DYNAMIC=1 MINUSONE_DYNAMIC_TARGET=local`.

## External sample directories

To avoid copying large files into the workspace:

```sh
node dist/cli/main.js trust 'C:\Users\you\Downloads\samples'   # read-only
node dist/cli/main.js untrust                                   # list / remove
```

Reads resolve from trusted roots directly; writes NEVER go there — the
workspace stays the only writable root.

## Running the tests

```sh
npm test
```

The full suite includes live tests (real docker backends, gdb sessions,
frida instrumentation, model GPU inference, TTD recording). Missing
dependencies do not fail the run — the affected tests are marked `skip`
with an honest reason.

## Connecting an agent (MCP)

```sh
node dist/mcp/server.js                                # stdio
node dist/mcp/server.js --transport http --port 3080   # HTTP
node dist/cli/main.js mcp --for claude                 # ready-made config snippet
```

Supported `--for` targets: `claude`, `cursor`, `cline`, `continue`,
`vscode`, `dsh`, `opencode`.

Load the usage doctrine into the agent before the first operation call:
[`.agents/skills/minusone/SKILL.md`](../.agents/skills/minusone/SKILL.md).
