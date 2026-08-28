# minusOne — Docker: container backends

minusOne keeps the heavy static analyzers in pinned Docker images. All of
them build from `docker/*.Dockerfile` in this repository — no third-party
registries beyond the base images are needed, and the analyzer version is
pinned together with the code.

## Images

| Image | Version | Powers operations |
| --- | --- | --- |
| `minusone/ghidra:12.1.2` | Ghidra 12.1.2 (JDK 21) | `function.decompile`, `function.decompile.range`, `binary.diff`, `binary.explain` (fallback) |
| `minusone/symbolic:angr9.3.3` | angr 9.3.3 + z3/claripy | `symbolic.solve`, `symbolic.simplify` |
| `minusone/unicorn:2.1.3` | Unicorn 2.1.3 | `emu.run`, `emu.chain`, `emu.diff`, `devirt.classify` |
| `minusone/capa:9.4.0` | capa 9.4.0 + capa-rules | `capabilities.detect` |
| `minusone/yara-x:1.19.0` | YARA-X 1.19.0 | `rules.scan` |
| `minusone/floss:3.1.1` | FLOSS 3.1.1 | `strings.extract.deep`, `dumps.floss`, `config.extract`, `unpack.chain` |
| `minusone/die:3.21` | Detect It Easy 3.21 | `packer.detect`, `binary.triage` |
| `minusone/binwalk:2.3.3` | binwalk 2.3.3 | `embedded.scan`, `embedded.extract` |
| `minusone/volatility3:2.28.0` | Volatility 3 | `memory.volatility` |
| `minusone/pe-tools:lief` | python + LIEF | `pe.rebuild`, `unpack.chain` (IAT restoration) |
| `radare/radare2:5.9.8` | official image | `disassembly.functions` (fallback, docker mode) |

## Why per-provider images, not one big image

Each analyzer pins its own toolchain (Ghidra needs JDK 21, angr wants its
own python dependency set, Volatility its own). One monolithic image would
be several gigabytes, and any fix to one runner script would invalidate the
whole build cache — per-provider images rebuild in seconds. The one-command
experience is still there: `npm run setup` builds all of them.

## Build

```sh
npm run setup        # builds everything + TTD + readiness report
# or individually:
docker build -f docker/symbolic.Dockerfile -t minusone/symbolic:angr9.3.3 .
```

The first build pulls base images (python:3.12-slim, temurin-21, ...) from
Docker Hub — a working `docker pull` is required. Rebuilds reuse the layer
cache; an image whose tag already exists locally is skipped.

## Isolation model

Static container backends run like this:

```text
docker run --rm --network none \
  --cpus <N> --memory <M> \
  -v <workspace>:/workspace:ro \        # sample and artifacts — read-only
  -v <run-dir>:/out \                   # results — into an isolated run dir
  <image> ...
```

- `--network none` — the analysis has no network. Ever.
- The sample mounts read-only: a container cannot corrupt it.
- NO sample code ever executes in the static backends — they are
  parsers/emulators of data. The only "execution" is Unicorn (`emu.run` and
  family): an isolated CPU with no host process, no syscalls.

The dynamic plane (`sample.execute`, `dynamic.unpack`, `dynamic.frida`,
`trace.*`, debuggers) runs ON the host, not in docker, and only when armed
(`minusOne arm`) — see [docs/installation.md](installation.md).

## Overrides and disabling

Every image can be replaced or disabled via an environment variable:

```sh
MINUSONE_GHIDRA_IMAGE=my-registry/ghidra:12.1.2   # replace the image
MINUSONE_GHIDRA_IMAGE=                             # EMPTY string = disable the backend
```

Full list: `MINUSONE_<GHIDRA|CAPA|YARA|FLOSS|DIE|R2|BINWALK|VOLATILITY|
PE_TOOLS|EMU|SYMBOLIC>_IMAGE`. A local binary instead of an image:
`MINUSONE_<...>_BIN` (checked first).

## When docker is unavailable

Part of the operation set survives: the native planes (`binary.find`,
`binary.search`, `memory.read`, `batch.survey`, the gdb/cdb/x64dbg
debuggers, the console TUI loop, TTD) need no docker at all. Containerized
operations return a structured error with the reason — the run does not
fail.
