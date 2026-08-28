# minusOne — Ranking models (CLAP + BinSeek)

The optional `model.rank.*` plane: small local ML models rank candidates for
the agent. The contract is **ranker, not oracle**: always a top-N candidate
list with scores plus deterministic verification pairs; a model error is
isolated to one request; the whole plane toggles on and off — nothing else
in the pipeline depends on it.

## Application domains (two models, two different worlds)

The models do NOT compete — each owns a domain. The question is never
"which is better" but "which world are we in":

| Domain | Model | Input | When to use |
| --- | --- | --- | --- |
| Normal binaries (~90% of cases: software, DLLs, firmware, legit audits) | **BinSeek** (`model_rank_pseudocode`) | Decompiled pseudocode | **MANDATORY first step after decompilation.** 300 functions → one call → a ranking of "where is the validator/parser/crypto". Cuts the library noise (90% of a binary) before manual reading. |
| Obfuscated binaries (megaprocedures, MBA, control-flow flattening) | **CLAP** (`model_rank_assembly`) | Raw disassembly | When the decompiler dies: failed/timeout on a function. Does not depend on decompilation at all. |

**Trigger rule (built into the operation descriptions):** `function_decompile`
returns failed/timeout for a function → do NOT retry with a bigger budget;
go straight to `model_rank_assembly` on that zone's disassembly
(`disassembly_dump` / `disassembly_list` output). The surrounding
decompilable functions still feed `model_rank_pseudocode` for navigation —
the domains intersect inside one binary.

Why BinSeek cannot serve obfuscated binaries: it needs pseudocode, which is
produced by exactly the decompiler that dies on such targets
(chicken-and-egg). Why CLAP is not needed on normal binaries: the
decompiler works there, and pseudocode navigation beats ranking raw
assembly.

## What you need

- Python 3.10+
- `torch` (CPU works; GPU is noticeably faster at load time)
- `transformers==4.57.1` (5.x breaks the custom CLAP model — `AsmEncoder`
  is incompatible)
- `sentence-transformers` (for BinSeek-Embedding)

One-line install:

```sh
python -m pip install torch "transformers==4.57.1" sentence-transformers
```

For the CUDA build of torch: grab a wheel from
https://download.pytorch.org/whl/ . The models run through the sidecar —
use the same python you installed torch into.

## Where the models come from

Weights live under `models/` (downloaded by the owner). Official sources:

| Model | Repository | Weights |
| --- | --- | --- |
| CLAP (asm encoder) | https://github.com/Hustcw/CLAP | https://huggingface.co/hustcw/clap-asm |
| CLAP (text encoder) | https://github.com/Hustcw/CLAP | https://huggingface.co/hustcw/clap-text |
| BinSeek-Embedding | https://github.com/XingTuLab/BinSeek | https://huggingface.co/XingTuLab/BinSeek-Embedding |
| BinSeek-Reranker | https://github.com/XingTuLab/BinSeek | https://huggingface.co/XingTuLab/BinSeek-Reranker (not used — listed for reference) |

Expected layout:

```text
models/
  clap-asm/           (config.json, model.safetensors, tokenizer*, clap_modeling.py)
  clap-text/
  BinSeek-Embedding/
```

## Enabling

```sh
node dist/cli/main.js models on <workspace>      # persistent, .minusone/config.json
MINUSONE_MODELS=1 ...                             # one-off, env override
node dist/cli/main.js models status <workspace>   # inspect state
```

Explicit enabling is a deliberate decision: not every machine has GPU/VRAM
headroom, and the plane must never spend resources silently.

## How it works

- Sidecar: `tools/models/sidecar.py`, a long-lived python process with a
  JSONL protocol over stdio. Loads lazily on first call; the device is
  auto-detected (`cuda` if available, else CPU). **Unload:** idle
  self-unload after `MINUSONE_MODELS_IDLE_SECONDS` (default 900s) without
  requests; `minusone models off` kills the sidecar via its pid file
  immediately — VRAM does not hang around for hours.
- `model.rank.pseudocode` (BinSeek): cosine similarity of function
  pseudocode to your query ("find the serial validator"). Domain: normal
  binaries — post-decompilation navigation, library-noise cutting.
- `model.rank.assembly` (CLAP): zero-shot classification of assembly
  against your candidate descriptions ("This function implements SHA-256",
  ...). Domain: obfuscated binaries where the decompiler is useless. The
  answer is a softmax score per prompt.

## Verification (the mandatory half of the contract)

Crypto verdicts arrive with deterministic verification pairs:

- CLAP says "SHA-256" → the response carries the needle
  `binary_find kind=bytes needle=982f8a42` (K[0] 0x428a2f98 little-endian);
- "TEA/XTEA" → `b979379e` (delta 0x9E3779B9);
- "ChaCha/Salsa" → `61707861` (sigma "expa").

A verdict without a pair is labeled a hypothesis. The system property: a
model error may REORDER the agent's work but may not LOSE it — the final
word always belongs to the deterministic check.

## Failure behavior

| Situation | Behavior |
| --- | --- |
| Plane disabled | `status: unavailable` + how to enable |
| No python/torch | `status: unavailable`; everything else works |
| Malformed request | `status: error` for that request only; sidecar stays alive |
| Model not found | honest error with the expected path |

## Quick calibration

```js
// model.rank.assembly:
{ assembly: "mov eax, 428a2f98h\nror eax,7\n...", prompts: [
    "This function implements SHA-256 hashing",
    "This is a TEA block cipher",
    "This function performs string comparison" ] }
// → SHA-256 dominates as expected (softmax > 0.9 on a live run)
```

Full live calibrations live in `test/models.test.mjs` (part of `npm test`).
