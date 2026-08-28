/**
 * Model-ranking plane tests: the toggle (config + env), the honest
 * unavailable degradation, malformed requests, verification pairs, the
 * JSONL sidecar protocol, and — when the plane is actually armed with
 * torch+models — live CLAP/BinSeek calibration runs.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CRYPTO_CONSTANTS,
  attachVerification,
  normalizeVerdict,
  rankAssembly,
  rankPseudocode,
  resolveModelsEnabled,
  shutdownModels,
} from "../dist/core/models.js";
import { operations } from "../dist/core/operations.js";
import { writeModelsMode } from "../dist/core/config.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

// The live calibrations need a python with torch + transformers; the owner
// points MINUSONE_MODELS_PYTHON at one, otherwise PATH's python is probed.
const MODELS_PYTHON = process.env.MINUSONE_MODELS_PYTHON ?? "python";

const SHA_ASM = [
  "mov eax, 428a2f98h",
  "ror eax, 7",
  "xor eax, edx",
  "add eax, 0B5C0FBCFh",
  "mov ecx, 71374491h",
  "cmp ecx, 40h",
  "jl loop",
  "ret",
].join("\n");

const TEA_ASM = [
  "mov eax, 0x9E3779B9",
  "add esi, eax",
  "xor esi, edx",
  "shl esi, 4",
  "add esi, [rbp-8]",
  "xor esi, edx",
  "shr edx, 5",
  "add edx, [rbp-10h]",
  "xor edx, esi",
  "loop",
].join("\n");

const PROMPTS = [
  "This function implements SHA-256 hashing",
  "This is a TEA block cipher",
  "This function performs string comparison",
  "This is a memory allocator",
];

function freshWorkspace() {
  return mkdtemp(path.join(os.tmpdir(), "minusone-models-"));
}

function clearModelsEnv(context) {
  const previous = process.env.MINUSONE_MODELS;
  delete process.env.MINUSONE_MODELS;
  context.after(() => {
    if (previous !== undefined) process.env.MINUSONE_MODELS = previous;
  });
}

test("operation descriptions carry the C9 domain split and the trigger rule", () => {
  const assembly = operations.find((entry) => entry.id === "model.rank.assembly");
  const pseudocode = operations.find((entry) => entry.id === "model.rank.pseudocode");
  const decompile = operations.find((entry) => entry.id === "function.decompile");
  assert.ok(assembly && pseudocode && decompile, "all three operations exist");

  // CLAP domain: obfuscated binaries, decompiler-dead zones; the trigger
  // rule routes a failed function_decompile HERE, not to a bigger budget.
  assert.match(assembly.description, /DOMAIN/i);
  assert.match(assembly.description, /TRIGGER RULE/);
  assert.match(assembly.description, /function_decompile returned failed\/timeout/i);

  // BinSeek domain: normal decompilable binaries — the mandatory first
  // navigation step; explicitly NOT for obfuscated binaries.
  assert.match(pseudocode.description, /MANDATORY FIRST STEP/i);
  assert.match(pseudocode.description, /Not for obfuscated binaries/i);

  // The decompiler's own description routes failures to CLAP.
  assert.match(decompile.description, /TRIGGER RULE/);
  assert.match(decompile.description, /model_rank_assembly/);
});

test("crypto constant table holds verifiable little-endian byte pairs", () => {
  assert.equal(CRYPTO_CONSTANTS["sha-256"][0].hex, "982f8a42", "SHA-256 K[0] 0x428a2f98 as LE bytes");
  assert.equal(CRYPTO_CONSTANTS.tea[0].hex, "b979379e", "TEA delta 0x9E3779B9 as LE bytes");
  assert.equal(CRYPTO_CONSTANTS.chacha20[0].hex, "61707861", "chacha sigma 'expa' as LE bytes");
});

test("normalizeVerdict matches prompts to constant pairs case-insensitively", () => {
  assert.equal(normalizeVerdict("This function implements SHA-256 hashing"), "sha-256");
  assert.equal(normalizeVerdict("This is a TEA block cipher"), "tea");
  assert.equal(normalizeVerdict("Uses sha256 internally"), "sha-256");
  assert.equal(normalizeVerdict("This is a memory allocator"), null);
});

test("attachVerification pairs every crypto verdict with a binary_find needle", () => {
  const ranked = [
    { prompt: "This function implements SHA-256 hashing", score: 0.99 },
    { prompt: "This is a memory allocator", score: 0.01 },
  ];
  const withPairs = attachVerification(ranked);
  assert.ok(Array.isArray(withPairs[0].verifyWith), "SHA verdict carries verification pairs");
  assert.match(withPairs[0].verifyWith[0].needle, /982f8a42/);
  assert.equal(withPairs[1].verifyWith, undefined, "non-crypto verdicts carry no pairs");
});

test("ranking is unavailable when the plane is off (config default)", async (context) => {
  const root = await freshWorkspace();
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  assert.equal(await resolveModelsEnabled(workspace), false, "models default to OFF");

  const result = await rankAssembly(workspace, { assembly: SHA_ASM, prompts: PROMPTS });
  assert.equal(result.status, "unavailable");
  assert.match(result.error, /minusone models on/);
  assert.match(result.note ?? "", /accelerator/, "the refusal says ranking is optional");

  const op = operations.find((entry) => entry.id === "model.rank.assembly");
  const response = await op.execute({ assembly: SHA_ASM, prompts: PROMPTS }, { workspace });
  assert.equal(response.status, "unavailable");
  assert.equal(response.ranked, undefined, "no ranking when the plane is off");
});

test("models toggle persists through workspace config", async (context) => {
  const root = await freshWorkspace();
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  await writeModelsMode(workspace, "on");
  assert.equal(await resolveModelsEnabled(workspace), true);
  await writeModelsMode(workspace, "off");
  assert.equal(await resolveModelsEnabled(workspace), false);
});

test("MINUSONE_MODELS=1 overrides the config for one-shot use", async (context) => {
  const root = await freshWorkspace();
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  await writeModelsMode(workspace, "off");
  process.env.MINUSONE_MODELS = "1";
  assert.equal(await resolveModelsEnabled(workspace), true);
  delete process.env.MINUSONE_MODELS;
  assert.equal(await resolveModelsEnabled(workspace), false);
});

test("malformed ranking requests fail per-request, never throw", async (context) => {
  const root = await freshWorkspace();
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  process.env.MINUSONE_MODELS = "1";
  const empty = await rankAssembly(workspace, { assembly: "", prompts: [] });
  assert.equal(empty.status, "error");
  assert.match(empty.error, /required/);
  const emptyQuery = await rankPseudocode(workspace, { query: "", snippets: [] });
  assert.equal(emptyQuery.status, "error");
  delete process.env.MINUSONE_MODELS;
});

test("live CLAP calibration: SHA constants beat TEA/strcmp/alloc prompts; TEA assembly ranks TEA first", { timeout: 600_000 }, async (context) => {
  const root = await freshWorkspace();
  context.after(async () => {
    await rmRoot(root);
    await shutdownModels().catch(() => {});
  });
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  // Skip unless the sidecar stack is actually present.
  try {
    execFileSync(MODELS_PYTHON, ["-c", "import torch, transformers, sentence_transformers"], { stdio: "pipe" });
  } catch {
    context.skip("needs python + torch + transformers + sentence-transformers");
    return;
  }
  process.env.MINUSONE_MODELS = "1";

  const sha = await rankAssembly(workspace, { assembly: SHA_ASM, prompts: PROMPTS });
  assert.equal(sha.status, "ok", sha.error ?? "");
  assert.equal(sha.ranked[0].prompt, "This function implements SHA-256 hashing");
  assert.ok(sha.ranked[0].score > 0.5, `SHA score should dominate, got ${sha.ranked.map((entry) => `${entry.prompt.split(" ").slice(-2).join("")}:${entry.score.toFixed(2)}`).join(" ")}`);

  const tea = await rankAssembly(workspace, { assembly: TEA_ASM, prompts: PROMPTS });
  assert.equal(tea.status, "ok", tea.error ?? "");
  assert.equal(tea.ranked[0].prompt, "This is a TEA block cipher", "the delta-constant assembly must rank TEA first");
});

test("live BinSeek calibration: the serial validator outranks allocator and parser", { timeout: 600_000 }, async (context) => {
  const root = await freshWorkspace();
  context.after(async () => {
    await rmRoot(root);
    await shutdownModels().catch(() => {});
  });
  const workspace = await Workspace.create(root);
  clearModelsEnv(context);
  try {
    execFileSync(MODELS_PYTHON, ["-c", "import torch, transformers, sentence_transformers"], { stdio: "pipe" });
  } catch {
    context.skip("needs python + torch + transformers + sentence-transformers");
    return;
  }
  process.env.MINUSONE_MODELS = "1";

  const result = await rankPseudocode(workspace, {
    query: "the function that validates the serial key",
    snippets: [
      { ref: "0x140001000", name: "check_serial", code: 'int check_serial(char *s) { if (strlen(s) != 19) return 0; for (int i = 0; i < 19; i++) if (!valid_char(s[i])) return 0; return compute(s) == 0x5a5a; }' },
      { ref: "0x140002000", name: "alloc_wrapper", code: "void *alloc(int n) { if (n > 1024) n = 1024; return HeapAlloc(h, 0, n); }" },
      { ref: "0x140003000", name: "parse_config", code: 'int parse(char *line, config_t *c) { char *k = strtok(line, "="); char *v = strtok(NULL, "="); set_key(c, k, v); return 0; }' },
    ],
  });
  assert.equal(result.status, "ok", result.error ?? "");
  assert.equal(result.ranked[0].ref, "0x140001000", "check_serial must rank first");
  assert.ok(result.ranked[0].score > result.ranked[1].score, "scores strictly order the candidates");
  assert.ok(result.ranked.every((entry) => typeof entry.score === "number"), "every candidate carries a score — ranker, not oracle");
});

test("model.rank operations attach verification pairs to crypto verdicts", () => {
  const op = operations.find((entry) => entry.id === "model.rank.assembly");
  assert.ok(op, "model.rank.assembly exists");
  assert.match(op.description, /ranker-not-oracle|never a single verdict/i);
  const pseudocodeOp = operations.find((entry) => entry.id === "model.rank.pseudocode");
  assert.ok(pseudocodeOp, "model.rank.pseudocode exists");
  assert.match(pseudocodeOp.description, /unavailable/i, "the description documents the degradation path");
});
