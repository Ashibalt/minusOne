/**
 * Blind evaluation runner: compiles the fixtures, launches the dsh headless
 * agent on each with a prompt that does NOT contain the secret, and checks
 * the agent's final answer for the expected token. Opt-in (needs dsh with a
 * configured model, and gcc; Docker/Ghidra optional — agents fall back to
 * objdump when unavailable). The packed-gate scenario exercises the LOCAL
 * dynamic plane (the packed fixture actually executes briefly) and only runs
 * when MINUSONE_EVAL_DYNAMIC=1.
 *
 *   npm run eval:blind
 *   MINUSONE_EVAL_DYNAMIC=1 npm run eval:blind packed-gate
 *
 * The memory-gate scenario drives memory_volatility over the official
 * Volatility Foundation XP test corpus and only runs when the dataset is
 * present (node scripts/fetch-volatility-data.mjs). The investigation-gate
 * scenario chains the whole pipeline on one packed sample: static triage ->
 * dynamic_unpack -> dumps_floss -> report_correlate, recovering a single
 * secret across all planes (also needs MINUSONE_EVAL_DYNAMIC=1).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const smokeRoot = path.join(repository, ".minusone", "smoke");

const FIXTURES = [
  {
    name: "hello-plaintext",
    source: "hello.c",
    binary: "hello.exe",
    flags: [],
    secret: "minusone-proof-accepted",
    prompt:
      "Blind reverse-engineering task: the binary at .minusone/smoke/hello.exe expects a phrase argument and prints an accepted/rejected verdict. Recover the exact accepted phrase using only static analysis; never execute the binary.",
  },
  {
    name: "xor-obfuscated",
    source: "xorsecret.c",
    binary: "xorsecret.exe",
    flags: [],
    secret: "minusone-xor-gate-7f3a",
    prompt:
      "Blind reverse-engineering task: the binary at .minusone/smoke/xorsecret.exe asks for a passphrase and prints 'access granted' or 'access denied'. The passphrase is obfuscated (never stored in plaintext), so plan for a decode routine: inspect the disassembly for the transformation, dump the relevant data section, and reverse it. Report the exact passphrase. Never execute the binary.",
  },
  {
    name: "dll-export",
    source: "secretlib.c",
    binary: "secretlib.dll",
    flags: ["-shared"],
    secret: "minusone-dll-proof-9c4e",
    prompt:
      "Blind reverse-engineering task: the native DLL at .minusone/smoke/secretlib.dll exports a check function that validates a token. Identify the export and recover the exact token using only static analysis; never execute or load the DLL.",
  },
  {
    name: "packed-gate",
    source: "packedsecret.c",
    binary: "packedsecret.exe",
    flags: [],
    packed: true,
    dynamic: true,
    secret: "minusone-packed-gate-e4c2",
    prompt:
      "Blind reverse-engineering task: the binary at .minusone/smoke/packedsecret.exe is a passphrase gate (it takes one argument and prints 'access granted' or 'access denied'). It is packed, so the passphrase is not recoverable from the file on disk with static tools alone. The dynamic plane is armed on this host: confirm the packer (provider_report, binary_inspect, packer_detect), run dynamic_unpack to dump the unpacked image from memory while the sample executes briefly, then analyze the dumped file statically (binary_inspect, strings_extract, and disassembly or strings_extract_deep as needed) to recover the exact passphrase. Report the exact passphrase.",
  },
  {
    name: "debug-gate",
    source: "xorsecret.c",
    binary: "xorsecret.exe",
    flags: [],
    dynamic: true,
    secret: "minusone-xor-gate-7f3a",
    prompt:
      "Blind reverse-engineering task: the binary at .minusone/smoke/xorsecret.exe asks for a passphrase and prints 'access granted' or 'access denied'. The passphrase is XOR-decoded into a stack buffer only at runtime, so recover it through the debugger plane instead of static decoding: create a debug session with debug_session_create (pass one dummy argument so the check path runs), set a breakpoint around the decode routine, run to it, and read the decoded buffer from process memory with debug_command (registers and x/... memory dumps, stepping as needed). Close the session with debug_session_close when done. Report the exact passphrase.",
  },
  {
    name: "investigation-gate",
    source: "fullcase.c",
    binary: "fullcase.exe",
    flags: [],
    packed: true,
    dynamic: true,
    secret: "minusone-full-case-b91d",
    prompt:
      "Full blind investigation of a packed passphrase gate: the binary at .minusone/smoke/fullcase.exe takes one argument and prints 'access granted' or 'access denied'. Work it as a case across the planes: (1) statically establish what it is (provider_report, binary_inspect, packer_detect). (2) The dynamic plane is armed on this host: run it briefly under dynamic_unpack and keep the dumpDir it reports. (3) Run dumps_floss on that dumpDir to auto-extract decoded/stack/tight strings from every dumped module in one pass. (4) Fuse the evidence with report_correlate (dumpDirPath from step 2). If the dumps yield nothing, fall back to strings_extract_deep or disassembly on the sample itself. Report the exact passphrase.",
  },
  {
    name: "memory-gate",
    dataset: true,
    secret: "Sarah",
    prompt:
      "Blind DFIR task: the file at .minusone/datasets/win-xp-laptop-2005-06-25.img is a full memory capture of a Windows laptop (treat it as evidence — never execute it). Use memory_volatility: start with windows.info to identify the OS, then choose further plugins yourself to answer: (1) the exact Windows version of the captured machine, (2) the primary interactive user account name — recover it from evidence inside the capture such as registry hive paths or process environment, and report it exactly as it appears in the evidence, (3) the total number of processes in the capture. Report all three findings in your final answer.",
  },
];

const MEMORY_DATASET = path.join(repository, ".minusone", "datasets", "win-xp-laptop-2005-06-25.img");

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repository,
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (exitCode) => resolve({ exitCode, stdout, stderr }));
  });
}

function resolveUpx() {
  const explicit = process.env.MINUSONE_UPX_BIN;
  if (explicit) {
    assert.ok(existsSync(explicit), `MINUSONE_UPX_BIN does not exist: ${explicit}`);
    return explicit;
  }
  const bundled = path.join(repository, "tools", "upx.exe");
  if (existsSync(bundled)) return bundled;
  return "upx";
}

async function compileFixtures() {
  await mkdir(smokeRoot, { recursive: true });
  for (const fixture of FIXTURES) {
    if (fixture.dataset) continue;
    const source = path.join(repository, "test", "fixtures", fixture.source);
    const binary = path.join(smokeRoot, fixture.binary);
    if (!fixture.packed) {
      const compilation = await run("gcc", ["-O0", ...fixture.flags, "-o", binary, source]);
      assert.equal(compilation.exitCode, 0, `${fixture.source} failed to compile: ${compilation.stderr}`);
      continue;
    }
    const raw = path.join(smokeRoot, fixture.binary.replace(/\.exe$/i, "-raw.exe"));
    const compilation = await run("gcc", ["-O0", ...fixture.flags, "-o", raw, source]);
    assert.equal(compilation.exitCode, 0, `${fixture.source} failed to compile: ${compilation.stderr}`);
    rmSync(binary, { force: true });
    // LZMA compression: the default NRV codec emits incompressible printable
    // .rdata runs as literals, which leaks the encoded blob to strings.
    const packing = await run(resolveUpx(), ["--lzma", "--best", "-o", binary, raw]);
    assert.equal(packing.exitCode, 0, `${fixture.binary} failed to pack: ${packing.stdout}${packing.stderr}`);
  }
}

/**
 * Resolve a spawnable dsh invocation. On Windows the npm shim is a .cmd that
 * cannot be spawned without a shell, so point at the CLI's JS entry instead
 * (same resolution strategy the PoC used for opencode).
 */
function resolveDshInvocation() {
  if (process.platform !== "win32") return { command: "dsh", prefix: [] };
  const explicit = process.env.MINUSONE_DSH_BIN;
  if (explicit && existsSync(explicit)) return { command: process.execPath, prefix: [explicit] };
  const candidates = [
    process.env.APPDATA ? path.join(process.env.APPDATA, "npm", "node_modules") : undefined,
  ].filter((value) => value !== undefined);
  const globalRoot = spawnSync("npm.cmd", ["root", "-g", "--silent"], { encoding: "utf8" });
  if (globalRoot.status === 0) candidates.push(globalRoot.stdout.trim());
  for (const root of candidates) {
    const entry = path.join(root, "@deepseek-ai", "dsh", "lib", "bin.js");
    if (existsSync(entry)) return { command: process.execPath, prefix: [entry] };
  }
  throw new Error("could not resolve the dsh CLI entry; set MINUSONE_DSH_BIN to .../dsh/lib/bin.js");
}

const dsh = resolveDshInvocation();

function agentTask(prompt, { extraEnv = {}, timeoutMinutes = 10 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(dsh.command, [...dsh.prefix, "--profile", "headless", prompt], {
      cwd: repository,
      env: {
        ...process.env,
        DSH_TELEMETRY_MODE: "DISABLED",
        ...extraEnv,
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), timeoutMinutes * 60_000);
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode) => {
      clearTimeout(timer);
      resolve({ exitCode, stdout, stderr });
    });
  });
}

const selected = process.argv.slice(2).filter((value) => !value.startsWith("-"));
const targets = selected.length > 0 ? FIXTURES.filter((f) => selected.includes(f.name)) : FIXTURES;
const dynamicArmed = process.env.MINUSONE_EVAL_DYNAMIC === "1";

await compileFixtures();

let failures = 0;
let skipped = 0;
for (const fixture of targets) {
  if (fixture.dynamic && !dynamicArmed) {
    console.log(`[eval] ${fixture.name}: SKIP (set MINUSONE_EVAL_DYNAMIC=1 to arm the dynamic-plane scenario)`);
    skipped += 1;
    continue;
  }
  if (fixture.dataset && !existsSync(MEMORY_DATASET)) {
    console.log(`[eval] ${fixture.name}: SKIP (fetch the corpus image first: node scripts/fetch-volatility-data.mjs)`);
    skipped += 1;
    continue;
  }
  process.stdout.write(`[eval] ${fixture.name}: running agent... `);
  const outcome = await agentTask(
    fixture.prompt,
    fixture.dynamic
      ? {
          extraEnv: { MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: "local" },
          timeoutMinutes: 15,
        }
      : fixture.dataset
        ? { timeoutMinutes: 15 }
        : {},
  );
  const recovered = outcome.stdout.includes(fixture.secret);
  const status = recovered && outcome.exitCode === 0 ? "PASS" : "FAIL";
  if (status === "FAIL") failures += 1;
  console.log(`${status} (exit ${outcome.exitCode}, answer ${outcome.stdout.length} chars)`);
  if (status === "FAIL") {
    console.log(outcome.stdout.slice(-800));
    if (outcome.stderr.trim() !== "") console.log("stderr:", outcome.stderr.slice(-400));
  }
}

const evaluated = targets.length - skipped;
console.log(`\n[eval] ${evaluated - failures}/${evaluated} fixtures recovered blind (${skipped} skipped)`);
process.exit(failures === 0 ? 0 : 1);
