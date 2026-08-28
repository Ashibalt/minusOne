#!/usr/bin/env node
/**
 * minusOne readiness bootstrap: builds every pinned docker image, checks the
 * native toolchain, and prints an operations-readiness report so the owner
 * knows exactly which capabilities are live before an engagement.
 *
 *   node scripts/bootstrap.mjs [--images-only | --report-only | --skip-build]
 *
 * --report-only  skip image building and native probes, just print the plan
 * --images-only  build images and exit (no report)
 * --skip-build   report against whatever images already exist
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const IMAGES = [
  { tag: "minusone/capa:9.4.0", dockerfile: "docker/capa.Dockerfile" },
  { tag: "minusone/yara-x:1.19.0", dockerfile: "docker/yarax.Dockerfile" },
  { tag: "minusone/floss:3.1.1", dockerfile: "docker/floss.Dockerfile" },
  { tag: "minusone/die:3.21", dockerfile: "docker/die.Dockerfile" },
  { tag: "minusone/binwalk:2.3.3", dockerfile: "docker/binwalk.Dockerfile" },
  { tag: "minusone/ghidra:12.1.2", dockerfile: "docker/ghidra.Dockerfile" },
  { tag: "minusone/volatility3:2.28.0", dockerfile: "docker/volatility3.Dockerfile" },
  { tag: "minusone/pe-tools:lief", dockerfile: "docker/pe-tools.Dockerfile" },
  { tag: "minusone/unicorn:2.1.3", dockerfile: "docker/unicorn.Dockerfile" },
  { tag: "minusone/symbolic:angr9.3.3", dockerfile: "docker/symbolic.Dockerfile" },
];

const NATIVE_TOOLS = [
  { name: "docker", probe: ["docker", "--version"], note: "container backends" },
  { name: "node", probe: [process.execPath, "--version"], note: "host runtime" },
  { name: "gcc", probe: ["gcc", "--version"], note: "test-fixture compilation" },
  { name: "gdb", probe: ["gdb", "--version"], note: "debug.session.create (gdb)" },
  { name: "r2", probe: ["r2", "-v"], note: "disassembly (local) — docker fallback exists" },
  { name: "frida", probe: [process.execPath, "-e", "import('frida')"], note: "dynamic.frida node binding" },
];

const PATH_HINTS = [
  { env: "MINUSONE_CDB_PATH", hint: "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe", op: "debug cdb backend" },
  { env: "MINUSONE_X64DBG_HOME", hint: "C:\\x64dbg", op: "debug x64dbg backend" },
  { env: "MINUSONE_PESIEVE_BIN", hint: "tools/pe-sieve64.exe (bundled)", op: "dynamic.unpack" },
];

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return result;
}

async function buildImages(skip) {
  if (skip) {
    console.log("[bootstrap] skipping image builds (--skip-build)");
    return;
  }
  console.log(`[bootstrap] building ${IMAGES.length} docker images...`);
  for (const image of IMAGES) {
    const existing = run("docker", ["image", "inspect", image.tag]);
    if (existing.status === 0) {
      console.log(`  ok (cached)  ${image.tag}`);
      continue;
    }
    process.stdout.write(`  building    ${image.tag} ... `);
    const build = run("docker", ["build", "-f", image.dockerfile, "-t", image.tag, "."], { cwd: packageRoot });
    if (build.status === 0) console.log("done");
    else {
      console.log("FAILED");
      console.log(`    ${String(build.stderr ?? "").split(/\r?\n/).slice(-5).join("\n    ")}`);
    }
  }
}

function imagePresent(tag) {
  return run("docker", ["image", "inspect", tag]).status === 0;
}

function probeNative(tool) {
  try {
    const result = run(tool.probe[0], tool.probe.slice(1));
    return result.status === 0;
  } catch {
    return false;
  }
}

/**
 * Ensure the TTD recorder + WinDbgX replay path exist: install WinDbg via
 * winget (idempotent) and extract the TTD stack from the MSIX into
 * tools/ttd (MSIX package paths are not directly executable). Skip
 * silently when pieces are already in place.
 */
function setupTtd() {
  const ttdExe = path.join(packageRoot, "tools", "ttd", "TTD.exe");
  if (existsSync(ttdExe)) {
    console.log("[bootstrap] TTD: tools/ttd/TTD.exe present");
    return;
  }
  console.log("[bootstrap] TTD: setting up (winget WinDbg + extract)...");
  const winget = run("winget", ["install", "Microsoft.WinDbg", "--accept-source-agreements", "--accept-package-agreements"]);
  if (winget.status !== 0 && !existsSync(path.join(process.env.LOCALAPPDATA ?? "", "Microsoft", "WindowsApps", "WinDbgX.exe"))) {
    console.log(`  winget WinDbg failed: ${String(winget.stderr ?? "").split("\\n").slice(-2).join(" ")}`);
    console.log("  trace.record/trace.replay stay unavailable; install WinDbg manually (https://aka.ms/windbg) and rerun bootstrap");
    return;
  }
  // Find the installed MSIX package directory.
  const appsRoot = "C:\\Program Files\\WindowsApps";
  let windbgDir = null;
  try {
    for (const entry of readdirSync(appsRoot)) {
      if (/^Microsoft\.WinDbg_.*x64__/i.test(entry)) windbgDir = path.join(appsRoot, entry);
    }
  } catch {
    console.log("  cannot enumerate WindowsApps (permission) — TTD setup skipped");
    return;
  }
  if (windbgDir === null) {
    console.log("  WinDbg MSIX not found after install — TTD setup skipped");
    return;
  }
  const src = path.join(windbgDir, "amd64");
  const dst = path.join(packageRoot, "tools", "ttd");
  run("powershell", ["-NoProfile", "-Command",
    `New-Item -ItemType Directory -Force -Path '${dst}' | Out-Null; ` +
    `robocopy '${src}' '${dst}' cdb.exe dbgeng.dll dbghelp.dll dbgcore.dll dbgmodel.dll ntkdmp.dll symsrv.dll srcsrv.dll /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null; ` +
    `robocopy '${path.join(src, "ttd")}' '${dst}' /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null; ` +
    `Remove-Item '${path.join(dst, "wow64")}' -Recurse -Force -ErrorAction SilentlyContinue`]);
  if (existsSync(ttdExe)) console.log("  TTD stack extracted to tools/ttd");
  else console.log("  TTD extraction failed — check tools/ttd manually");
}

function printReport() {
  console.log("");
  console.log("=== minusOne readiness report ===");
  console.log(`workspace root: ${packageRoot}`);
  console.log("");

  console.log("Container backends:");
  for (const image of IMAGES) {
    const present = imagePresent(image.tag);
    console.log(`  ${present ? "ok      " : "missing "} ${image.tag}`);
  }
  const radare = imagePresent("radare/radare2:5.9.8");
  console.log(`  ${radare ? "ok      " : "missing "} radare/radare2:5.9.8 (pinned default, docker pull)`);
  console.log("");

  console.log("Native tools:");
  for (const tool of NATIVE_TOOLS) {
    const present = probeNative(tool);
    console.log(`  ${present ? "ok      " : "missing "} ${tool.name.padEnd(8)} ${tool.note}`);
  }
  console.log("");

  console.log("Path overrides (optional, auto-detected when unset):");
  for (const hint of PATH_HINTS) {
    const set = process.env[hint.env] !== undefined;
    console.log(`  ${set ? "set     " : "unset   "} ${hint.env.padEnd(22)} ${hint.op} (${hint.hint})`);
  }
  console.log("");

  const cdbDefault = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe";
  if (process.env.MINUSONE_CDB_PATH === undefined && !existsSync(cdbDefault)) {
    console.log("note: cdb not found at the default Windows Kits path; debug cdb sessions will refuse until installed or MINUSONE_CDB_PATH is set.");
  }
  console.log("Dynamic plane: unarmed by default. Run 'minusOne arm <workspace>' once to authorize the local execution target.");
  console.log("");
}

const flags = process.argv.slice(2);
if (flags.includes("--report-only")) {
  printReport();
} else {
  await buildImages(flags.includes("--skip-build"));
  if (!flags.includes("--images-only")) {
    setupTtd();
    printReport();
  }
}
