import { access } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IMAGES, resolveDockerImage } from "./backends.js";
import { probeCommand, runBoundedCommand } from "./command.js";
import { resolveOpenCodeExecutable } from "./opencode.js";
import { detectWindowsToolchain } from "./windows-tools.js";
import { resolveGdb } from "./debugger.js";
import { resolveDynamicTarget } from "./dynamic.js";
import { probeFridaAvailability } from "./frida.js";
import { isD810Available, resolveD810Path } from "./d810.js";
import { isTtdAvailable, resolveTtdExe, resolveWindbgX } from "./ttd.js";
import { resolveModelsPython } from "./models.js";
import { resolveIdat } from "./ida.js";
import type { DoctorReport, ToolCapability } from "./types.js";
import type { Workspace } from "./workspace.js";

function firstUsefulLine(text: string): string | undefined {
  return text.split(/\r?\n/).map((line) => line.trim()).find(Boolean);
}

async function commandCapability(name: string, command = name, args: string[] = ["--version"]): Promise<ToolCapability> {
  const result = await probeCommand(command, args);
  if (!result) return { name, available: false };
  const version = firstUsefulLine(result.stdout) ?? firstUsefulLine(result.stderr);
  return { name, available: true, ...(version ? { version } : {}) };
}

async function capaCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_CAPA_BIN) {
    return { name: "capa", available: true, path: process.env.MINUSONE_CAPA_BIN, note: "local backend" };
  }
  const local = await commandCapability("capa");
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_CAPA_IMAGE, DEFAULT_IMAGES.capa);
  if (docker.available && image) {
    return { name: "capa", available: true, path: image, note: "Docker backend with pinned capa-rules (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "capa", available: false, note: "Docker backend disabled by an empty MINUSONE_CAPA_IMAGE; set MINUSONE_CAPA_BIN for a local backend." }
    : { name: "capa", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.capa}); install Docker or set MINUSONE_CAPA_BIN.` };
}

async function yaraCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_YARA_BIN) {
    return { name: "yara-x", available: true, path: process.env.MINUSONE_YARA_BIN, note: "local backend" };
  }
  const local = await commandCapability("yara-x", "yr", ["--version"]);
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_YARA_IMAGE, DEFAULT_IMAGES.yaraX);
  if (docker.available && image) {
    return { name: "yara-x", available: true, path: image, note: "Docker backend; rule source is compiled in-sandbox (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "yara-x", available: false, note: "Docker backend disabled by an empty MINUSONE_YARA_IMAGE; set MINUSONE_YARA_BIN for a local backend." }
    : { name: "yara-x", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.yaraX}); install Docker or set MINUSONE_YARA_BIN.` };
}

async function flossCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_FLOSS_BIN) {
    return { name: "floss", available: true, path: process.env.MINUSONE_FLOSS_BIN, note: "local backend" };
  }
  const local = await commandCapability("floss");
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_FLOSS_IMAGE, DEFAULT_IMAGES.floss);
  if (docker.available && image) {
    return { name: "floss", available: true, path: image, note: "Docker backend; decoders are emulated statically, never executed (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "floss", available: false, note: "Docker backend disabled by an empty MINUSONE_FLOSS_IMAGE; set MINUSONE_FLOSS_BIN for a local backend." }
    : { name: "floss", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.floss}); install Docker or set MINUSONE_FLOSS_BIN.` };
}

async function dieCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_DIE_BIN) {
    return { name: "detect-it-easy", available: true, path: process.env.MINUSONE_DIE_BIN, note: "local backend" };
  }
  const local = await commandCapability("detect-it-easy", "diec", ["--version"]);
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_DIE_IMAGE, DEFAULT_IMAGES.die);
  if (docker.available && image) {
    return { name: "detect-it-easy", available: true, path: image, note: "Docker backend; static signatures only, no sample execution (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "detect-it-easy", available: false, note: "Docker backend disabled by an empty MINUSONE_DIE_IMAGE; set MINUSONE_DIE_BIN for a local backend." }
    : { name: "detect-it-easy", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.die}); install Docker or set MINUSONE_DIE_BIN.` };
}

async function radareCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_R2_BIN) {
    return { name: "radare2", available: true, path: process.env.MINUSONE_R2_BIN, note: "local backend" };
  }
  const local = await commandCapability("radare2", "r2", ["-v"]);
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_R2_IMAGE, DEFAULT_IMAGES.radare2);
  if (docker.available && image) {
    return { name: "radare2", available: true, path: image, note: "Docker backend (official image with a pinned tag; not pulled by doctor)" };
  }
  return image === null
    ? { name: "radare2", available: false, note: "Docker backend disabled by an empty MINUSONE_R2_IMAGE; set MINUSONE_R2_BIN for a local backend." }
    : { name: "radare2", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.radare2}); install Docker or set MINUSONE_R2_BIN.` };
}

async function binwalkCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_BINWALK_BIN) {
    return { name: "binwalk", available: true, path: process.env.MINUSONE_BINWALK_BIN, note: "local backend" };
  }
  const local = await commandCapability("binwalk");
  if (local.available) return local;
  const image = resolveDockerImage(process.env.MINUSONE_BINWALK_IMAGE, DEFAULT_IMAGES.binwalk);
  if (docker.available && image) {
    return { name: "binwalk", available: true, path: image, note: "Docker backend; scan + carve-only extract (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "binwalk", available: false, note: "Docker backend disabled by an empty MINUSONE_BINWALK_IMAGE; set MINUSONE_BINWALK_BIN for a local backend." }
    : { name: "binwalk", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.binwalk}); install Docker or set MINUSONE_BINWALK_BIN.` };
}

async function volatilityCapability(docker: ToolCapability): Promise<ToolCapability> {
  if (process.env.MINUSONE_VOLATILITY_BIN) {
    return { name: "volatility3", available: true, path: process.env.MINUSONE_VOLATILITY_BIN, note: "local backend" };
  }
  const local = await probeCommand("vol", ["-h"]);
  if (local && /volatility/i.test(`${local.stdout}\n${local.stderr}`)) {
    return { name: "volatility3", available: true, path: "vol", note: "local backend" };
  }
  const image = resolveDockerImage(process.env.MINUSONE_VOLATILITY_IMAGE, DEFAULT_IMAGES.volatility3);
  if (docker.available && image) {
    return { name: "volatility3", available: true, path: image, note: "Docker backend; kernel symbols served from tools/volatility-symbols, scans run offline (image is not pulled by doctor)" };
  }
  return image === null
    ? { name: "volatility3", available: false, note: "Docker backend disabled by an empty MINUSONE_VOLATILITY_IMAGE; set MINUSONE_VOLATILITY_BIN for a local backend (pip install volatility3)." }
    : { name: "volatility3", available: false, note: `Docker is unavailable (pinned image ${DEFAULT_IMAGES.volatility3}); install Docker or set MINUSONE_VOLATILITY_BIN (pip install volatility3).` };
}

export async function resolveLocalGhidraHeadless(): Promise<string | null> {
  const explicit = process.env.MINUSONE_GHIDRA_HEADLESS;
  const candidates = [
    explicit,
    process.env.GHIDRA_HOME ? path.join(process.env.GHIDRA_HOME, "support", process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless") : undefined,
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return path.resolve(candidate);
    } catch {
      // Try the next configured location.
    }
  }
  return null;
}

export async function createDoctorReport(workspace: Workspace): Promise<DoctorReport> {
  const openCodeExecutable = await resolveOpenCodeExecutable();
  const [opencode, file, strings, readelf, objdump, docker, java] = await Promise.all([
    openCodeExecutable
      ? commandCapability("opencode", openCodeExecutable)
      : Promise.resolve<ToolCapability>({ name: "opencode", available: false }),
    commandCapability("file"),
    commandCapability("strings"),
    commandCapability("readelf"),
    commandCapability("objdump"),
    commandCapability("docker"),
    commandCapability("java", "java", ["-version"]),
  ]);
  // The debug bridge resolves gdb through env/PATH/the MSYS2 prefix, not PATH alone.
  const gdbPath = await resolveGdb();
  const gdb: ToolCapability = gdbPath !== null
    ? await commandCapability("gdb", gdbPath, ["--version"])
    : { name: "gdb", available: false, note: "debug.session backend; install gdb (MSYS2: pacman -S mingw-w64-ucrt-x86_64-gdb) or set MINUSONE_GDB_BIN" };

  const localGhidra = await resolveLocalGhidraHeadless();
  const dockerImage = resolveDockerImage(process.env.MINUSONE_GHIDRA_IMAGE, DEFAULT_IMAGES.ghidra);
  const ghidra: ToolCapability = localGhidra
    ? { name: "ghidra", available: true, path: localGhidra, note: "local headless backend" }
    : docker.available && dockerImage
      ? { name: "ghidra", available: true, path: dockerImage, note: "Docker headless backend (image is not pulled by doctor)" }
      : {
          name: "ghidra",
          available: false,
          note: dockerImage === null
            ? "Docker backend disabled by an empty MINUSONE_GHIDRA_IMAGE; set MINUSONE_GHIDRA_HEADLESS for a local backend (Ghidra 12.1 requires JDK 21)."
            : `Docker is unavailable (pinned image ${DEFAULT_IMAGES.ghidra}); install Docker or set MINUSONE_GHIDRA_HEADLESS (Ghidra 12.1 requires JDK 21 for local execution).`,
        };

  const toolchain = await detectWindowsToolchain();

  // D810-ng deobfuscation: IDA + the plugin, both owner-installed.
  const idat = resolveIdat();
  const d810Ready = await isD810Available();
  const d810: ToolCapability = d810Ready && idat !== null
    ? { name: "d810", available: true, path: resolveD810Path() ?? "", note: `IDA microcode deobfuscation (function.deobfuscate); idat: ${idat}` }
    : {
        name: "d810",
        available: false,
        note: idat === null
          ? "function.deobfuscate needs IDA (licensed) AND the d810-ng plugin in %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng"
          : "IDA is present but the d810-ng plugin is missing: copy the d810-ng repository to %APPDATA%/Hex-Rays/IDA Pro/plugins/d810-ng",
      };

  // Model-ranking sidecar: python + torch + transformers + the models dir.
  const modelsPython = resolveModelsPython();
  let models: ToolCapability = {
    name: "models",
    available: false,
    note: "model.rank_assembly / model.rank_pseudocode need python with torch+transformers+sentence-transformers and ./models (clap-asm, clap-text, BinSeek-Embedding); enable with 'minusone models on'",
  };
  if (modelsPython !== null) {
    // `import torch` initializes CUDA — can take tens of seconds cold.
    const probe = await runBoundedCommand(modelsPython, ["-c", "import torch, transformers, sentence_transformers"], {
      timeoutMs: 90_000,
      maxOutputBytes: 16 * 1024,
    }).catch(() => null);
    if (probe !== null && probe.exitCode === 0) {
      models = {
        name: "models",
        available: true,
        path: modelsPython,
        note: "CLAP + BinSeek ranking sidecar (ranker, not oracle); toggle with 'minusone models on|off'",
      };
    }
  }

  // Time-travel plane: TTD recorder + WinDbgX replay path.
  const ttdReady = await isTtdAvailable();
  const ttd: ToolCapability = ttdReady
    ? { name: "ttd", available: true, path: resolveTtdExe() ?? "", note: `time-travel record/replay (trace.record/trace.replay); replay: ${resolveWindbgX() ?? "?"}; recording needs ELEVATION` }
    : {
        name: "ttd",
        available: false,
        note: "trace.record/trace.replay need tools/ttd/TTD.exe (minusOne setup extracts it from the WinDbg MSIX) and WinDbgX (winget install Microsoft.WinDbg)",
      };

  const fridaRuntime = await probeFridaAvailability();
  const fridaRuntimeCapability: ToolCapability = fridaRuntime.available
    ? {
        name: "frida-runtime",
        available: true,
        ...(fridaRuntime.version ? { version: fridaRuntime.version } : {}),
        note: "node binding; powers dynamic.frida on the armed local plane",
      }
    : {
        name: "frida-runtime",
        available: false,
        note: "dynamic.frida needs the frida node package (npm install frida)",
      };
  const capa = await capaCapability(docker);
  const yara = await yaraCapability(docker);
  const floss = await flossCapability(docker);
  const die = await dieCapability(docker);
  const radare = await radareCapability(docker);
  const binwalk = await binwalkCapability(docker);
  const volatility = await volatilityCapability(docker);

  const capabilities = [opencode, file, strings, readelf, objdump, docker, java, ghidra, capa, yara, floss, die, radare, binwalk, volatility, gdb, fridaRuntimeCapability, d810, models, ttd, ...toolchain.tools];
  return {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    workspace: workspace.root,
    capabilities,
    readyForBaselineAnalysis: objdump.available || readelf.available,
    readyForGhidra: ghidra.available,
    dynamicAnalysisPolicy: await (async () => {
      const mode = await resolveDynamicTarget(workspace);
      const driverNote = `debugger driver detected: ${toolchain.hasDebuggerDriver}, scriptable bridge: gdb ${gdb.available ? "available" : "absent"} / cdb ${toolchain.hasScriptableBridge ? "available" : "absent"}`;
      if (mode === "local") {
        return `enabled with LOCAL target (armed via 'minusone arm' or MINUSONE_ALLOW_DYNAMIC=1 + MINUSONE_DYNAMIC_TARGET=local): sample_execute and dynamic_unpack run samples on this host by owner decision — no VM boundary or network isolation applies (${driverNote})`;
      }
      if (mode === "armed-no-target") {
        return `armed but no target configured: run 'minusone arm' or set MINUSONE_DYNAMIC_TARGET=local to authorize this host as the execution target (${driverNote})`;
      }
      return "disabled (default): samples are never executed; run 'minusone arm' (one-time) or set MINUSONE_ALLOW_DYNAMIC=1 + MINUSONE_DYNAMIC_TARGET=local";
    })(),
  };
}
