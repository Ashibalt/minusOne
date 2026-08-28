"""Unicorn emulation runner for minusOne (docker entrypoint).

Reads a JSON job from stdin (or MINUSONE_EMU_JOB env), emulates code
snippets with mapped memory + registers, writes a JSON result to stdout.
The emulated code never touches the host: no process, no syscalls, no
filesystem — Unicorn executes CPU instructions against a flat memory map
we control.

Job shape — single run (legacy):
{
  "arch": "x86" | "x64",
  "codeHex": "...",            # code bytes to execute at entry
  "entryOffset": 0,            # where in the code mapping execution starts
  "base": "0x100000",          # mapping base for code+data
  "codeMaxBytes": 65536,
  "data": [                    # additional mappings
    {"address": "0x200000", "bytesHex": "...", "size": 4096}
  ],
  "registers": {"eax": "0x10"},
  "runAddress": "0x100000",    # start RIP (default base)
  "until": "0x100fff",         # stop address (default: end of the code mapping)
  "timeoutUs": 1000000,
  "count": 10000000
}

Job shape — chain (multi-step, stateful):
{
  "arch": "x64",
  "base": "0x100000",
  "data": [...],               # mappings shared by ALL steps
  "registers": {...},          # initial registers, applied before step 1
  "steps": [                   # max 16; memory + registers carry across steps
    {"codeHex": "...", "registers": {"rcx": "0x10"}, "until": "0x100fff"},
    {"codeHex": "..."}
  ]
}
Each step's code is written at `base` (replacing the previous step's code).
Per-step fields: codeHex (required), entryOffset, runAddress, until,
registers (applied before the step), timeoutUs, count. A step that ends in
`ret` gets a fresh stack sentinel — no stack wiring needed. The chain stops
at the first failed step (state past a failure is garbage).

Job shape — diff (reconstruction oracle):
{
  "arch": "x64",
  "codeHex": "...",             # THEIR function (carved), run under Unicorn
  "registers": {...},           # initial registers (shared by both sides)
  "data": [...],                # input mappings (the candidate sees the ORIGINAL bytes)
  "until": "0x100fff",
  "candidate": {
    "python": "out = bytes(b ^ 0x42 for b in mem[0x200000][:4])",
    "outputAddress": "0x201000",  # window the reference writes its result to
    "outputLength": 4              # optional; default: the mapping size at outputAddress
  }
}
The candidate snippet runs in the same container with `mem` (address int →
original input bytes), `regs` (name → int, INITIAL values), `struct`, and a
whitelisted builtins set; it must assign `out` to bytes. The comparison
trims trailing zeros off the reference window (sparse outputs are the
norm), then reports match / firstDivergence / divergenceCount.

Result (stdout): JSON with status; single mode carries final registers,
mapped memory, and a bounded trace head; chain mode carries a per-step
array of the same; diff mode carries the comparison verdict. Bad input
always answers {"status": "error"} — never a traceback.
"""

import json
import os
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP,
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RIP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
)

MAX_TRACE = 256
MAX_CHAIN_TRACE = 64
MAX_STEPS = 16
MAX_DIFF_BYTES = 0x100000
DIFF_PREVIEW_BYTES = 512
REG32 = {
    "eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
    "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP,
    "eip": UC_X86_REG_EIP,
}
REG64 = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI, "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
    "rip": UC_X86_REG_RIP,
    # r8–r15: the argument/base/counter registers of compiled x64 code —
    # r12–r15 are the callee-saved loop registers most carved functions
    # live in. Without them, setting up a function's calling convention
    # is impossible.
    "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13, "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
}


def parse_int(value, default=None):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text.startswith("0x"):
        return int(text[2:], 16)
    try:
        return int(text, 10)
    except ValueError:
        return int(text, 16)


def export_memory(uc, mappings):
    """Read back every data mapping — what the snippet WROTE is the point."""
    memory_out = []
    for mapping in mappings:
        address = parse_int(mapping.get("address"))
        size = min(parse_int(mapping.get("size"), 0x1000), 0x1000000)
        if address is None:
            continue
        try:
            raw = bytes(uc.mem_read(address, size))
            # Trim trailing zeros so JSON stays small for sparse outputs.
            trimmed = raw.rstrip(b"\x00")
            memory_out.append({
                "address": hex(address),
                "size": size,
                "bytesHex": trimmed.hex() if len(trimmed) > 0 else "",
                "writtenBytes": len(trimmed),
            })
        except Exception as read_error:  # noqa: BLE001
            # NEVER name this binding `error`: `except X as e` DELETES the
            # name after the block, which used to unbind a run-status
            # `error = None` above and turn any read failure here into an
            # UnboundLocalError that destroyed the whole JSON result.
            memory_out.append({"address": hex(address), "size": size, "error": str(read_error)})
    return memory_out


def run_step(uc, regs, spec, *, base, code_max, stack_pointer, esp_reg, is64, trace_cap, label):
    """Run ONE step in place. Returns the per-step result dict; raises
    nothing — every failure is a {"status": "error"} answer."""
    result = {"step": label, "status": "ok", "error": None}
    try:
        code = bytes.fromhex(spec.get("codeHex", ""))
    except ValueError as hex_error:
        return {**result, "status": "error", "error": f"codeHex is not valid hex: {hex_error}"}
    if len(code) == 0:
        return {**result, "status": "error", "error": "codeHex is empty"}
    if len(code) > code_max:
        return {**result, "status": "error", "error": f"codeHex ({len(code)} bytes) exceeds the code mapping ({code_max} bytes)"}

    uc.mem_write(base, code)

    # Per-step registers, then re-arm the stack sentinel: a previous step's
    # `ret` consumed the old return address and moved SP past it.
    for name, value in (spec.get("registers") or {}).items():
        if name.lower() in regs:
            uc.reg_write(regs[name.lower()], parse_int(value, 0))
    if (spec.get("registers") or {}).get("esp" if not is64 else "rsp") is None:
        sentinel = parse_int(spec.get("until"), base + code_max - 1)
        fmt = "<Q" if is64 else "<I"
        uc.mem_write(stack_pointer, struct.pack(fmt, sentinel))
        uc.reg_write(esp_reg, stack_pointer)

    run_address = parse_int(spec.get("runAddress"), base + parse_int(spec.get("entryOffset", 0), 0))
    until = parse_int(spec.get("until"), base + code_max - 1)
    timeout_us = min(parse_int(spec.get("timeoutUs"), 1_000_000), 60_000_000)
    count = min(parse_int(spec.get("count"), 10_000_000), 200_000_000)

    trace = []
    trace_holder = {"list": trace}

    def hook_code(uc_, address, size_, user):
        current = trace_holder["list"]
        if len(current) < trace_holder["cap"]:
            regs_snapshot = {}
            for name, const in regs.items():
                regs_snapshot[name] = hex(uc_.reg_read(const))
            current.append({"address": hex(address), "size": size_, "registers": regs_snapshot})

    trace_holder["cap"] = trace_cap
    hook = uc.hook_add(UC_HOOK_CODE, hook_code)
    try:
        try:
            # emu_start(begin, until, timeout_us, count) — positional: the
            # keyword form is not supported on this binding version.
            uc.emu_start(run_address, until, timeout_us, count)
        except Exception as err:  # noqa: BLE001 — Unicorn errors are the result, not a crash
            result["status"] = "error"
            result["error"] = str(err)
    finally:
        uc.hook_del(hook)

    final_registers = {name: hex(uc.reg_read(const)) for name, const in regs.items()}
    result["entry"] = hex(run_address)
    result["stoppedAt"] = final_registers.get("rip" if is64 else "eip")
    result["registers"] = final_registers
    result["traceHead"] = trace
    result["traceTruncated"] = len(trace) >= trace_cap
    return result


def run_diff(uc, regs, job, *, base, code_max, stack_pointer, esp_reg, is64):
    """Reconstruction oracle: emulate THEIR function, evaluate the analyst's
    python reimplementation against the same inputs, report the first
    diverging byte. Every failure is a structured error — never a traceback."""
    candidate = job.get("candidate")
    if not isinstance(candidate, dict):
        return {"status": "error", "error": "candidate must be an object with python + outputAddress"}
    python_source = str(candidate.get("python", ""))
    output_address = parse_int(candidate.get("outputAddress"))
    output_length = parse_int(candidate.get("outputLength"))
    if output_address is None:
        return {"status": "error", "error": "candidate.outputAddress is required (the window the reference writes its result to)"}
    if not python_source:
        return {"status": "error", "error": "candidate.python is required (a snippet that assigns out = bytes(...))"}

    data_specs = job.get("data", [])[:16]
    # Snapshot the ORIGINAL inputs and INITIAL registers: the candidate is an
    # independent implementation fed the same inputs, never the leftovers of
    # the reference run.
    mem_in = {}
    for mapping in data_specs:
        address = parse_int(mapping.get("address"))
        if address is None:
            continue
        size = min(parse_int(mapping.get("size"), 0x1000), 0x1000000)
        try:
            mem_in[address] = bytes(uc.mem_read(address, size))
        except Exception:  # noqa: BLE001 — failed mappings already carry their error
            pass
    regs_in = {name: uc.reg_read(const) for name, const in regs.items()}

    spec = {key: job[key] for key in ("codeHex", "entryOffset", "runAddress", "until", "timeoutUs", "count", "registers") if key in job}
    step = run_step(
        uc, regs, spec,
        base=base, code_max=code_max,
        stack_pointer=stack_pointer, esp_reg=esp_reg, is64=is64,
        trace_cap=MAX_CHAIN_TRACE, label=0,
    )
    reference = {
        "status": step["status"],
        "error": step["error"],
        "registers": step.get("registers", {}),
        "stoppedAt": step.get("stoppedAt"),
    }
    if step["status"] != "ok":
        return {"status": "error", "error": f"reference emulation failed: {step['error']}", "reference": reference}

    if output_length is None:
        for mapping in data_specs:
            if parse_int(mapping.get("address")) == output_address:
                output_length = min(parse_int(mapping.get("size"), 0x1000), 0x1000000)
                break
        else:
            output_length = 16
    output_length = min(output_length, MAX_DIFF_BYTES)
    try:
        reference_bytes = bytes(uc.mem_read(output_address, output_length))
    except Exception as read_error:  # noqa: BLE001
        return {"status": "error", "error": f"cannot read the reference output window at {hex(output_address)}: {read_error}", "reference": reference}
    # Sparse outputs are the norm: a 4KB window with 16 meaningful bytes
    # compares against a 16-byte candidate. Trim trailing zeros first.
    trimmed = reference_bytes.rstrip(b"\x00")
    trimmed_bytes = len(reference_bytes) - len(trimmed)
    reference_bytes = trimmed

    safe_builtins = {
        "abs": abs, "all": all, "any": any, "bool": bool, "bytearray": bytearray,
        "bytes": bytes, "chr": chr, "dict": dict, "divmod": divmod, "enumerate": enumerate,
        "filter": filter, "hex": hex, "int": int, "len": len, "list": list, "map": map,
        "max": max, "min": min, "oct": oct, "ord": ord, "range": range, "reversed": reversed,
        "round": round, "set": set, "slice": slice, "sorted": sorted, "str": str,
        "sum": sum, "tuple": tuple, "zip": zip,
    }
    env = {"__builtins__": safe_builtins, "mem": mem_in, "regs": regs_in, "struct": struct}
    try:
        exec(python_source, env)  # noqa: S102 — sandboxed docker (--network none, --rm); the caller is the analyst
    except Exception as eval_error:  # noqa: BLE001 — a candidate crash is a result, not a crash of the oracle
        return {
            "status": "error",
            "error": f"candidate python failed: {type(eval_error).__name__}: {eval_error}",
            "reference": reference,
            "candidate": {"status": "error"},
        }
    out = env.get("out")
    if not isinstance(out, (bytes, bytearray)):
        return {
            "status": "error",
            "error": "candidate python must assign `out` to a bytes/bytearray value",
            "reference": reference,
            "candidate": {"status": "error"},
        }
    candidate_bytes = bytes(out)[:MAX_DIFF_BYTES]

    overlap = min(len(reference_bytes), len(candidate_bytes))
    divergence_offsets = []
    first = None
    for index in range(overlap):
        if reference_bytes[index] != candidate_bytes[index]:
            if first is None:
                first = {
                    "offset": index,
                    "referenceHex": f"{reference_bytes[index]:02x}",
                    "candidateHex": f"{candidate_bytes[index]:02x}",
                }
            divergence_offsets.append(index)
    length_mismatch = len(reference_bytes) != len(candidate_bytes)
    return {
        "status": "ok",
        "match": not divergence_offsets and not length_mismatch,
        "outputAddress": hex(output_address),
        "comparedBytes": overlap,
        "referenceBytes": len(reference_bytes),
        "candidateBytes": len(candidate_bytes),
        "referenceTrailingZerosTrimmed": trimmed_bytes,
        "lengthMismatch": length_mismatch,
        "divergenceCount": len(divergence_offsets),
        "firstDivergence": first,
        "divergenceOffsets": divergence_offsets[:64],
        "reference": reference,
        "candidate": {"status": "ok", "outputBytes": len(candidate_bytes)},
        "referenceOutputHex": reference_bytes[:DIFF_PREVIEW_BYTES].hex(),
        "candidateOutputHex": candidate_bytes[:DIFF_PREVIEW_BYTES].hex(),
    }


def main() -> None:
    # The job arrives either on stdin (interactive use) or through the
    # MINUSONE_EMU_JOB env var (the MCP path — spawned commands have no
    # stdin wiring). Bad input answers a STRUCTURED error on stdout and
    # exits clean — a traceback here is a broken contract (the caller
    # would see a non-JSON answer and lose the whole result).
    def fail(message: str) -> None:
        print(json.dumps({"status": "error", "error": message}))

    env_job = os.environ.get("MINUSONE_EMU_JOB")
    try:
        if env_job:
            job = json.loads(env_job)
        else:
            job = json.load(sys.stdin)
    except ValueError as parse_error:
        fail(f"job is not valid JSON: {parse_error}")
        return
    if not isinstance(job, dict):
        fail(f"job must be a JSON object, got {type(job).__name__}")
        return
    arch = job.get("arch", "x86")
    is64 = arch == "x64"
    uc = Uc(UC_ARCH_X86, UC_MODE_64 if is64 else UC_MODE_32)
    regs = REG64 if is64 else REG32

    base = parse_int(job.get("base"), 0x100000)
    code_max = min(parse_int(job.get("codeMaxBytes"), 0x10000), 0x100000)

    steps = job.get("steps")
    candidate = job.get("candidate")
    diff_mode = candidate is not None
    chain_mode = steps is not None and not diff_mode
    if diff_mode:
        pass  # candidate shape is validated inside run_diff
    elif chain_mode:
        if not isinstance(steps, list) or len(steps) == 0:
            fail("steps must be a non-empty array")
            return
        if len(steps) > MAX_STEPS:
            fail(f"too many steps ({len(steps)}; max {MAX_STEPS})")
            return
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                fail(f"step {index} must be an object, got {type(step).__name__}")
                return
    else:
        # Single-run mode validates codeHex here so the failure shape stays
        # identical to the historical contract.
        try:
            single_code = bytes.fromhex(job.get("codeHex", ""))
        except ValueError as hex_error:
            fail(f"codeHex is not valid hex: {hex_error}")
            return
        if len(single_code) == 0:
            fail("codeHex is empty")
            return
        del single_code

    uc.mem_map(base, code_max)

    # Default stack: snippets routinely `ret` at the end; an unmapped ESP
    # would abort with UC_ERR_READ_UNMAPPED. We push a sentinel equal to
    # the until-address so a bare `ret` lands on the stop condition and
    # emu_start finishes cleanly instead of crashing through the stack.
    # The sentinel is re-armed per step (a `ret` consumes it).
    stack_size = 0x10000
    stack_base = parse_int(job.get("stackBase"), 0x700000)
    stack_pointer = stack_base + stack_size // 2
    esp_reg = UC_X86_REG_ESP if not is64 else UC_X86_REG_RSP
    try:
        uc.mem_map(stack_base, stack_size)
    except Exception:  # noqa: BLE001 — a custom stack may already be mapped
        pass

    mappings = []
    for mapping in job.get("data", [])[:16]:
        address = parse_int(mapping.get("address"))
        size = min(parse_int(mapping.get("size"), 0x1000), 0x1000000)
        if address is None:
            continue
        # Unicorn requires 4KB-aligned mapping bases; a misaligned data
        # address used to die here with UC_ERR_ARG. Align the base DOWN and
        # grow the size so the caller's [address, address+size) window stays
        # fully covered; payload writes and read-backs still target the
        # ORIGINAL address, so the caller's mental model never shifts.
        delta = address % 0x1000
        map_address = address - delta
        map_size = ((size + delta + 0xFFF) // 0x1000) * 0x1000
        try:
            uc.mem_map(map_address, map_size)
            payload_hex = mapping.get("bytesHex", "")
            if payload_hex:
                uc.mem_write(address, bytes.fromhex(payload_hex)[:size])
            entry = {"address": hex(address), "size": size}
            if delta or map_size != size:
                entry["mappedAddress"] = hex(map_address)
                entry["mappedSize"] = map_size
            mappings.append(entry)
        except Exception as map_error:  # noqa: BLE001 — one bad mapping must not kill the run
            mappings.append({"address": hex(address), "size": size, "error": str(map_error)})

    # Job-level registers are the INITIAL state (applied before step 1 in
    # chain mode; the only set in single mode).
    for name, value in (job.get("registers") or {}).items():
        if name.lower() in regs:
            uc.reg_write(regs[name.lower()], parse_int(value, 0))

    if chain_mode:
        step_results = []
        overall = "ok"
        error = None
        for index, step in enumerate(steps):
            trace_cap = MAX_CHAIN_TRACE
            step_result = run_step(
                uc, regs, step,
                base=base, code_max=code_max,
                stack_pointer=stack_pointer, esp_reg=esp_reg, is64=is64,
                trace_cap=trace_cap, label=index,
            )
            step_result["memory"] = export_memory(uc, job.get("data", [])[:16])
            step_results.append(step_result)
            if step_result["status"] != "ok":
                # State past a failed step is garbage — stop the chain here.
                overall = "error"
                error = f"step {index} failed: {step_result['error']}"
                break
        print(json.dumps({
            "status": overall,
            "error": error,
            "arch": arch,
            "stepsCompleted": sum(1 for s in step_results if s["status"] == "ok"),
            "steps": step_results,
            "mappings": mappings,
        }))
        return

    # ---- diff mode: reconstruction oracle -----------------------------------
    if diff_mode:
        print(json.dumps(run_diff(
            uc, regs, job,
            base=base, code_max=code_max,
            stack_pointer=stack_pointer, esp_reg=esp_reg, is64=is64,
        )))
        return

    # ---- legacy single-run shape (unchanged contract) ----------------------
    spec = {
        "codeHex": job.get("codeHex", ""),
        "entryOffset": job.get("entryOffset", 0),
        **{key: job[key] for key in ("runAddress", "until", "timeoutUs", "count") if key in job},
    }
    step_result = run_step(
        uc, regs, spec,
        base=base, code_max=code_max,
        stack_pointer=stack_pointer, esp_reg=esp_reg, is64=is64,
        trace_cap=MAX_TRACE, label=None,
    )
    code = bytes.fromhex(job.get("codeHex", ""))
    code_read = bytes(uc.mem_read(base, min(len(code), code_max)))
    print(json.dumps({
        "status": step_result["status"],
        "error": step_result["error"],
        "arch": arch,
        "entry": step_result.get("entry", "unknown"),
        "stoppedAt": step_result.get("stoppedAt"),
        "registers": step_result.get("registers", {}),
        "mappings": mappings,
        "memory": export_memory(uc, job.get("data", [])[:16]),
        "traceHead": step_result.get("traceHead", []),
        "traceTruncated": step_result.get("traceTruncated", False),
        "codeMappingHeadHex": code_read.hex()[:8192],
    }))


if __name__ == "__main__":
    main()
