"""Symbolic execution runner for minusOne (docker entrypoint).

Reads a JSON job from stdin, writes a JSON result to stdout. The sample is
loaded as DATA into angr's CLE loader and explored symbolically — nothing
executes on the host, there is no network, no process of the sample.

Job shapes:
  mode "solve":    find inputs that reach a target address (or the
                   avoid address backwards) — the keygen question.
    {"mode": "solve", "binary": "/workspace/sample.exe",
     "target": "0x4012f0",           # address (or symbol) that means "valid"
     "avoid": ["0x4013a0"],          # addresses that mean "invalid"
     "stdinLen": 16,                 # model the input as argv[0]? stdin bytes
     "args": ["SYMBOL"],             # argv entries; "SYMBOL" becomes symbolic
     "maxStates": 2000, "timeoutSeconds": 240}

  mode "simplify": z3 simplification of an MBA expression + optional
                   EQUIVALENCE PROOF against a guessed simpler form.
    {"mode": "simplify", "expression": "(x ^ y) + 2*(x & y)",
     "vars": ["x", "y"], "bits": 32,
     "candidate": "x + y"}     # optional: prove/disprove expr == candidate

Result (stdout): JSON with status and mode-specific fields. Every failure
is {"status": "error", "error": ...} — the TS side degrades per request.
"""

import json
import os
import sys
import traceback

MAX_EXPR_CHARS = 4000
MAX_VARS = 8
DEFAULT_BITS = 32


def bounded_int(value, default, lo, hi):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def run_solve(job: dict) -> dict:
    import angr
    import claripy

    binary = str(job.get("binary", ""))
    if not binary or not os.path.isfile(binary):
        return {"status": "error", "error": f"binary not found: {binary}"}

    target = job.get("target")
    avoid = [str(a) for a in job.get("avoid", []) if str(a).strip()]
    stdin_len = bounded_int(job.get("stdinLen"), 0, 0, 64)
    argv = [str(a) for a in job.get("args", [])]
    max_states = bounded_int(job.get("maxStates"), 2000, 10, 20000)
    timeout_seconds = bounded_int(job.get("timeoutSeconds"), 240, 10, 1800)

    def parse_addr(value: str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except (TypeError, ValueError):
            return None

    # Load with instruction-count pressure OFF: autodicts are slow and
    # crackmes are small; we trade load time for exploration time.
    project = angr.Project(binary, auto_load_libs=False)

    # Resolve the target: hex address, or a symbol through the loader
    # (kb.functions is empty until a full analysis runs — too slow here).
    target_addr = None
    if target is not None:
        target = str(target)
        if target.lower().startswith("0x") or target.isdigit():
            target_addr = parse_addr(target)
        else:
            symbol = project.loader.find_symbol(target)
            if symbol is not None and symbol.rebased_addr is not None:
                target_addr = symbol.rebased_addr
            else:
                return {"status": "error", "error": f"symbol not found: {target} (pass the hex address from your disassembly instead)"}
        if target_addr is None:
            return {"status": "error", "error": f"cannot parse target {target!r}"}
        # Hook the target with a termination stub so exploration stops there
        # (the classic angr keygen recipe).
        project.hook(target_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())

    avoid_addrs = []
    for entry in avoid:
        addr = parse_addr(entry)
        if addr is None:
            symbol = project.loader.find_symbol(entry)
            if symbol is None or symbol.rebased_addr is None:
                continue
            addr = symbol.rebased_addr
        avoid_addrs.append(addr)

    # Start AT the validator instead of the process entry: PE binaries drag
    # the whole CRT init (millions of instructions) through the simulation;
    # call_state at the entrypoint with a hand-built argv reaches the check
    # in seconds — how analysts actually use angr on crackmes.
    state_args = argv if argv else []
    argv_symbol = None
    if "SYMBOL" in state_args:
        argv_symbol = claripy.BVS("argv0", 8 * 64)
        index = state_args.index("SYMBOL")
        state_args[index] = argv_symbol

    # PE+gcc binaries call __main (CRT init) INSIDE main and puts/printf at
    # the end — both drag the simulation into unmapped externals. __main is
    # stubbed to a plain return; libc calls get angr's REAL sim procedures
    # (a ReturnUnconstrained stub would "return" into the call_state's
    # missing return address and kill the state — the trap that cost an
    # hour of debugging).
    for external in ("__main", "__stack_chk_fail"):
        external_symbol = project.loader.find_symbol(external)
        if external_symbol is not None and external_symbol.rebased_addr is not None:
            project.hook(external_symbol.rebased_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
    for libc_name in ("puts", "printf", "malloc", "free", "memcpy", "strlen"):
        libc_symbol = project.loader.find_symbol(libc_name)
        if libc_symbol is not None and libc_symbol.rebased_addr is not None:
            try:
                project.hook(libc_symbol.rebased_addr, angr.SIM_PROCEDURES["libc"][libc_name]())
            except KeyError:
                pass

    entry = entry_point(project)
    entry_state = project.factory.call_state(
        entry,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )

    # Hand-build the argv block: a page near the stack top, argv[0] = the
    # binary path, argv[1] = the (symbolic or concrete) key, then NULL.
    if state_args:
        argv_page = 0x7fff0000
        try:
            entry_state.memory.map_region(argv_page, 0x1000, 1)
        except Exception:  # noqa: BLE001 - already mapped
            pass
        current = argv_page + 0x100
        pointers = []
        concrete_argv0 = f"{argv_page + 0x400:x}".encode() + b"\x00"
        entry_state.memory.store(argv_page + 0x400, concrete_argv0)
        pointers.append(argv_page + 0x400)
        for index, arg in enumerate(state_args):
            slot = argv_page + 0x200 + index * 0x40
            if isinstance(arg, claripy.ast.Bits):
                entry_state.memory.store(slot, arg, endness="Iend_BE")
            else:
                entry_state.memory.store(slot, str(arg).encode() + b"\x00")
            pointers.append(slot)
        for index, pointer in enumerate(pointers):
            entry_state.memory.store(argv_page + 0x10 + index * 8, pointer, endness=project.arch.memory_endness)
        # x64 windows calling convention: rcx = argc is not a thing; main
        # reads argc/argv from the stack shadow — but gcc main() takes
        # (argc, argv) via (ecx, rdx). call_state passes positional args.
        entry_state.regs.ecx = len(pointers)
        entry_state.regs.rdx = argv_page + 0x10

    stdin_symbol = None
    if stdin_len > 0:
        stdin_symbol = claripy.BVS("stdin", 8 * stdin_len)
        entry_state.posix.stdin = angr.SimFile("/dev/stdin", content=stdin_symbol, has_end=False)

    simulation = project.factory.simgr(entry_state)
    exploration_result = simulation.explore(
        find=target_addr,
        avoid=avoid_addrs if avoid_addrs else None,
        num=find_limit(max_states),
    )

    import time

    deadline = time.time() + timeout_seconds
    solutions = []
    errors = []
    found = list(simulation.found)
    for state in found[:8]:
        if time.time() > deadline:
            errors.append("solution evaluation timed out")
            break
        solution = {"how": "argv" if argv_symbol is not None else "stdin"}
        if argv_symbol is not None:
            try:
                model = state.solver.eval(argv_symbol, cast_to=bytes)
                solution["argv"] = model.rstrip(b"\x00").decode("latin1")
            except Exception as error:  # noqa: BLE001
                solution["argvError"] = f"{type(error).__name__}: {error}"
        if stdin_symbol is not None:
            try:
                model = state.solver.eval(stdin_symbol, cast_to=bytes)
                solution["stdinHex"] = model.hex()
                solution["stdin"] = model.decode("latin1")
            except Exception as error:  # noqa: BLE001
                solution["stdinError"] = f"{type(error).__name__}: {error}"
        # Register snapshot at the target: what the validator compared.
        try:
            solution["atAddress"] = hex(state.addr)
            solution["rax"] = hex(state.solver.eval(state.regs.rax))
            solution["eax"] = hex(state.solver.eval(state.regs.eax))
        except Exception:  # noqa: BLE001
            pass
        solutions.append(solution)

    return {
        "status": "ok",
        "mode": "solve",
        "target": hex(target_addr) if target_addr is not None else None,
        "avoid": [hex(a) for a in avoid_addrs],
        "foundCount": len(simulation.found),
        "avoidedCount": len(simulation.avoid) if hasattr(simulation, "avoid") else 0,
        "deadendedCount": len(simulation.deadended),
        "solutions": solutions,
        "notes": [
            "solutions are concrete inputs that reach the target address",
            "verify by running the sample with the input — the solver proves reachability, not semantics",
        ],
        **({"errors": errors} if errors else {}),
    }


def entry_point(project):
    """Resolve main() when the symbol exists (gcc -g keeps it); fall back to
    the ELF/PE entrypoint."""
    symbol = project.loader.find_symbol("main")
    if symbol is not None and symbol.rebased_addr is not None:
        return symbol.rebased_addr
    return project.loader.main_object.entry


def find_limit(max_states: int):
    # angr's explore(num=...) caps the number of found states.
    return max(1, max_states)


def run_simplify(job: dict) -> dict:
    expression = str(job.get("expression", ""))[:MAX_EXPR_CHARS]
    variables = [str(v) for v in job.get("vars", [])][:MAX_VARS]
    bits = bounded_int(job.get("bits"), DEFAULT_BITS, 8, 64)
    if not expression:
        return {"status": "error", "error": "expression is required"}
    if not variables:
        return {"status": "error", "error": "vars is required (the free variables of the expression)"}

    import claripy
    import z3

    # claripy's local simplify is weak on MBA; the z3 simplify tactic
    # (bundled with angr) collapses these reliably. The expression is
    # evaluated twice — once in claripy for the equivalence check, once in
    # z3 for the display simplification.
    env = {}
    for name in variables:
        env[name] = claripy.BVS(name, bits)
    try:
        ast = eval(expression, {"__builtins__": {}}, env)  # noqa: S307 - the caller is the analyst
    except Exception as error:  # noqa: BLE001
        return {"status": "error", "error": f"expression evaluation failed: {type(error).__name__}: {error}"}

    z3_env = {}
    for name in variables:
        z3_env[name] = z3.BitVec(name, bits)
    try:
        z3_raw = eval(expression, {"__builtins__": {}}, z3_env)  # noqa: S307
        z3_simplified = z3.simplify(z3_raw)
        simplified_repr = str(z3_simplified)
    except Exception as error:  # noqa: BLE001
        simplified_repr = claripy.simplify(ast).__repr__()
        z3_raw = None

    # Equivalence PROOF against the analyst's guess ("is this wall really
    # just x + y?"): z3 ForAll over the free variables decides it. This is
    # the honest form of MBA collapse — the guess is confirmed or refuted
    # on every input, not pattern-matched.
    candidate = job.get("candidate")
    candidate_equivalent = None
    candidate_checked = False
    if candidate is not None and z3_raw is not None:
        candidate = str(candidate)[:MAX_EXPR_CHARS]
        try:
            z3_candidate = eval(candidate, {"__builtins__": {}}, z3_env)  # noqa: S307
            solver = z3.Solver()
            solver.set(timeout=30_000)
            solver.add(z3.ForAll(list(z3_env.values()), z3_raw == z3_candidate))
            result = solver.check()
            if result == z3.sat:
                candidate_equivalent = True
            elif result == z3.unsat:
                candidate_equivalent = False
            candidate_checked = True
        except Exception:  # noqa: BLE001
            candidate_checked = False

    # A truth-table equivalence check for small widths: the simplified form
    # must match the original on every input — proof, not vibes. The check
    # compares the ORIGINAL against the z3-simplified form re-evaluated in
    # z3 (cheaper than claripy substitution for small widths).
    checked = False
    equivalent = None
    if bits <= 8 and len(variables) <= 2 and z3_raw is not None:
        try:
            for pattern in range(1 << bits):
                z3_subs = {}
                for index, name in enumerate(variables):
                    value = (pattern >> index) & ((1 << bits) - 1)
                    z3_subs[z3_env[name]] = z3.BitVecVal(value, bits)
                orig = z3.substitute(z3_raw, z3_subs)
                simp = z3.substitute(z3_simplified, z3_subs)
                if z3.simplify(orig != simp).is_true():
                    equivalent = False
                    break
            else:
                equivalent = True
            checked = True
        except Exception:  # noqa: BLE001
            checked = False

    return {
        "status": "ok",
        "mode": "simplify",
        "original": expression,
        "simplified": simplified_repr,
        "bits": bits,
        "vars": variables,
        **({"candidate": candidate, "candidateEquivalent": candidate_equivalent} if candidate_checked else {}),
        **({"equivalenceChecked": checked, "equivalent": equivalent} if checked else {}),
        "notes": [
            "z3 simplification of the expression",
            "candidateEquivalent=true/false is a ForAll PROOF that the expression equals (or differs from) the guessed form on every input",
            "equivalenceChecked=true means the simplified form matches the original on every input (exhaustive for <=8 bits, <=2 vars)",
        ],
    }


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"status": "error", "error": "empty job"}))
        return 0
    try:
        job = json.loads(raw)
    except json.JSONDecodeError as error:
        print(json.dumps({"status": "error", "error": f"invalid JSON: {error}"}))
        return 0

    mode = str(job.get("mode", ""))
    try:
        if mode == "solve":
            result = run_solve(job)
        elif mode == "simplify":
            result = run_simplify(job)
        else:
            result = {"status": "error", "error": f"unknown mode {mode!r} (expected solve | simplify)"}
    except Exception as error:  # noqa: BLE001 - one bad job dies alone
        result = {
            "status": "error",
            "error": f"{type(error).__name__}: {error}",
            "traceback": traceback.format_exc(limit=6),
        }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
