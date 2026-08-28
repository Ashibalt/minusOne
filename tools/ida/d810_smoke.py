"""Headless D810-ng smoke check for minusOne.

Loads the MBA-obfuscation fixture under idat, activates the D810-ng
deobfuscation harness (default rules), and decompiles flattened_check both
with and without D810 so the effect is measurable. Report is JSON on
stdout via MINUSONE_D810_OUT.

The plugin normally activates through the IDA UI; in headless mode we drive
its manager directly (d810.manager.D810State) the way the plugin's init
does, then run one decompilation pass per optimizer profile.
"""

import json
import os
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_pro
import idaapi
import idc


def log(message: str) -> None:
    print(f"minusone-d810: {message}")


def main() -> None:
    out_path = os.environ.get("MINUSONE_D810_OUT")
    if not out_path:
        log("MINUSONE_D810_OUT not set; aborting")
        ida_pro.qexit(1)
        return

    report = {"d810Available": False, "baseline": None, "deobfuscated": None, "error": None}

    try:
        ida_auto.auto_wait()

        if not ida_hexrays.init_hexrays_plugin():
            report["error"] = "Hex-Rays unavailable"
        else:
            target_name = os.environ.get("MINUSONE_D810_TARGET", "flattened_check")
            ea = idc.get_name_ea_simple(target_name)
            if ea == idaapi.BADADDR:
                # fall back to any non-library function
                for function_ea in idautils.Functions():
                    if not (ida_funcs.get_func(function_ea).flags & idaapi.FUNC_LIB):
                        ea = function_ea
                        break
            if ea == idaapi.BADADDR:
                report["error"] = "no function found to decompile"
            else:
                baseline = ida_hexrays.decompile(ea)
                report["baseline"] = str(baseline) if baseline else None

                # Activate D810-ng the headless way. Rule classes register
                # themselves via __init_subclass__ at MODULE IMPORT time, but
                # nothing imports them in headless mode (in the UI the plugin
                # loader does). Scan every rule package the way d810-ng's own
                # test conftest does, so the registries are populated before
                # D810State.load() enumerates known rules.
                try:
                    d810_root = os.environ.get("MINUSONE_D810_PATH", "")
                    sys.path.insert(0, d810_root)
                    import d810  # noqa: F401
                    from d810._vendor.ida_reloader import Scanner

                    rule_packages = [
                        "optimizers/microcode/instructions/pattern_matching",
                        "optimizers/microcode/instructions/chain",
                        "optimizers/microcode/instructions/early",
                        "optimizers/microcode/instructions/peephole",
                        "optimizers/microcode/instructions/z3",
                        "optimizers/microcode/instructions/analysis",
                        "optimizers/microcode/flow",
                    ]
                    for relative in rule_packages:
                        package_dir = os.path.join(d810_root, "d810", *relative.split("/"))
                        if not os.path.isdir(package_dir):
                            continue
                        prefix = "d810." + ".".join(relative.split("/")) + "."
                        try:
                            Scanner.scan(
                                package_path=[package_dir],
                                prefix=prefix,
                                callback=None,
                                skip_packages=True,
                            )
                        except Exception as scan_error:  # noqa: BLE001
                            log(f"scan {relative} failed: {scan_error}")

                    import d810.manager as manager

                    state = manager.D810State(name="D810")
                    state.load(gui=False)
                    # Pick the deobfuscation profile by file name; the OLLVM
                    # unflattening profile is the default for combat work.
                    wanted = os.environ.get(
                        "MINUSONE_D810_PROJECT", "default_unflattening_ollvm"
                    )
                    # Project keys carry the .json extension; accept the stem or
                    # the full file name so an explicit profile actually selects.
                    wanted_names = (
                        {wanted}
                        if wanted.endswith(".json")
                        else {wanted, wanted + ".json"}
                    )
                    chosen = None
                    for index in range(len(state.project_manager)):
                        project = state.project_manager.get(index)
                        if project is not None and project.path.name in wanted_names:
                            chosen = index
                            break
                    if chosen is not None and chosen != state.current_project_index:
                        state.load_project(chosen)
                        log(f"project profile: {wanted}")
                    report["profile"] = wanted
                    state.start_d810()
                    report["d810Available"] = True
                    log("D810 activated")

                    deobfuscated = ida_hexrays.decompile(ea)
                    report["deobfuscated"] = str(deobfuscated) if deobfuscated else None

                    state.stop_d810()
                    state.unload(gui=False)
                except Exception as error:  # noqa: BLE001 - report and continue
                    import traceback

                    report["error"] = f"D810 activation failed: {type(error).__name__}: {error}"
                    report["traceback"] = traceback.format_exc()
                    log(report["error"])
    except Exception as error:  # noqa: BLE001
        report["error"] = f"{type(error).__name__}: {error}"

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    log(f"report written to {out_path}")
    ida_pro.qexit(0)


import idautils  # noqa: E402  (IDA injects stdlib quirks; keep the import late but visible)

if __name__ == "__main__":
    main()
