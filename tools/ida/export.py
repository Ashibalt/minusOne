"""Headless IDA exporter for minusOne (run via `idat -A -c -S`).

Writes a JSON report: image metadata, bounded function list, import/export
tables, and — when requested — decompiled pseudocode for chosen functions
(Hex-Rays) plus cross-references. The mode and output path arrive through
MINUSONE_IDA_* environment variables so the -S argument stays a plain path
(no quoting hazards in the idat command line).

Modes:
  overview   metadata + functions + imports + exports
  functions  function list only (name/start/size/blocks), optionally filtered
  decompile  pseudocode for --targets (names or hex addresses), bounded
  xrefs      for each target (hex address or string literal): everything
             referencing it — code xrefs (lea/push of the address) resolved
             to containing functions, ready for a follow-up decompile
"""

import json
import os
import sys

import ida_auto
import ida_frame
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import idaapi
import idc

MAX_FUNCTIONS = 4096
MAX_NAMES_PER_FUNCTION = 8
MAX_PSEUDO_CHARS = 20000
MAX_XREFS = 64


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def function_record(function) -> dict:
    frame_size = ida_frame.get_frame_size(function)
    return {
        "name": ida_funcs.get_func_name(function.start_ea),
        "start": hex(function.start_ea),
        "end": hex(function.end_ea),
        "size": function.size(),
        "blocks": sum(1 for _ in idaapi.FlowChart(function)),
        "frame": frame_size if frame_size else None,
    }


def decompile(target: str) -> dict:
    """Decompile one function by name or hex address."""
    try:
        address = int(target, 16) if target.lower().startswith("0x") else idc.get_name_ea_simple(target)
        if address == idaapi.BADADDR:
            return {"target": target, "error": "not found"}
        function = ida_funcs.get_func(address)
        start = function.start_ea if function else address
        if not ida_hexrays.init_hexrays_plugin():
            return {"target": target, "error": "Hex-Rays is unavailable for this file"}
        pseudocode = ida_hexrays.decompile(start)
        if pseudocode is None:
            return {"target": target, "error": "decompilation failed"}
        text = str(pseudocode)
        truncated = len(text) > MAX_PSEUDO_CHARS
        callers = []
        for reference in idautils_XrefsTo(start):
            callers.append({
                "from": hex(reference.frm),
                "function": ida_funcs.get_func_name(reference.frm),
            })
            if len(callers) >= MAX_XREFS:
                break
        return {
            "target": target,
            "name": ida_funcs.get_func_name(start),
            "start": hex(start),
            "pseudocode": text[:MAX_PSEUDO_CHARS],
            "truncated": truncated,
            "callers": callers,
        }
    except Exception as error:  # noqa: BLE001 — report, never crash the batch
        return {"target": target, "error": str(error)}


def idautils_XrefsTo(address):
    import idautils  # noqa: PLC0415 — heavy import, only on demand

    yield from idautils.XrefsTo(address)


def resolve_target(target: str):
    """Resolve a target to an address: hex, name, or string literal."""
    try:
        address = int(target, 16) if target.lower().startswith("0x") else idc.get_name_ea_simple(target)
    except ValueError:
        address = idaapi.BADADDR
    if address != idaapi.BADADDR:
        return address, None
    # String literal: find every occurrence via the strings list (bounded).
    lowered = target.lower()
    matches = []
    for string in idautils_Strings():
        if string.str.lower().find(lowered) != -1:
            matches.append(string.ea)
            if len(matches) >= 8:
                break
    return None, matches


def idautils_Strings():
    import idautils  # noqa: PLC0415 — heavy import, only on demand

    yield from idautils.Strings()


def xrefs_for(target: str) -> dict:
    """Everything that references the target (address or string literal)."""
    try:
        address, literal_hits = resolve_target(target)
        if address is None:
            if not literal_hits:
                return {"target": target, "kind": "string", "error": "string not found in the binary"}
            refs = []
            for hit in literal_hits:
                for reference in idautils_XrefsTo(hit):
                    function = ida_funcs.get_func(reference.frm)
                    refs.append({
                        "stringAddress": hex(hit),
                        "from": hex(reference.frm),
                        "function": ida_funcs.get_func_name(reference.frm) if function else None,
                        "functionStart": hex(function.start_ea) if function else None,
                    })
                    if len(refs) >= MAX_XREFS:
                        break
                if len(refs) >= MAX_XREFS:
                    break
            return {
                "target": target,
                "kind": "string",
                "occurrences": [hex(hit) for hit in literal_hits],
                "xrefs": refs,
            }
        refs = []
        for reference in idautils_XrefsTo(address):
            function = ida_funcs.get_func(reference.frm)
            refs.append({
                "from": hex(reference.frm),
                "function": ida_funcs.get_func_name(reference.frm) if function else None,
                "functionStart": hex(function.start_ea) if function else None,
                "type": str(reference.type),
            })
            if len(refs) >= MAX_XREFS:
                break
        return {"target": target, "kind": "address", "address": hex(address), "xrefs": refs}
    except Exception as error:  # noqa: BLE001 — report, never crash the batch
        return {"target": target, "error": str(error)}


def main() -> None:
    ida_auto.auto_wait()
    mode = os.environ.get("MINUSONE_IDA_MODE", "overview")
    output = os.environ.get("MINUSONE_IDA_OUTPUT")
    if output is None:
        raise SystemExit("MINUSONE_IDA_OUTPUT is not set")

    report: dict = {
        "mode": mode,
        "inputFile": ida_nalt.get_input_file_path(),
        "imageBase": hex(idaapi.get_imagebase()),
        "fileType": idaapi.get_file_type_name(),
    }

    if mode in ("overview", "functions"):
        functions = []
        total = ida_funcs.get_func_qty()
        for index in range(min(total, MAX_FUNCTIONS)):
            function = ida_funcs.getn_func(index)
            functions.append(function_record(function))
        report["functionCount"] = total
        report["functionsTruncated"] = total > MAX_FUNCTIONS
        report["functions"] = functions

    if mode == "overview":
        imports = []
        nimps = ida_nalt.get_import_module_qty()
        modules = []
        for module_index in range(nimps):
            module_name = ida_nalt.get_import_module_name(module_index)
            module_imports = []

            def collect(ea, name, ord_, sink=module_imports):  # noqa: ANN001
                sink.append({"address": hex(ea), "name": name, "ordinal": ord_ if ord_ else None})
                return True

            ida_nalt.enum_import_names(module_index, collect)
            modules.append({"module": module_name, "count": len(module_imports)})
            imports.extend({"module": module_name, **entry} for entry in module_imports[:256])
        report["importModules"] = modules
        report["imports"] = imports[:2048]

        exports = []
        for index, entry in enumerate(idautils_Entries()):
            address, name, ordinal = entry[0], entry[1], entry[2]
            exports.append({"address": hex(address), "name": name, "ordinal": ordinal})
            if index >= 1024:
                break
        report["exports"] = exports

    if mode == "decompile":
        targets = json.loads(os.environ.get("MINUSONE_IDA_TARGETS", "[]"))
        report["decompilations"] = [decompile(target) for target in targets]

    if mode == "xrefs":
        targets = json.loads(os.environ.get("MINUSONE_IDA_TARGETS", "[]"))
        report["xrefs"] = [xrefs_for(target) for target in targets]

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    ida_pro.qexit(0)


def idautils_Entries():
    import idautils  # noqa: PLC0415 — heavy import, only on demand

    yield from idautils.Entries()


main()
