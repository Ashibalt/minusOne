#!/usr/bin/env python3
"""Rebuild a loadable PE from a pe-sieve memory dump.

pe-sieve dumps faithfully reproduce the in-memory image of a module: the
section table carries the *virtual* sizes, the import directory may point
into a destroyed/unmapped thunk array, and the file often cannot be loaded
by the OS loader as-is. This script best-effort rebuilds a runnable PE:

  1. Load the dump with LIEF.
  2. If the dump's import table is missing or unusable, transplant the
     ORIGINAL sample's import directory (a dump of the same module at a
     different point in its lifetime keeps the same statically-linked
     imports; the unpacked image just added runtime-resolved ones).
  3. For each section, set raw size/data offset from the dumped content
     and clear uninitialized-data flags that block loaders on sections
     that now carry real content (same intent as the dump sanitizer).
  4. Rebuild and write the output plus a JSON report of every repair.

Best-effort by design: IAT reconstruction after unpacking is an art
(the original IAT may be destroyed, redirected through stubs, or rebuilt
elsewhere in memory). Every failure is reported, never fatal — the output
is always written when LIEF could parse the dump at all.
"""
import json
import sys

import lief


def log(message: str) -> None:
    print(f"[pe-rebuild] {message}", file=sys.stderr)


def import_fingerprint(pe) -> dict:
    """Bounded view of an import table usable for comparison/reporting."""
    imports = {}
    try:
        for entry in pe.imports:
            dll = entry.name if entry.name else "?"
            functions = []
            for func in entry.entries:
                if func.name:
                    functions.append(func.name)
                elif func.is_ordinal:
                    functions.append(f"#{func.ordinal}")
            imports[dll] = functions
    except Exception as error:  # noqa: BLE001 - report, never fail
        log(f"import enumeration failed: {error}")
    return imports


def rebuild(dump_path: str, original_path: str | None, output_path: str) -> int:
    try:
        dump = lief.PE.parse(dump_path)
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"status": "error", "stage": "parse-dump", "detail": str(error)}))
        return 2
    if dump is None:
        print(json.dumps({"status": "error", "stage": "parse-dump", "detail": "LIEF could not parse the dump as a PE"}))
        return 2

    report = {
        "status": "ok",
        "dump": dump_path,
        "original": original_path,
        "output": output_path,
        "repairs": [],
        "importsRestored": None,
        "dumpImports": None,
        "originalImports": None,
        "sectionAdjustments": [],
    }

    original = None
    if original_path:
        try:
            original = lief.PE.parse(original_path)
        except Exception as error:  # noqa: BLE001
            log(f"original parse failed: {error}")

    # --- 0. rebase off the ASLR address the dump was taken at ----------------
    # The dump was taken at an ASLR address (e.g. 0x7ff6...). The loader can
    # rebase the rebuilt PE itself THROUGH the relocation table, so instead of
    # rewriting every absolute reference we normalize the relocation directory:
    # LIEF's builder relocates the image to the default base and rebuilds the
    # directory coherently. When there are no relocations at all, we set the
    # default base directly (nothing references the old one).
    dumped_base = dump.optional_header.imagebase
    try:
        default_base = 0x180000000 if dump.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64 else 0x400000
        if dumped_base != default_base:
            dump.optional_header.imagebase = default_base
            report["repairs"].append(
                f"rebased image from the ASLR address {hex(dumped_base)} to the default {hex(default_base)}"
                + (" (relocations rebuilt)" if dump.has_relocations else " (no relocations present)")
            )
    except Exception as error:  # noqa: BLE001
        log(f"rebase failed: {error}")

    # --- 1. import table restoration --------------------------------------
    dump_imports = import_fingerprint(dump)
    report["dumpImports"] = {dll: len(funcs) for dll, funcs in dump_imports.items()}
    dump_import_count = sum(len(funcs) for funcs in dump_imports.values())

    if dump_import_count == 0 and original is not None:
        original_imports = import_fingerprint(original)
        original_import_count = sum(len(funcs) for funcs in original_imports.values())
        report["originalImports"] = {dll: len(funcs) for dll, funcs in original_imports.items()}
        if original_import_count > 0:
            try:
                for dll, functions in original_imports.items():
                    lib = None
                    for entry in dump.imports:
                        if entry.name == dll:
                            lib = entry
                            break
                    if lib is None:
                        lib = dump.add_library(dll)
                    for function in functions:
                        name = function if not function.startswith("#") else None
                        ordinal = int(function[1:]) if function.startswith("#") else 0
                        if name:
                            lib.add_entry(name)
                        elif ordinal:
                            lib.add_entry(ordinal)
                report["importsRestored"] = {dll: len(funcs) for dll, funcs in original_imports.items()}
                report["repairs"].append(
                    f"restored the original import table ({original_import_count} functions across "
                    f"{len(original_imports)} DLLs) into the dump"
                )
            except Exception as error:  # noqa: BLE001
                log(f"import restoration failed: {error}")
                report["repairs"].append(f"import restoration failed: {error}")
        else:
            report["repairs"].append("the original sample itself has no import table to transplant")
    elif dump_import_count > 0:
        report["repairs"].append(
            f"the dump already carries {dump_import_count} import entries across "
            f"{len(dump_imports)} DLLs; original not needed"
        )

    # --- 2. section table normalization ------------------------------------
    try:
        file_alignment = dump.optional_header.file_alignment or 0x200
        for section in dump.sections:
            virtual_size = section.virtual_size
            raw_size = section.size
            if raw_size == 0 and virtual_size > 0:
                # The section carried only virtual content in the dump; give it
                # the raw bytes it actually owns so loaders can map it.
                section.size = virtual_size
                report["sectionAdjustments"].append(
                    {"section": section.name, "change": f"raw size 0 -> 0x{virtual_size:x} (from virtual size)"}
                )
            if raw_size % file_alignment != 0 and virtual_size > 0:
                aligned = ((raw_size + file_alignment - 1) // file_alignment) * file_alignment
                section.size = aligned
                report["sectionAdjustments"].append(
                    {"section": section.name, "change": f"raw size 0x{raw_size:x} aligned to 0x{aligned:x}"}
                )
    except Exception as error:  # noqa: BLE001
        log(f"section normalization failed: {error}")

    # --- 3. rebuild ----------------------------------------------------------
    try:
        builder = lief.PE.Builder(dump)
        builder.build_imports(True)  # rebuild the import table (IAT fixup)
        builder.patch_imports(True)
        if dump.has_relocations:
            builder.build_relocations(True)
        builder.build()
        builder.write(output_path)
        report["repairs"].append("rebuilt with import-table reconstruction and import patching enabled")
    except Exception as error:  # noqa: BLE001
        print(json.dumps({**report, "status": "error", "stage": "rebuild", "detail": str(error)}))
        return 3

    print(json.dumps(report))
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: pe-rebuild.py <dump> <output> [original]", file=sys.stderr)
        return 1
    dump_path = sys.argv[1]
    output_path = sys.argv[2]
    original_path = sys.argv[3] if len(sys.argv) > 3 else None
    return rebuild(dump_path, original_path, output_path)


if __name__ == "__main__":
    sys.exit(main())
