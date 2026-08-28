// Export bounded function metadata, decompiler output, and call references as JSON.
// When entry addresses are passed, only those functions are exported; otherwise the
// first max-functions functions in program order are exported.
// With "--references <address...>" the script answers a different question:
// which functions REFERENCE the given addresses (data or code)? Every reference
// is resolved to its containing function, and each referring function is
// exported with its decompiled code — the string/xref/decompile pipeline in
// one headless run.
// With "--range <start> <end>" the script exports the FUNCTIONS intersecting
// the address range (the megaprocedure slicer): decompilation is attempted
// per function with a SHORT timeout so one 800KB flattened monster cannot
// eat the whole budget, and any function that fails or times out falls back
// to a disassembly listing of its range portion with call annotations —
// the agent always gets structure, never an empty timeout.
// @category minusOne

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportAnalysis extends GhidraScript {
    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder output = new StringBuilder(value.length() + 16);
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': output.append("\\\""); break;
                case '\\': output.append("\\\\"); break;
                case '\b': output.append("\\b"); break;
                case '\f': output.append("\\f"); break;
                case '\n': output.append("\\n"); break;
                case '\r': output.append("\\r"); break;
                case '\t': output.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        output.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        output.append(character);
                    }
            }
        }
        output.append('"');
        return output.toString();
    }

    private static int boundedInteger(String value, int minimum, int maximum) {
        int parsed = Integer.parseInt(value);
        return Math.min(Math.max(parsed, minimum), maximum);
    }

    private List<Function> resolveAddressTargets(String[] addressArguments) {
        List<Function> resolved = new ArrayList<>();
        for (String argument : addressArguments) {
            long value;
            try {
                value = Long.decode(argument);
            }
            catch (NumberFormatException error) {
                println("minusOne: ignoring malformed target address " + argument);
                continue;
            }
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                function = currentProgram.getFunctionManager().getFunctionContaining(address);
            }
            if (function == null) {
                println("minusOne: no function at or containing " + argument);
                continue;
            }
            if (!resolved.contains(function)) {
                resolved.add(function);
            }
        }
        return resolved;
    }

    private void writeXrefs(BufferedWriter writer, Function function) throws Exception {
        List<String> callers = new ArrayList<>();
        for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
            String fromAddress = reference.getFromAddress().toString();
            String callerName = caller == null ? null : caller.getName();
            String callerEntry = caller == null ? null : caller.getEntryPoint().toString();
            callers.add(
                "{\"fromAddress\": " + json(fromAddress) +
                ", \"callerName\": " + json(callerName) +
                ", \"callerEntryPoint\": " + json(callerEntry) +
                ", \"referenceType\": " + json(reference.getReferenceType().toString()) + "}"
            );
        }
        List<String> callees = new ArrayList<>();
        for (Function callee : function.getCalledFunctions(monitor)) {
            callees.add(
                "{\"name\": " + json(callee.getName()) +
                ", \"entryPoint\": " + json(callee.getEntryPoint().toString()) +
                ", \"isThunk\": " + callee.isThunk() + "}"
            );
        }
        writer.write("      \"callers\": [" + String.join(", ", callers) + "],\n");
        writer.write("      \"callees\": [" + String.join(", ", callees) + "],\n");
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 3) {
            throw new IllegalArgumentException(
                "Usage: ExportAnalysis.java <output.json> <max-functions> <max-decompiled-chars> [--references] [entry-address...]"
            );
        }

        Path outputPath = Paths.get(arguments[0]).toAbsolutePath().normalize();
        int maxFunctions = boundedInteger(arguments[1], 1, 200);
        int maxDecompiledChars = boundedInteger(arguments[2], 256, 10_000);
        String[] addressArguments = new String[arguments.length - 3];
        System.arraycopy(arguments, 3, addressArguments, 0, addressArguments.length);
        boolean referencesMode = addressArguments.length > 0 && "--references".equals(addressArguments[0]);
        boolean rangeMode = addressArguments.length >= 3 && "--range".equals(addressArguments[0]);
        if (referencesMode) {
            String[] stripped = new String[addressArguments.length - 1];
            System.arraycopy(addressArguments, 1, stripped, 0, stripped.length);
            addressArguments = stripped;
        }
        if (rangeMode) {
            String[] stripped = new String[addressArguments.length - 3];
            System.arraycopy(addressArguments, 3, stripped, 0, stripped.length);
            addressArguments = stripped;
        }
        if (referencesMode && addressArguments.length == 0) {
            throw new IllegalArgumentException("--references requires at least one target address");
        }
        Files.createDirectories(outputPath.getParent());

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Decompiler could not open the current program");
        }

        if (referencesMode) {
            runReferencesMode(outputPath, maxFunctions, maxDecompiledChars, addressArguments, decompiler);
            decompiler.dispose();
            println("minusOne references analysis exported to " + outputPath);
            return;
        }
        if (rangeMode) {
            String rangeStart = arguments[4];
            String rangeEnd = arguments[5];
            runRangeMode(outputPath, maxFunctions, maxDecompiledChars, rangeStart, rangeEnd, decompiler);
            decompiler.dispose();
            println("minusOne range analysis exported to " + outputPath);
            return;
        }

        List<Function> targetedFunctions = addressArguments.length > 0 ? resolveAddressTargets(addressArguments) : null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        int scopeTotal = targetedFunctions == null ? totalFunctions : targetedFunctions.size();
        int exportedFunctions = 0;

        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            writer.write("{\n");
            writer.write("  \"schemaVersion\": 2,\n");
            writer.write("  \"program\": {\n");
            writer.write("    \"name\": " + json(currentProgram.getName()) + ",\n");
            writer.write("    \"executableFormat\": " + json(currentProgram.getExecutableFormat()) + ",\n");
            writer.write("    \"language\": " + json(currentProgram.getLanguageID().toString()) + ",\n");
            writer.write("    \"imageBase\": " + json(currentProgram.getImageBase().toString()) + "\n");
            writer.write("  },\n");
            writer.write("  \"scope\": {\"targetedAddresses\": [" +
                joinQuoted(addressArguments) + "], \"functionCountTotal\": " + totalFunctions + "},\n");
            writer.write("  \"limits\": {\"maxFunctions\": " + maxFunctions +
                ", \"maxDecompiledChars\": " + maxDecompiledChars + "},\n");
            writer.write("  \"functionCountTotal\": " + totalFunctions + ",\n");
            writer.write("  \"functions\": [\n");

            while (exportedFunctions < maxFunctions && !monitor.isCancelled()) {
                Function function;
                if (targetedFunctions != null) {
                    if (exportedFunctions >= targetedFunctions.size()) {
                        break;
                    }
                    function = targetedFunctions.get(exportedFunctions);
                }
                else {
                    if (!functions.hasNext()) {
                        break;
                    }
                    function = functions.next();
                }
                if (exportedFunctions > 0) {
                    writer.write(",\n");
                }

                String decompiledCode = null;
                boolean decompilationCompleted = false;
                boolean decompilationTruncated = false;
                String decompilationError = null;
                try {
                    DecompileResults decompilation = decompiler.decompileFunction(function, 30, monitor);
                    decompilationCompleted = decompilation.decompileCompleted();
                    if (decompilationCompleted && decompilation.getDecompiledFunction() != null) {
                        decompiledCode = decompilation.getDecompiledFunction().getC();
                        if (decompiledCode.length() > maxDecompiledChars) {
                            decompiledCode = decompiledCode.substring(0, maxDecompiledChars);
                            decompilationTruncated = true;
                        }
                    }
                    else {
                        decompilationError = decompilation.getErrorMessage();
                    }
                }
                catch (Exception error) {
                    decompilationError = error.getClass().getSimpleName() + ": " + error.getMessage();
                }

                writer.write("    {\n");
                writer.write("      \"name\": " + json(function.getName()) + ",\n");
                writer.write("      \"entryPoint\": " + json(function.getEntryPoint().toString()) + ",\n");
                writer.write("      \"signature\": " + json(function.getSignature().getPrototypeString()) + ",\n");
                writer.write("      \"bodySize\": " + function.getBody().getNumAddresses() + ",\n");
                writer.write("      \"isThunk\": " + function.isThunk() + ",\n");
                writeXrefs(writer, function);
                writer.write("      \"decompilationCompleted\": " + decompilationCompleted + ",\n");
                writer.write("      \"decompilationTruncated\": " + decompilationTruncated + ",\n");
                writer.write("      \"decompilationError\": " + json(decompilationError) + ",\n");
                writer.write("      \"decompiledCode\": " + json(decompiledCode) + "\n");
                writer.write("    }");
                exportedFunctions++;
            }

            writer.write("\n  ],\n");
            writer.write("  \"functionsExported\": " + exportedFunctions + ",\n");
            writer.write("  \"truncated\": " + (exportedFunctions < scopeTotal) + "\n");
            writer.write("}\n");
        }
        finally {
            decompiler.dispose();
        }

        println("minusOne analysis exported to " + outputPath);
    }

    /**
     * References mode: for each TARGET address (typically a string or data
     * VA), find every reference TO it, resolve the containing function, and
     * export those referring functions with their decompiled code. Output
     * shape mirrors the normal export (functions[] with decompiledCode) plus
     * per-function "referencedTargets" so the caller knows which target(s)
     * each function touches and from where.
     */
    private void runReferencesMode(Path outputPath, int maxFunctions, int maxDecompiledChars,
            String[] targetArguments, DecompInterface decompiler) throws Exception {

        // target argument -> parsed address (skip malformed)
        List<Address> targets = new ArrayList<>();
        List<String> targetNames = new ArrayList<>();
        for (String argument : targetArguments) {
            long value;
            try {
                value = Long.decode(argument);
            }
            catch (NumberFormatException error) {
                println("minusOne: ignoring malformed reference target " + argument);
                continue;
            }
            targets.add(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value));
            targetNames.add(argument);
        }

        // referring function -> references it makes to the targets
        Map<Function, List<String>> referring = new LinkedHashMap<>();
        for (Address target : targets) {
            for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(target)) {
                Function container = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                if (container == null) {
                    continue;
                }
                List<String> hits = referring.computeIfAbsent(container, key -> new ArrayList<>());
                hits.add(
                    "{\"target\": " + json(target.toString()) +
                    ", \"fromAddress\": " + json(reference.getFromAddress().toString()) +
                    ", \"referenceType\": " + json(reference.getReferenceType().toString()) + "}"
                );
            }
        }

        int totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        int exported = 0;
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            writer.write("{\n");
            writer.write("  \"schemaVersion\": 2,\n");
            writer.write("  \"referencesMode\": true,\n");
            writer.write("  \"program\": {\n");
            writer.write("    \"name\": " + json(currentProgram.getName()) + ",\n");
            writer.write("    \"executableFormat\": " + json(currentProgram.getExecutableFormat()) + ",\n");
            writer.write("    \"language\": " + json(currentProgram.getLanguageID().toString()) + ",\n");
            writer.write("    \"imageBase\": " + json(currentProgram.getImageBase().toString()) + "\n");
            writer.write("  },\n");
            writer.write("  \"scope\": {\"targetedAddresses\": [" + joinQuoted(targetNames.toArray(new String[0])) +
                "], \"functionCountTotal\": " + totalFunctions + "},\n");
            writer.write("  \"limits\": {\"maxFunctions\": " + maxFunctions +
                ", \"maxDecompiledChars\": " + maxDecompiledChars + "},\n");
            writer.write("  \"referenceSitesTotal\": " + referring.values().stream().mapToInt(List::size).sum() + ",\n");
            writer.write("  \"functions\": [\n");

            for (Function function : referring.keySet()) {
                if (exported >= maxFunctions || monitor.isCancelled()) {
                    break;
                }
                if (exported > 0) {
                    writer.write(",\n");
                }

                String decompiledCode = null;
                boolean decompilationCompleted = false;
                boolean decompilationTruncated = false;
                String decompilationError = null;
                try {
                    DecompileResults decompilation = decompiler.decompileFunction(function, 30, monitor);
                    decompilationCompleted = decompilation.decompileCompleted();
                    if (decompilationCompleted && decompilation.getDecompiledFunction() != null) {
                        decompiledCode = decompilation.getDecompiledFunction().getC();
                        if (decompiledCode.length() > maxDecompiledChars) {
                            decompiledCode = decompiledCode.substring(0, maxDecompiledChars);
                            decompilationTruncated = true;
                        }
                    }
                    else {
                        decompilationError = decompilation.getErrorMessage();
                    }
                }
                catch (Exception error) {
                    decompilationError = error.getClass().getSimpleName() + ": " + error.getMessage();
                }

                writer.write("    {\n");
                writer.write("      \"name\": " + json(function.getName()) + ",\n");
                writer.write("      \"entryPoint\": " + json(function.getEntryPoint().toString()) + ",\n");
                writer.write("      \"signature\": " + json(function.getSignature().getPrototypeString()) + ",\n");
                writer.write("      \"isThunk\": " + function.isThunk() + ",\n");
                writer.write("      \"referencedTargets\": [" + String.join(", ", referring.get(function)) + "],\n");
                writer.write("      \"decompilationCompleted\": " + decompilationCompleted + ",\n");
                writer.write("      \"decompilationTruncated\": " + decompilationTruncated + ",\n");
                writer.write("      \"decompilationError\": " + json(decompilationError) + ",\n");
                writer.write("      \"decompiledCode\": " + json(decompiledCode) + "\n");
                writer.write("    }");
                exported++;
            }

            writer.write("\n  ],\n");
            writer.write("  \"functionsExported\": " + exported + ",\n");
            writer.write("  \"referringFunctionsTotal\": " + referring.size() + ",\n");
            writer.write("  \"truncated\": " + (exported < referring.size()) + "\n");
            writer.write("}\n");
        }
    }

    /**
     * Range mode (the megaprocedure slicer): export every function that
     * INTERSECTS [start, end]. Each function gets a short decompile attempt
     * (a flattened megaprocedure may take minutes whole — a bounded slice
     * attempt keeps the budget) and, when decompilation fails or times out,
     * a disassembly listing of the function's portion inside the range with
     * call/branch annotations. The agent always walks away with structure.
     */
    private void runRangeMode(Path outputPath, int maxFunctions, int maxDecompiledChars,
            String startArgument, String endArgument, DecompInterface decompiler) throws Exception {

        long startValue;
        long endValue;
        try {
            startValue = Long.decode(startArgument);
            endValue = Long.decode(endArgument);
        }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException("--range requires two addresses: got " + startArgument + ", " + endArgument);
        }
        if (endValue < startValue) {
            throw new IllegalArgumentException("--range end " + endArgument + " is before start " + startArgument);
        }
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startValue);
        Address end = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(endValue);
        AddressSet range = new AddressSet(start, end);

        // Every function whose body overlaps the range, in address order.
        List<Function> intersecting = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(start, true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.getEntryPoint().getOffset() > endValue) {
                break;
            }
            AddressSet body = new AddressSet(function.getBody());
            if (body.intersects(range)) {
                intersecting.add(function);
            }
        }

        int totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        int exported = 0;
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            writer.write("{\n");
            writer.write("  \"schemaVersion\": 2,\n");
            writer.write("  \"rangeMode\": true,\n");
            writer.write("  \"range\": {\"start\": " + json(start.toString()) + ", \"end\": " + json(end.toString()) + "},\n");
            writer.write("  \"program\": {\n");
            writer.write("    \"name\": " + json(currentProgram.getName()) + ",\n");
            writer.write("    \"executableFormat\": " + json(currentProgram.getExecutableFormat()) + ",\n");
            writer.write("    \"language\": " + json(currentProgram.getLanguageID().toString()) + ",\n");
            writer.write("    \"imageBase\": " + json(currentProgram.getImageBase().toString()) + "\n");
            writer.write("  },\n");
            writer.write("  \"scope\": {\"rangeStart\": " + json(startArgument) +
                ", \"rangeEnd\": " + json(endArgument) + ", \"functionCountTotal\": " + totalFunctions + "},\n");
            writer.write("  \"limits\": {\"maxFunctions\": " + maxFunctions +
                ", \"maxDecompiledChars\": " + maxDecompiledChars + "},\n");
            writer.write("  \"functionsIntersecting\": " + intersecting.size() + ",\n");
            writer.write("  \"functions\": [\n");

            for (Function function : intersecting) {
                if (exported >= maxFunctions || monitor.isCancelled()) {
                    break;
                }
                if (exported > 0) {
                    writer.write(",\n");
                }

                String decompiledCode = null;
                boolean decompilationCompleted = false;
                boolean decompilationTruncated = false;
                String decompilationError = null;
                try {
                    // Short per-function budget: a flattened megaprocedure is
                    // allowed to FAIL here fast — the listing fallback below
                    // is the deliverable for those.
                    DecompileResults decompilation = decompiler.decompileFunction(function, 15, monitor);
                    decompilationCompleted = decompilation.decompileCompleted();
                    if (decompilationCompleted && decompilation.getDecompiledFunction() != null) {
                        decompiledCode = decompilation.getDecompiledFunction().getC();
                        if (decompiledCode.length() > maxDecompiledChars) {
                            decompiledCode = decompiledCode.substring(0, maxDecompiledChars);
                            decompilationTruncated = true;
                        }
                    }
                    else {
                        decompilationError = decompilation.getErrorMessage();
                    }
                }
                catch (Exception error) {
                    decompilationError = error.getClass().getSimpleName() + ": " + error.getMessage();
                }

                // The intersection of the function body with the requested
                // range — how much of the megaprocedure this slice covers.
                AddressSet overlap = new AddressSet(function.getBody());
                overlap = (AddressSet) overlap.intersect(range);
                String overlapStart = overlap.isEmpty() ? null : overlap.getMinAddress().toString();
                String overlapEnd = overlap.isEmpty() ? null : overlap.getMaxAddress().toString();
                long overlapBytes = overlap.isEmpty() ? 0 : overlap.getNumAddresses();

                // Disassembly fallback (bounded): always produced when
                // decompilation did not complete, so a timed-out
                // megaprocedure still yields readable structure.
                String listing = null;
                if (!decompilationCompleted) {
                    StringBuilder listingBuilder = new StringBuilder();
                    Address listingStart = overlap.isEmpty() ? function.getEntryPoint() : overlap.getMinAddress();
                    Address listingEnd = overlap.isEmpty() ? function.getEntryPoint() : overlap.getMaxAddress();
                    InstructionIterator instructions = currentProgram.getListing().getInstructions(
                        new AddressSet(listingStart, listingEnd), true);
                    int lines = 0;
                    while (instructions.hasNext() && lines < 400) {
                        Instruction instruction = instructions.next();
                        listingBuilder.append(instruction.getAddress().toString())
                            .append("  ")
                            .append(instruction.toString());
                        for (Address flow : instruction.getFlows()) {
                            Function target = currentProgram.getFunctionManager()
                                .getFunctionAt(flow);
                            if (target != null) {
                                listingBuilder.append("  ; call ").append(target.getName());
                            }
                        }
                        listingBuilder.append('\n');
                        lines++;
                    }
                    listing = listingBuilder.toString();
                    if (listing.length() > maxDecompiledChars) {
                        listing = listing.substring(0, maxDecompiledChars);
                    }
                }

                writer.write("    {\n");
                writer.write("      \"name\": " + json(function.getName()) + ",\n");
                writer.write("      \"entryPoint\": " + json(function.getEntryPoint().toString()) + ",\n");
                writer.write("      \"signature\": " + json(function.getSignature().getPrototypeString()) + ",\n");
                writer.write("      \"isThunk\": " + function.isThunk() + ",\n");
                writer.write("      \"rangeOverlap\": {\"start\": " + json(overlapStart) +
                    ", \"end\": " + json(overlapEnd) + ", \"bytes\": " + overlapBytes + "},\n");
                writeXrefs(writer, function);
                writer.write("      \"decompilationCompleted\": " + decompilationCompleted + ",\n");
                writer.write("      \"decompilationTruncated\": " + decompilationTruncated + ",\n");
                writer.write("      \"decompilationError\": " + json(decompilationError) + ",\n");
                writer.write("      \"decompiledCode\": " + json(decompiledCode) + ",\n");
                writer.write("      \"disassemblyFallback\": " + json(listing) + "\n");
                writer.write("    }");
                exported++;
            }

            writer.write("\n  ],\n");
            writer.write("  \"functionsExported\": " + exported + ",\n");
            writer.write("  \"truncated\": " + (exported < intersecting.size()) + "\n");
            writer.write("}\n");
        }
    }

    private static String joinQuoted(String[] values) {
        List<String> quoted = new ArrayList<>();
        for (String value : values) {
            quoted.add(json(value));
        }
        return String.join(", ", quoted);
    }
}
