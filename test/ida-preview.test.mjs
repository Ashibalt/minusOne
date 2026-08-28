// R3-3: the IDA pseudocode preview must skip the leading Hex-Rays
// declaration block — a naive slice(0, 4000) showed ONLY declarations on
// any typical main(), hiding every actual statement behind artifact_read.

import assert from "node:assert/strict";
import test from "node:test";
import { idaPreviewSlice } from "../dist/core/operations.js";

function typicalMain() {
  // The shape Hex-Rays emits: long declaration block, then statements.
  const declarations = [
    "__int64 main(int argc, const char **argv, const char **envp) {",
    "  // rax : __int64",
    "  // rbx : __int64",
    "  // rcx : __int64",
    "  // rdx : __int64",
    "  // rsi : const char **",
    "  // rdi : int",
    "  // [rsp+0h] [rbp-58h] : __int64",
    "  // [rsp+8h] [rbp-50h] : __int64",
    "  // [rsp+10h] [rbp-48h] : char[24]",
    "  // [rsp+28h] [rbp-30h] : __int64",
    "  // [rsp+30h] [rbp-28h] : __int64",
    "  // [rsp+38h] [rbp-20h] : char[8]",
    "  // [rsp+40h] [rbp-18h] : __int64",
    "  // [rsp+48h] [rbp-10h] : __int64",
  ].join("\n");
  const statements = [
    "",
    "  puts(\"hi\");",
    "  return 0LL;",
    "}",
  ].join("\n");
  return { declarations, statements, full: `${declarations}\n${statements}` };
}

test("idaPreviewSlice: short pseudocode passes through untouched", () => {
  const short = "__int64 f() {\n  return 1LL;\n}";
  assert.equal(idaPreviewSlice(short), short);
});

test("idaPreviewSlice: the declaration block is skipped, statements survive", () => {
  const { declarations, statements, full } = typicalMain();
  const padded = full + "  // " + "x".repeat(5000); // force past the 4000 budget
  const preview = idaPreviewSlice(padded);
  assert.ok(!preview.includes("// rax :"), "register declarations are skipped");
  assert.ok(!preview.includes(declarations.split("\n")[1]), "no declaration lines in the preview");
  assert.ok(preview.includes("puts(\"hi\");"), "actual statements are visible");
  assert.ok(preview.length <= 4000, "preview respects the budget");
});

test("idaPreviewSlice: pseudocode without a declaration block still previews from the top", () => {
  const body = "int f(int x) {\n  return x + 1;\n" + Array.from({ length: 500 }, (_, i) => `  // trailing note ${i}`).join("\n") + "\n}";
  const preview = idaPreviewSlice(body);
  // The signature+statement head is skipped only when a declaration run
  // follows; here line 2 is CODE, so the skip stops right after the
  // signature and the statements lead the preview.
  assert.ok(preview.includes("return x + 1;"), "statements are visible");
  assert.ok(preview.length <= 4000, "preview respects the budget");
});

test("idaPreviewSlice: a code statement right after the signature stops the skip", () => {
  const src = [
    "void f() {",
    "  do_thing();",
    ...Array.from({ length: 400 }, (_, i) => `  // padding line ${i} : __int64`),
    "}",
  ].join("\n");
  const preview = idaPreviewSlice(src);
  assert.ok(preview.includes("do_thing();"), "the first statement survives even when declarations come later");
});
