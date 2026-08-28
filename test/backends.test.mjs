import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_IMAGES, resolveDockerImage } from "../dist/core/backends.js";

test("resolveDockerImage falls back to the pinned default when unset", () => {
  assert.equal(resolveDockerImage(undefined, DEFAULT_IMAGES.die), DEFAULT_IMAGES.die);
});

test("resolveDockerImage treats an explicit empty value as disabled", () => {
  assert.equal(resolveDockerImage("", DEFAULT_IMAGES.die), null);
  assert.equal(resolveDockerImage("   ", DEFAULT_IMAGES.die), null);
});

test("resolveDockerImage keeps explicit overrides verbatim", () => {
  assert.equal(
    resolveDockerImage("registry.example/die:dev", DEFAULT_IMAGES.die),
    "registry.example/die:dev",
  );
});

test("DEFAULT_IMAGES pins every containerized provider to repo:tag", () => {
  const keys = ["capa", "yaraX", "floss", "die", "radare2", "binwalk", "ghidra"];
  for (const key of keys) {
    assert.match(DEFAULT_IMAGES[key], /^[a-z0-9._/-]+:[A-Za-z0-9._-]+$/, `${key} is pinned`);
  }
});
