import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { trustRoot, untrustRoot, readWorkspaceConfig } from "../dist/core/config.js";
import { Workspace } from "../dist/core/workspace.js";
import { inspectBinary } from "../dist/core/binary.js";
import { rmRoot } from "./helpers.mjs";

function withEnv(overrides, body) {
  const saved = Object.fromEntries(Object.keys(overrides).map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve(body()).finally(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

test("trusted roots: resolveFile accepts external samples, writes still refuse", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-trust-"));
  const workspaceRoot = path.join(parent, "ws");
  const samplesRoot = path.join(parent, "samples");
  await mkdir(workspaceRoot, { recursive: true });
  await mkdir(path.join(samplesRoot, "sub"), { recursive: true });
  await writeFile(path.join(samplesRoot, "sub", "zed.exe"), Buffer.from("MZ fake binary", "ascii"));
  context.after(() => rmRoot(parent));

  // No trusted roots: external sample refuses (the report.txt complaint).
  await withEnv({ MINUSONE_TRUSTED_ROOTS: undefined }, async () => {
    const bare = await Workspace.create(workspaceRoot);
    assert.equal(bare.trustedRoots.length, 0);
    await assert.rejects(
      () => bare.resolveFile(path.join(samplesRoot, "sub", "zed.exe")),
      /escapes the workspace/,
    );
  });

  // Env-var root: reads work, absolute or workspace-relative-syntax paths.
  await withEnv({ MINUSONE_TRUSTED_ROOTS: samplesRoot }, async () => {
    const workspace = await Workspace.create(workspaceRoot);
    assert.equal(workspace.trustedRoots.length, 1);
    const resolved = await workspace.resolveFile(path.join(samplesRoot, "sub", "zed.exe"));
    assert.ok(resolved.endsWith("zed.exe"));
    // inspectBinary runs over the external sample (the full static plane).
    const binary = await inspectBinary(workspace, path.join(samplesRoot, "sub", "zed.exe"));
    assert.ok(binary.sha256.length === 64);

    // Write asymmetry: resolveWritablePath NEVER accepts trusted-root targets.
    await assert.rejects(
      () => workspace.resolveWritablePath(path.join(samplesRoot, "sub", "evil.txt")),
      /escapes the workspace/,
    );
    await assert.rejects(
      () => workspace.resolveWritableDir(path.join(samplesRoot, "sub", "evil-dir")),
      /escapes the workspace/,
    );

    // Escaping the trusted root itself still refuses.
    await assert.rejects(
      () => workspace.resolveFile(path.join(parent, "outside.bin")),
      /escapes the workspace/,
    );
  });
});

test("minusone trust persists to config.json and untrust removes it", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-trust2-"));
  const workspaceRoot = path.join(parent, "ws");
  const samplesRoot = path.join(parent, "samples");
  await mkdir(workspaceRoot);
  await mkdir(samplesRoot);
  context.after(() => rmRoot(parent));

  const workspace = await Workspace.create(workspaceRoot);
  const trusted = await trustRoot(workspace, samplesRoot);
  assert.equal(trusted.trustedRoots.length, 1);
  assert.equal(trusted.trustedRoots[0], await (await import("node:fs/promises")).realpath(samplesRoot));
  // Dynamic mode survives the trust edit (writeConfig merges, not replaces).
  assert.equal(trusted.dynamic, "none");

  // Round-trip through a fresh Workspace: the trusted root is live.
  await writeFile(path.join(samplesRoot, "sample.dll"), Buffer.from("MZ dll", "ascii"));
  const fresh = await Workspace.create(workspaceRoot);
  assert.equal(fresh.trustedRoots.length, 1);
  await fresh.resolveFile(path.join(samplesRoot, "sample.dll"));

  // Untrust: reads refuse again.
  const after = await untrustRoot(workspace, samplesRoot);
  assert.equal(after.trustedRoots.length, 0);
  const reFresh = await Workspace.create(workspaceRoot);
  assert.equal(reFresh.trustedRoots.length, 0);
  await assert.rejects(
    () => reFresh.resolveFile(path.join(samplesRoot, "sample.dll")),
    /escapes the workspace/,
  );

  // Config file shape is stable JSON with trustedRoots persisted.
  const raw = JSON.parse(await readFile(path.join(workspaceRoot, ".minusone", "config.json"), "utf8"));
  assert.ok(Array.isArray(raw.trustedRoots));
  assert.equal(raw.version, 1);
});

test("readWorkspaceConfig tolerates junk trustedRoots entries", async (context) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), "minusone-trust3-"));
  const workspaceRoot = path.join(parent, "ws");
  await mkdir(path.join(workspaceRoot, ".minusone"), { recursive: true });
  await writeFile(
    path.join(workspaceRoot, ".minusone", "config.json"),
    JSON.stringify({ version: 1, dynamic: "none", trustedRoots: [42, "", "C:\\\\definitely-not-here", "C:\\\\also-missing"] }),
    "utf8",
  );
  context.after(() => rmRoot(parent));

  const workspace = await Workspace.create(workspaceRoot);
  // Non-existent roots are skipped silently (they may appear later; the
  // config keeps them); the junk (non-string/empty) entries are filtered.
  assert.equal(workspace.trustedRoots.length, 0);
  const config = await readWorkspaceConfig(workspace);
  // Junk dropped, not-yet-existing paths preserved in the config.
  assert.deepEqual(config.trustedRoots, ["C:\\\\definitely-not-here", "C:\\\\also-missing"]);
});
