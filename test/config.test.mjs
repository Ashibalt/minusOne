import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { configPath, readWorkspaceConfig, writeWorkspaceConfig } from "../dist/core/config.js";
import { resolveDynamicTarget } from "../dist/core/dynamic.js";
import { Workspace } from "../dist/core/workspace.js";

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

async function freshWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-config-"));
  return { root, workspace: await Workspace.create(root) };
}

test("writeWorkspaceConfig persists .minusone/config.json and round-trips", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rm(root, { recursive: true, force: true }));

  const config = await writeWorkspaceConfig(workspace, "local");
  assert.equal(config.dynamic, "local");
  assert.ok(config.updatedAt > 0);

  const raw = JSON.parse(await readFile(configPath(workspace), "utf8"));
  assert.equal(raw.dynamic, "local");
  assert.equal(raw.version, 1);

  const reread = await readWorkspaceConfig(workspace);
  assert.equal(reread.dynamic, "local");

  await writeWorkspaceConfig(workspace, "none");
  assert.equal((await readWorkspaceConfig(workspace)).dynamic, "none");
});

test("readWorkspaceConfig defaults to none when the file is missing or corrupt", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rm(root, { recursive: true, force: true }));

  assert.equal((await readWorkspaceConfig(workspace)).dynamic, "none");

  const file = configPath(workspace);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, "{not json", "utf8");
  assert.equal((await readWorkspaceConfig(workspace)).dynamic, "none");
});

test("resolveDynamicTarget precedence: env overrides config, config overrides default none", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rm(root, { recursive: true, force: true }));

  // No config, no env → none.
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    assert.equal(await resolveDynamicTarget(workspace), "none");
  });

  // Armed config, no env → local.
  await writeWorkspaceConfig(workspace, "local");
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    assert.equal(await resolveDynamicTarget(workspace), "local");
  });

  // Armed config but env disables → none (env wins).
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: "0", MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    assert.equal(await resolveDynamicTarget(workspace), "none");
  });

  // Armed config, env armed without a target → armed-no-target (env wins).
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: "1", MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    assert.equal(await resolveDynamicTarget(workspace), "armed-no-target");
  });

  // No workspace, no env → none.
  await withEnv({ MINUSONE_ALLOW_DYNAMIC: undefined, MINUSONE_DYNAMIC_TARGET: undefined }, async () => {
    assert.equal(await resolveDynamicTarget(), "none");
  });
});

test("resolveWritablePath creates the tree and is contained; resolveWritableDir creates a directory", async (context) => {
  const { root, workspace } = await freshWorkspace();
  context.after(() => rm(root, { recursive: true, force: true }));

  const target = await workspace.resolveWritablePath("exports/nested/out.bin");
  assert.ok(target.endsWith(path.join("exports", "nested", "out.bin")));
  const dirStat = await stat(path.dirname(target));
  assert.ok(dirStat.isDirectory(), "parent tree was created");

  const dir = await workspace.resolveWritableDir("exports/dir");
  const dirStat2 = await stat(dir);
  assert.ok(dirStat2.isDirectory());

  await assert.rejects(() => workspace.resolveWritablePath("../escape.bin"), /escapes the workspace/);
  await assert.rejects(() => workspace.resolveWritableDir("../escape"), /escapes the workspace/);
});
