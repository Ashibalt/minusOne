import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ArtifactError,
  getArtifactMetadata,
  listArtifacts,
  parseArtifactId,
  readArtifact,
  storeArtifact,
} from "../dist/core/artifacts.js";
import { operations } from "../dist/core/operations.js";
import { rmRoot } from "./helpers.mjs";
import { Workspace } from "../dist/core/workspace.js";

async function artifactWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-artifacts-"));
  return { root, workspace: await Workspace.create(root) };
}

test("stores artifacts content-addressed and lists them", async (context) => {
  const fixture = await artifactWorkspace();
  context.after(() => rmRoot(fixture.root));

  const first = await storeArtifact(fixture.workspace, '{"report": 1}', {
    mediaType: "application/json",
    sourceOperation: "test",
    description: "first",
  });
  const second = await storeArtifact(fixture.workspace, '{"report": 1}', {
    mediaType: "application/json",
    sourceOperation: "test",
    description: "same content, same hash",
  });

  assert.equal(first.id, second.id, "identical content deduplicates to one id");
  assert.match(first.id, /^sha256:[a-f0-9]{64}$/);
  assert.equal(first.bytes, 13);

  const listed = await listArtifacts(fixture.workspace);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].sourceOperation, "test");

  const metadata = await getArtifactMetadata(fixture.workspace, first.id);
  assert.equal(metadata.sha256, parseArtifactId(first.id));
});

test("reads artifacts through bounded offset/limit windows", async (context) => {
  const fixture = await artifactWorkspace();
  context.after(() => rmRoot(fixture.root));

  const payload = "0123456789".repeat(100); // 1000 bytes
  const stored = await storeArtifact(fixture.workspace, payload, {
    mediaType: "text/plain",
    sourceOperation: "test",
    description: "paging probe",
  });

  const first = await readArtifact(fixture.workspace, stored.id, { offset: 0, limit: 400 });
  assert.equal(first.length, 400);
  assert.equal(first.truncated, true);
  assert.equal(first.nextOffset, 400);
  assert.equal(first.content, payload.slice(0, 400));

  const second = await readArtifact(fixture.workspace, stored.id, { offset: 400, limit: 400 });
  assert.equal(second.nextOffset, 800);
  assert.equal(second.content, payload.slice(400, 800));

  const tail = await readArtifact(fixture.workspace, stored.id, { offset: 800, limit: 400 });
  assert.equal(tail.truncated, false);
  assert.equal(tail.nextOffset, null);
  assert.equal(tail.content, payload.slice(800));

  const pastEnd = await readArtifact(fixture.workspace, stored.id, { offset: 5000 });
  assert.equal(pastEnd.length, 0);
  assert.equal(pastEnd.content, "");
});

test("rejects malformed and unknown artifact ids", async (context) => {
  const fixture = await artifactWorkspace();
  context.after(() => rmRoot(fixture.root));

  assert.throws(() => parseArtifactId("not-an-id"), ArtifactError);
  assert.throws(() => parseArtifactId("sha256:zzzz"), ArtifactError);
  await assert.rejects(
    () => readArtifact(fixture.workspace, "sha256:" + "a".repeat(64)),
    ArtifactError,
  );
});

test("cache keys resolve to stored artifacts only on exact match", async (context) => {
  const fixture = await artifactWorkspace();
  context.after(() => rmRoot(fixture.root));

  const { cacheKeyDigest, findArtifactByCacheKey } = await import("../dist/core/artifacts.js");
  const key = cacheKeyDigest({ sample: "abc", options: { maxFunctions: 40 } });
  const other = cacheKeyDigest({ sample: "abc", options: { maxFunctions: 41 } });

  assert.equal(await findArtifactByCacheKey(fixture.workspace, key), null, "no artifact before the first store");
  const stored = await storeArtifact(fixture.workspace, '{"cached": true}', {
    mediaType: "application/json",
    sourceOperation: "function.decompile",
    description: "cache probe",
    cacheKey: key,
  });
  const hit = await findArtifactByCacheKey(fixture.workspace, key);
  assert.ok(hit, "exact key hits");
  assert.equal(hit.id, stored.id);
  assert.equal(await findArtifactByCacheKey(fixture.workspace, other), null, "different options miss");
});

test("dynamic plane operations refuse with structured policy output", async (context) => {
  const { operations } = await import("../dist/core/operations.js");
  // Use a fresh temp dir as the workspace root so the refusal comes from the
  // default unarmed policy, not an armed host .minusone/config.json.
  const unarmedRoot = await mkdtemp(path.join(os.tmpdir(), "minusone-refuse-"));
  context.after(() => rmRoot(unarmedRoot));
  const previous = process.env.MINUSONE_ALLOW_DYNAMIC;
  delete process.env.MINUSONE_ALLOW_DYNAMIC;
  try {
    for (const id of ["debug.session.create", "debug.command", "debug.session.close"]) {
      const operation = operations.find((entry) => entry.id === id);
      assert.ok(operation, `${id} registered`);
      const refusal = await operation.execute(
        id === "debug.session.create" ? { path: "sample.exe" } : { sessionId: "s1", command: "r" },
        { workspace: { root: unarmedRoot } },
      );
      assert.equal(refusal.status, "refused");
      assert.ok(refusal.reason.includes("policy"));
      assert.ok(refusal.requirements.length >= 2);
    }
  } finally {
    if (previous !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = previous;
  }
});

test("artifact.export materializes content as a real workspace file", async (context) => {
  const { root, workspace } = await artifactWorkspace();
  context.after(() => rmRoot(root));
  const stored = await storeArtifact(workspace, "export-payload-body", {
    mediaType: "application/json",
    sourceOperation: "test.export",
    description: "export probe",
  });

  const operation = operations.find((entry) => entry.id === "artifact.export");
  assert.ok(operation, "artifact.export operation exists");
  assert.equal(operation.toolName, "artifact_export");

  const result = await operation.execute({ id: stored.id, path: "exports/nested/out.json" }, { workspace });
  assert.equal(result.artifactId, stored.id);
  assert.equal(result.bytes, "export-payload-body".length);
  assert.equal(result.sha256, stored.sha256);
  assert.match(result.exportedPath, /exports[\\/]nested[\\/]out\.json/);

  const exported = await readFile(path.join(workspace.root, "exports", "nested", "out.json"), "utf8");
  assert.equal(exported, "export-payload-body");

  // The CAS artifact is unchanged.
  const meta = await getArtifactMetadata(workspace, stored.id);
  assert.equal(meta.bytes, stored.bytes);
});
