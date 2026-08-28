import assert from "node:assert/strict";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { storeArtifact } from "../dist/core/artifacts.js";
import { correlateEvidence } from "../dist/core/correlate.js";
import { Workspace } from "../dist/core/workspace.js";

const SHARED_FILE = "C:\\Users\\analyst\\AppData\\Roaming\\payload, v2.dat";

async function fixtureWorkspace(context) {
  const repository = path.resolve(".");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-corr-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  await copyFile(path.join(repository, "test", "fixtures", "procmon-trace.csv"), path.join(root, "trace.csv"));
  await writeFile(
    path.join(root, "frida-call-events.json"),
    JSON.stringify({
      pid: 5678,
      probeSeconds: 6,
      callLogTruncated: false,
      hookedApis: ["connect", "CreateFileW", "WriteFile", "RegSetValueExW"],
      callEvents: [
        { api: "CreateFileW", atMs: 120, module: "sample.exe", path: SHARED_FILE },
        { api: "WriteFile", atMs: 130, module: "sample.exe", bytes: 1024 },
        { api: "connect", atMs: 200, module: "sample.exe", sockaddr: "ipv4 93.184.216.34:80" },
        { api: "RegSetValueExW", atMs: 300, module: "sample.exe", value: "payload", type: 1, data: "C:\\Temp\\evil.exe" },
      ],
    }),
  );
  await mkdir(path.join(root, "dump", "module_a"), { recursive: true });
  await writeFile(path.join(root, "dump", "module_a", "implanted.exe"), "IMPLANTED-PE-PLACEHOLDER");
  await writeFile(path.join(root, "dump", "replaced.dll"), "REPLACED-PE-PLACEHOLDER");
  return await Workspace.create(root);
}

test("report.correlate cross-references procmon, frida, dumps, and transcripts", async (context) => {
  const workspace = await fixtureWorkspace(context);
  const transcript = await storeArtifact(workspace, JSON.stringify({
    sessionId: "abc123",
    target: "sample.exe",
    transcript: [
      { command: "<create>", output: "", seconds: 0 },
      { command: "break decode", output: "Breakpoint 1", seconds: 0.1 },
      { command: "x/16xb $rsp", output: "0x...", seconds: 0.1 },
    ],
  }), { mediaType: "application/json", sourceOperation: "debug.session.close", description: "test transcript" });

  const report = await correlateEvidence(workspace, {
    procmonPath: "trace.csv",
    fridaLogPath: "frida-call-events.json",
    dumpDirPath: "dump",
    transcriptArtifactId: transcript.id,
  });

  assert.equal(report.schema, 2);
  assert.equal(report.sources.procmon.eventCount, 8);
  assert.ok(report.sources.procmon.processes.includes("malware, sample.exe"));
  assert.equal(report.sources.frida.callEventCount, 4);
  assert.equal(report.sources.dumps.fileCount, 2);
  assert.equal(report.sources.transcript.commandsTotal, 2);

  const endpoint = report.networkEndpoints.find((entry) => entry.endpoint === "93.184.216.34:80");
  assert.ok(endpoint, "the shared C2 endpoint must appear");
  assert.equal(endpoint.procmonEvents, 2, "TCP Connect + TCP Send");
  assert.equal(endpoint.fridaConnects, 1);
  assert.equal(endpoint.crossReferenced, true);

  const sharedFile = report.fileActivity.find((entry) => entry.path === SHARED_FILE);
  assert.ok(sharedFile, "the dropped payload path must appear");
  assert.deepEqual(sharedFile.procmonOperations, ["CreateFile", "WriteFile"]);
  assert.deepEqual(sharedFile.fridaApis, ["CreateFileW"]);
  assert.equal(sharedFile.crossReferenced, true);

  const procmonPersistence = report.persistence.filter((entry) => entry.source === "procmon");
  assert.equal(procmonPersistence.length, 1);
  assert.match(procmonPersistence[0].detail, /CurrentVersion\\Run/);
  assert.ok(report.persistence.some((entry) => entry.source === "frida" && entry.detail.includes("payload")));

  assert.deepEqual(report.dumps.map((entry) => entry.file).sort(), ["module_a/implanted.exe", "replaced.dll"]);
  assert.deepEqual(report.transcriptCommands, ["break decode", "x/16xb $rsp"]);
});

test("report.correlate cross-references static sample anchors against dynamic observations", async (context) => {
  const workspace = await fixtureWorkspace(context);

  // A fake sample carrying the same C2 URL the dynamic sources observed.
  await writeFile(
    path.join(workspace.root, "sample.bin"),
    Buffer.concat([
      Buffer.from("strings: https://c2.example/ping and 93.184.216.34 more text\n"),
      Buffer.from("CreateFileW WriteFile RegSetValueExW references\n"),
    ]),
  );

  const report = await correlateEvidence(workspace, {
    fridaLogPath: "frida-call-events.json",
    samplePath: "sample.bin",
  });

  assert.equal(report.schema, 2);
  assert.ok(report.sources.staticAnchor, "the static anchor source is recorded");
  assert.equal(report.sources.staticAnchor.path, "sample.bin");
  assert.match(report.sources.staticAnchor.sha256, /^[0-9a-f]{64}$/);

  // The endpoint observed by frida confirms the static IP IOC.
  const confirmed = report.staticDynamic.confirmedIocs;
  assert.ok(confirmed.some((entry) => entry.value === "93.184.216.34" && entry.kind === "ips"), JSON.stringify(confirmed));
  // Import cross-referencing needs PE tables; the text fixture has none —
  // the API-name plane only reports for real PEs (covered by triage tests).
  assert.deepEqual(report.staticDynamic.importedApisSeenAtRuntime, []);
  // A URL nobody observed stays unconfirmed.
  assert.equal(report.staticDynamic.unconfirmedIocCount >= 1, true, "the unobserved URL IOC is counted");

  // Sample-only correlate is valid (static report, no dynamic confirmation).
  const staticOnly = await correlateEvidence(workspace, { samplePath: "sample.bin" });
  assert.equal(staticOnly.staticDynamic.confirmedIocs.length, 0, "nothing is confirmed without a dynamic source");
});

test("report.correlate works with a single source and rejects empty requests", async (context) => {
  const workspace = await fixtureWorkspace(context);

  await assert.rejects(() => correlateEvidence(workspace, {}), /at least one source/);

  const fridaOnly = await correlateEvidence(workspace, { fridaLogPath: "frida-call-events.json" });
  assert.equal(fridaOnly.sources.frida.callEventCount, 4);
  assert.equal(fridaOnly.networkEndpoints.length, 1);
  assert.equal(fridaOnly.networkEndpoints[0].crossReferenced, false, "a single source cannot cross-reference");
  assert.equal(fridaOnly.fileActivity.length, 1);
  assert.equal(fridaOnly.dumps.length, 0);

  await assert.rejects(
    () => correlateEvidence(workspace, { transcriptArtifactId: "sha256:" + "0".repeat(64) }),
    /is not readable in this workspace/,
  );
});
