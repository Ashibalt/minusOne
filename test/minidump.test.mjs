import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { operations } from "../dist/core/operations.js";
import { inspectMinidump } from "../dist/core/minidump.js";
import { Workspace } from "../dist/core/workspace.js";

/** Hand-built minimal but structurally valid x64 minidump. */
function buildSyntheticDump() {
  const buffer = Buffer.alloc(1024);
  buffer.write("MDMP", 0, "ascii");
  buffer.writeUInt32LE(0xa793, 4); // version
  buffer.writeUInt32LE(5, 8); // numberOfStreams
  buffer.writeUInt32LE(32, 12); // directoryRva
  buffer.writeUInt32LE(0, 16); // checksum
  buffer.writeUInt32LE(1770000000, 20); // timestamp

  // Stream directory: [type, size, rva] x 5 at offset 32 (60 bytes).
  const SYS = 96, MOD = 128, THR = 512, EXC = 600, M64 = 800;
  const entries = [
    [7, 32, SYS],
    [4, 4 + 2 * 108, MOD],
    [3, 4 + 1 * 48, THR],
    [6, 160, EXC],
    [9, 16 + 2 * 16, M64],
  ];
  entries.forEach(([type, size, rva], index) => {
    const at = 32 + index * 12;
    buffer.writeUInt32LE(type, at);
    buffer.writeUInt32LE(size, at + 4);
    buffer.writeUInt32LE(rva, at + 8);
  });

  // SystemInfo: arch x64 (9), major 10, minor 0, build 19045.
  buffer.writeUInt16LE(9, SYS);
  buffer.writeUInt32LE(10, SYS + 8);
  buffer.writeUInt32LE(0, SYS + 12);
  buffer.writeUInt32LE(19045, SYS + 16);

  // Module names (MINIDUMP_STRING: u32 byte length + UTF-16LE).
  const name1 = 380, name2 = 460;
  const writeString = (rva, text) => {
    buffer.writeUInt32LE(text.length * 2, rva);
    buffer.write(text, rva + 4, "utf16le");
  };
  writeString(name1, "C:\\Windows\\System32\\kernel32.dll");
  writeString(name2, "C:\\App\\target.exe");

  // ModuleList: two 108-byte entries after the count.
  buffer.writeUInt32LE(2, MOD);
  const module1 = MOD + 4;
  buffer.writeBigUInt64LE(0x7ff800000000n, module1);
  buffer.writeUInt32LE(0x71000, module1 + 8);
  buffer.writeUInt32LE(0xdeadbeef, module1 + 12);
  buffer.writeUInt32LE(1700000000, module1 + 16);
  buffer.writeUInt32LE(name1, module1 + 20);
  buffer.writeUInt32LE(0xfeef04bd, module1 + 24);
  buffer.writeUInt32LE(10 << 16 | 0, module1 + 24 + 16); // fileVersionMS 10.0
  buffer.writeUInt32LE(19041 << 16 | 1234, module1 + 24 + 20); // LS 19041.1234
  const module2 = module1 + 108;
  buffer.writeBigUInt64LE(0x140000000n, module2);
  buffer.writeUInt32LE(0x21000, module2 + 8);
  buffer.writeUInt32LE(0, module2 + 12);
  buffer.writeUInt32LE(0, module2 + 16);
  buffer.writeUInt32LE(name2, module2 + 20);

  // ThreadList: one thread (48 bytes).
  buffer.writeUInt32LE(1, THR);
  buffer.writeUInt32LE(4242, THR + 4); // thread id
  buffer.writeBigUInt64LE(0x7ffdc0000000n, THR + 4 + 16); // teb
  buffer.writeBigUInt64LE(0x7ffd00001000n, THR + 4 + 24); // stack start
  buffer.writeUInt32LE(0x8000, THR + 4 + 32); // stack size

  // Exception: threadId + align + MINIDUMP_EXCEPTION (152) + context locator.
  buffer.writeUInt32LE(4242, EXC);
  buffer.writeUInt32LE(0xc0000005, EXC + 8); // access violation
  buffer.writeBigUInt64LE(0x140001234n, EXC + 8 + 16); // exception address
  buffer.writeUInt32LE(2, EXC + 8 + 24); // number of parameters
  buffer.writeBigUInt64LE(0n, EXC + 8 + 40 + 0 * 8); // read access
  buffer.writeBigUInt64LE(0xdead0000n, EXC + 8 + 40 + 1 * 8);

  // Memory64List: two ranges.
  buffer.writeBigUInt64LE(2n, M64);
  buffer.writeBigUInt64LE(900n, M64 + 8);
  buffer.writeBigUInt64LE(0x140000000n, M64 + 16);
  buffer.writeBigUInt64LE(0x21000n, M64 + 24);
  buffer.writeBigUInt64LE(0x7ffd00001000n, M64 + 32);
  buffer.writeBigUInt64LE(0x8000n, M64 + 40);

  return buffer;
}

async function dumpWorkspace() {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-dmp-"));
  await writeFile(path.join(root, "capture.dmp"), buildSyntheticDump());
  await writeFile(path.join(root, "not-a-dump.bin"), "mz-not-a-minidump");
  return { root, workspace: await Workspace.create(root) };
}

test("minidump parser reads streams, modules, threads, exception, and memory bounds", async (context) => {
  const fixture = await dumpWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  const report = await inspectMinidump(fixture.workspace, "capture.dmp");
  assert.equal(report.dumpKind, "minidump");
  assert.equal(report.architecture, "x86_64");
  assert.deepEqual(report.os, { major: 10, minor: 0, build: 19045 });
  assert.equal(report.moduleCountTotal, 2);
  assert.equal(report.modules[0].name, "C:\\Windows\\System32\\kernel32.dll");
  assert.equal(report.modules[0].base, "0x7ff800000000");
  assert.equal(report.modules[0].version, "10.0.19041.1234");
  assert.equal(report.modules[1].name, "C:\\App\\target.exe");
  assert.equal(report.modules[1].version, null, "no VS_FIXEDFILEINFO signature -> no version");
  assert.equal(report.threadCountTotal, 1);
  assert.equal(report.threads[0].id, 4242);
  assert.equal(report.threads[0].teb, "0x7ffdc0000000");
  assert.equal(report.memory.regionCount, 2);
  assert.equal(report.memory.totalBytes, 0x21000 + 0x8000);
  assert.equal(report.memory.largest.size, 0x21000);
  assert.equal(report.exception.code, "0xc0000005");
  assert.equal(report.exception.address, "0x140001234");
  assert.equal(report.exception.parameters.length, 2);
  assert.equal(report.truncated, false);
  assert.ok(report.streams.length >= 5);

  await assert.rejects(
    () => inspectMinidump(fixture.workspace, "not-a-dump.bin"),
    /not a minidump/,
  );
});

test("dump.inspect operation filters modules and stays wire-safe", async (context) => {
  const operation = operations.find((entry) => entry.id === "dump.inspect");
  assert.ok(operation, "dump.inspect operation exists");
  assert.equal(operation.toolName, "dump_inspect");
  const fixture = await dumpWorkspace();
  context.after(() => rm(fixture.root, { recursive: true, force: true }));

  const result = await operation.execute(
    { path: "capture.dmp", moduleFilter: "kernel32" },
    { workspace: fixture.workspace },
  );
  assert.equal(result.architecture, "x86_64");
  assert.equal(result.modules.length, 1);
  assert.match(result.modules[0].name, /kernel32\.dll/);
  assert.equal(result.truncated, true, "module filter narrowed the list");
  assert.equal(result.exception.code, "0xc0000005");

  const all = await operation.execute({ path: "capture.dmp" }, { workspace: fixture.workspace });
  assert.equal(all.modules.length, 2);
  assert.equal(all.truncated, false);
});
