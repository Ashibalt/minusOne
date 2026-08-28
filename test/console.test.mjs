/**
 * console.* plane tests: detached launch, WriteConsoleInputW send with
 * readBack, screen read, key markers, validation errors, process.kill.
 * Live tests need gcc + a real Windows console — they self-skip otherwise.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CONSOLE_MAX_TEXT_CHARS,
  consoleDriverScript,
  readConsoleScreen,
  sendConsoleInput,
} from "../dist/core/console.js";
import { killProcessTree, launchDetachedSample } from "../dist/core/dynamic.js";
import { operations } from "../dist/core/operations.js";
import { Workspace } from "../dist/core/workspace.js";
import { rmRoot } from "./helpers.mjs";

function compileFixture(source, target) {
  try {
    execFileSync("gcc", ["-O0", "-o", target, source]);
    return true;
  } catch {
    return false;
  }
}

function armEnv(context) {
  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  process.env.MINUSONE_ALLOW_DYNAMIC = "1";
  process.env.MINUSONE_DYNAMIC_TARGET = "local";
  context.after(() => {
    if (previousAllow === undefined) delete process.env.MINUSONE_ALLOW_DYNAMIC;
    else process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget === undefined) delete process.env.MINUSONE_DYNAMIC_TARGET;
    else process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

test("console driver script embeds the field lessons", () => {
  const script = consoleDriverScript();
  assert.match(script, /FreeConsole/, "FreeConsole before AttachConsole — the silent-false trap");
  assert.match(script, /AttachConsole/);
  assert.match(script, /WriteConsoleInputW/);
  assert.match(script, /ReadConsoleOutputCharacterW/);
  assert.match(script, /CONIN\$/, "input goes through CONIN$ (GetStdHandle is stale after AttachConsole)");
  assert.match(script, /CONOUT\$/, "screen reads go through CONOUT$");
});

test("sendConsoleInput validates pid and text length before touching the OS", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-console-"));
  const workspace = await Workspace.create(root);
  await assert.rejects(
    () => sendConsoleInput(workspace, 0, "hi"),
    /invalid pid/,
  );
  await assert.rejects(
    () => sendConsoleInput(workspace, -5, "hi"),
    /invalid pid/,
  );
  await assert.rejects(
    () => sendConsoleInput(workspace, 999999, "x".repeat(CONSOLE_MAX_TEXT_CHARS + 1)),
    new RegExp(String(CONSOLE_MAX_TEXT_CHARS)),
    "the cap is enforced client-side with a helpful message",
  );
  await assert.rejects(
    () => readConsoleScreen(workspace, 0),
    /invalid pid/,
  );
});

test("console.send on a dead pid reports a structured error, not a crash", async (context) => {
  if (process.platform !== "win32") context.skip("Windows-only");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-console-"));
  context.after(() => rmRoot(root));
  const workspace = await Workspace.create(root);
  // 4194304 is inside the valid pid range but nothing listens there.
  const result = await sendConsoleInput(workspace, 4194304, "x");
  assert.equal(result.attached, false);
  assert.ok(result.error, "attach failure is reported");
  assert.match(result.error, /AttachConsole|failed/i);
});

test("console.launch/send/read round-trip drives a real menu TUI", { timeout: 180_000 }, async (context) => {
  if (process.platform !== "win32") context.skip("Windows-only");
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-tui-"));
  context.after(() => rmRoot(root));
  const binary = path.join(root, "menu-tui.exe");
  if (!compileFixture(path.resolve(".", "test", "fixtures", "menu-tui.c"), binary)) {
    context.skip("needs gcc");
  }
  armEnv(context);
  const workspace = await Workspace.create(root);

  // console.launch operation: detached, hidden console, PID handed back.
  const launchOp = operations.find((entry) => entry.id === "console.launch");
  assert.ok(launchOp, "console.launch operation exists");
  const launched = await launchOp.execute({ path: "menu-tui.exe" }, { workspace });
  assert.equal(launched.status, "launched");
  assert.ok(Number.isInteger(launched.pid) && launched.pid > 0);
  context.after(async () => {
    try { await killProcessTree(launched.pid); } catch {}
  });

  // Give the TUI a moment to draw its first frame.
  await sleep(700);

  const sendOp = operations.find((entry) => entry.id === "console.send");
  assert.ok(sendOp, "console.send operation exists");
  const readOp = operations.find((entry) => entry.id === "console.read");
  assert.ok(readOp, "console.read operation exists");

  // Plain read: the initial menu frame is on the screen buffer.
  const initial = await readOp.execute({ pid: launched.pid }, { workspace });
  assert.equal(initial.status, "ok", initial.error ?? "");
  assert.equal(initial.attached, true);
  assert.match(initial.screen.text, /MINUSONE MENU TUI/);
  assert.match(initial.screen.text, /Run check/);
  assert.ok(initial.screen.width > 0 && initial.screen.height > 0);

  // Type "1" to open the name prompt, then the name + Enter.
  const opened = await sendOp.execute({ pid: launched.pid, text: "1", settleMs: 300 }, { workspace });
  assert.equal(opened.status, "ok", opened.error ?? "");
  const typed = await sendOp.execute(
    { pid: launched.pid, text: "analyst\n", settleMs: 300 },
    { workspace },
  );
  assert.equal(typed.status, "ok", typed.error ?? "");
  assert.equal(typed.keysSent > 0, true);

  // The menu now shows the entered name.
  const withName = await readOp.execute({ pid: launched.pid }, { workspace });
  assert.equal(withName.status, "ok");
  assert.match(withName.screen.text, /analyst/);

  // VK probe: {UP} read through the RAW INPUT_RECORD plane (what
  // ratatui/crossterm reads) must carry the real virtual-key code —
  // the combat failure mode was TUIs ignoring synthetic keys with vk=0.
  // Two separate sends: the CRT _getch buffers console events, so a key
  // sent in the same call as 'v' is consumed before the raw read.
  const vkArmed = await sendOp.execute({ pid: launched.pid, text: "v", settleMs: 400 }, { workspace });
  assert.equal(vkArmed.status, "ok");
  const vkProbe = await sendOp.execute(
    { pid: launched.pid, text: "{UP}", settleMs: 500 },
    { workspace },
  );
  assert.equal(vkProbe.status, "ok");
  assert.match(vkProbe.screen.text, /VK=38/, "{UP} arrives as VK 38 (VK_UP)");

  // Enter on "Run check". The VK probe's _getch() wait consumes the first
  // Enter, so send two: one unblocks the probe hold, one triggers the check.
  const checked = await sendOp.execute(
    { pid: launched.pid, text: "\n\n", settleMs: 700 },
    { workspace },
  );
  assert.equal(checked.status, "ok");
  assert.match(checked.screen.text, /CHECK name='analyst' len=7/);

  // Quit: the CHECK line holds until a keypress, so the first q unblocks it
  // and the second q quits (deterministic: asserting BYE on screen races the
  // console teardown — process death is the observable outcome).
  const unblock = await sendOp.execute(
    { pid: launched.pid, text: "q", settleMs: 500 },
    { workspace },
  );
  assert.equal(unblock.status, "ok");
  assert.match(unblock.screen.text, /MINUSONE MENU TUI/, "menu redraws after the CHECK key-wait");
  const quit = await sendOp.execute(
    { pid: launched.pid, text: "q", settleMs: 500 },
    { workspace },
  );
  assert.equal(quit.status, "ok");
  await sleep(600);
  const afterQuit = await readOp.execute({ pid: launched.pid }, { workspace });
  assert.equal(afterQuit.status, "error");
  assert.equal(afterQuit.attached, false, "the console is gone once the process exited");

  // process.kill terminates the tree; a later read reports the dead console.
  const killOp = operations.find((entry) => entry.id === "process.kill");
  assert.ok(killOp, "process.kill operation exists");
  const killed = await killOp.execute({ pid: launched.pid }, { workspace });
  assert.equal(killed.status, "ok");
  await sleep(300);
  const afterKill = await readOp.execute({ pid: launched.pid }, { workspace });
  assert.equal(afterKill.status, "error");
  assert.equal(afterKill.attached, false);
});

test("console.launch refuses when the plane is unarmed", async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "minusone-console-"));
  context.after(() => rmRoot(root));
  await writeFile(path.join(root, "sample.exe"), "dummy");
  const workspace = await Workspace.create(root);
  const previousAllow = process.env.MINUSONE_ALLOW_DYNAMIC;
  const previousTarget = process.env.MINUSONE_DYNAMIC_TARGET;
  delete process.env.MINUSONE_ALLOW_DYNAMIC;
  delete process.env.MINUSONE_DYNAMIC_TARGET;
  context.after(() => {
    if (previousAllow !== undefined) process.env.MINUSONE_ALLOW_DYNAMIC = previousAllow;
    if (previousTarget !== undefined) process.env.MINUSONE_DYNAMIC_TARGET = previousTarget;
  });
  const operation = operations.find((entry) => entry.id === "console.launch");
  const refused = await operation.execute({ path: "sample.exe" }, { workspace });
  assert.equal(refused.status, "refused");
  assert.match(refused.reason, /disabled by policy/);
});

test("console.send rejects a non-positive pid at the operation layer", async () => {
  const operation = operations.find((entry) => entry.id === "console.send");
  await assert.rejects(
    () => operation.execute({ pid: 0, text: "x" }, { workspace: undefined }),
    /pid must be a positive integer/,
  );
});
