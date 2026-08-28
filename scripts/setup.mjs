#!/usr/bin/env node
/**
 * minusOne one-command setup: thin, documented entry point around the
 * bootstrap engine (build pinned images + TTD extraction + readiness
 * report). See docs/installation.md.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2).filter((arg) => arg !== "--help" && arg !== "-h");
if (args.length !== process.argv.slice(2).length) {
  console.log("usage: npm run setup [--images-only | --report-only | --skip-build]");
  process.exit(0);
}
const result = spawnSync(process.execPath, [path.join(here, "bootstrap.mjs"), ...args], { stdio: "inherit" });
process.exit(result.status ?? 1);
