import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Workspace } from "./workspace.js";

/**
 * Output budget (owner-specified mechanics): every tool answer is capped at
 * `max_output` characters (default 8000, the model picks per call). When the
 * full answer exceeds the cap the model receives the FIRST max_output
 * characters and the FULL text lands in a file under .minusone/outputs/ with
 * the path reported in the answer; a shorter answer is returned whole and
 * nothing is written.
 */
export const MAX_OUTPUT_DEFAULT = 8000;
const MAX_OUTPUT_MIN = 256;

export interface OutputBudgetResult {
  text: string;
  truncated: boolean;
  outputFile?: string;
  totalChars: number;
}

export function resolveMaxOutput(raw: unknown): number {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return MAX_OUTPUT_DEFAULT;
  return Math.max(MAX_OUTPUT_MIN, Math.floor(raw));
}

export async function capToolOutput(
  workspace: Workspace,
  label: string,
  text: string,
  maxOutput: number,
): Promise<OutputBudgetResult> {
  const totalChars = text.length;
  if (totalChars <= maxOutput) {
    return { text, truncated: false, totalChars };
  }
  const relative = await writeOutputSpill(workspace, label, text);
  const head = text.slice(0, maxOutput);
  return {
    text: `${head}\n\n[output truncated: ${totalChars} chars total, showing first ${maxOutput}; full output saved to ${relative}]`,
    truncated: true,
    outputFile: relative,
    totalChars,
  };
}

/**
 * Write a full payload into .minusone/outputs/ and return the
 * workspace-relative path. Used directly by operations whose answer is a
 * summary by design (trace.diff): the detail rides the file, not the reply.
 */
export async function writeOutputSpill(workspace: Workspace, label: string, text: string): Promise<string> {
  const outputDirectory = path.join(workspace.root, ".minusone", "outputs");
  await mkdir(outputDirectory, { recursive: true });
  const safeLabel = label.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "output";
  const fileName = `${safeLabel}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}.txt`;
  const absolute = path.join(outputDirectory, fileName);
  await writeFile(absolute, text, "utf8");
  return workspace.relative(absolute);
}
