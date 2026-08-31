/**
 * Investigation notes — the campaign's working memory, a first-class file
 * at .minusone/campaign/notes.md. NOT a task list: hypotheses with statuses
 * (and WHY they died), the address table, dead ends so they are never
 * re-walked, open questions, and an append-only log. Written CONTINUOUSLY
 * (context compaction is unpredictable), read at session start.
 *
 * The file is human/agent-editable markdown with a frontmatter block and
 * fixed section headers; the parser is tolerant of hand edits, and every
 * update round-trips through parse → apply → render → atomic write.
 */
import { readFile } from "node:fs/promises";
import {
  atomicWriteFile,
  ensureCampaignDir,
  notesPath,
} from "./campaign.js";
import type { Workspace } from "./workspace.js";

export type HypothesisStatus = "open" | "confirmed" | "killed";

export interface NotesData {
  goal: string;
  updated: string;
  hypotheses: Array<{ status: HypothesisStatus; text: string; stamp: string }>;
  addresses: Array<{ address: string; name: string }>;
  deadEnds: Array<{ text: string; stamp: string }>;
  openQuestions: string[];
  log: Array<{ stamp: string; text: string }>;
}

const EMPTY_NOTES: NotesData = {
  goal: "",
  updated: "",
  hypotheses: [],
  addresses: [],
  deadEnds: [],
  openQuestions: [],
  log: [],
};

function nowStamp(): string {
  return new Date().toISOString();
}

/** Parse notes.md; tolerant of hand edits — unknown lines stay out of the structured form but never crash it. */
export function parseNotes(markdown: string): NotesData {
  const data: NotesData = { ...EMPTY_NOTES, hypotheses: [], addresses: [], deadEnds: [], openQuestions: [], log: [] };
  const goalMatch = /^goal:\s*"(.*)"\s*$/m.exec(markdown);
  if (goalMatch?.[1] !== undefined) data.goal = goalMatch[1];
  const updatedMatch = /^updated:\s*(\S+)\s*$/m.exec(markdown);
  if (updatedMatch?.[1] !== undefined) data.updated = updatedMatch[1];

  const sections = markdown.split(/^## /m).slice(1);
  for (const section of sections) {
    const newline = section.indexOf("\n");
    const header = (newline === -1 ? section : section.slice(0, newline)).trim();
    const body = newline === -1 ? "" : section.slice(newline + 1);
    const lines = body.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith("- ") && line !== "- (none yet)" && line !== "- (empty)");
    if (header === "Hypotheses") {
      for (const line of lines) {
        const match = /^- \[(open|confirmed|killed)\] (.*?) \(([^()]*)\)$/.exec(line);
        if (match) data.hypotheses.push({ status: match[1] as HypothesisStatus, text: match[2] ?? "", stamp: match[3] ?? "" });
      }
    } else if (header === "Addresses") {
      for (const line of lines) {
        const match = /^- (\S+) — (.*)$/.exec(line);
        if (match) data.addresses.push({ address: match[1] ?? "", name: match[2] ?? "" });
      }
    } else if (header === "Dead ends") {
      for (const line of lines) {
        const match = /^- (.*?) \(([^()]*)\)$/.exec(line);
        if (match) data.deadEnds.push({ text: match[1] ?? "", stamp: match[2] ?? "" });
      }
    } else if (header === "Open questions") {
      for (const line of lines) {
        data.openQuestions.push(line.slice(2));
      }
    } else if (header === "Log") {
      for (const line of lines) {
        const match = /^- (\S+) — (.*)$/.exec(line);
        if (match) data.log.push({ stamp: match[1] ?? "", text: match[2] ?? "" });
      }
    }
  }
  return data;
}

export function renderNotes(data: NotesData): string {
  const lines: string[] = [
    "---",
    `goal: "${data.goal.replace(/"/g, "'")}"`,
    `updated: ${data.updated}`,
    "---",
    "",
    "# Investigation notes",
    "",
    "## Goal",
    data.goal,
    "",
    "## Hypotheses",
    ...(data.hypotheses.length === 0 ? ["- (none yet)"] : data.hypotheses.map((hypothesis) => `- [${hypothesis.status}] ${hypothesis.text} (${hypothesis.stamp})`)),
    "",
    "## Addresses",
    ...(data.addresses.length === 0 ? ["- (none yet)"] : data.addresses.map((entry) => `- ${entry.address} — ${entry.name}`)),
    "",
    "## Dead ends",
    ...(data.deadEnds.length === 0 ? ["- (none yet)"] : data.deadEnds.map((entry) => `- ${entry.text} (${entry.stamp})`)),
    "",
    "## Open questions",
    ...(data.openQuestions.length === 0 ? ["- (none yet)"] : data.openQuestions.map((question) => `- ${question}`)),
    "",
    "## Log",
    ...(data.log.length === 0 ? ["- (empty)"] : data.log.map((entry) => `- ${entry.stamp} — ${entry.text}`)),
    "",
  ];
  return lines.join("\n");
}

export async function readNotes(workspace: Workspace): Promise<{ exists: boolean; markdown: string; data: NotesData | null }> {
  let markdown: string;
  try {
    markdown = await readFile(notesPath(workspace), "utf8");
  } catch {
    return { exists: false, markdown: "", data: null };
  }
  return { exists: true, markdown, data: parseNotes(markdown) };
}

export type NotesUpdate =
  | { action: "goal"; text: string }
  | { action: "log"; text: string }
  | { action: "hypothesis"; text: string; status: HypothesisStatus }
  | { action: "address"; address: string; name: string }
  | { action: "dead_end"; text: string }
  | { action: "question"; text: string }
  | { action: "resolve_question"; text: string };

export interface NotesSummary {
  hypotheses: Record<HypothesisStatus, number>;
  addresses: number;
  deadEnds: number;
  openQuestions: number;
  logLines: number;
}

function summarize(data: NotesData): NotesSummary {
  return {
    hypotheses: {
      open: data.hypotheses.filter((hypothesis) => hypothesis.status === "open").length,
      confirmed: data.hypotheses.filter((hypothesis) => hypothesis.status === "confirmed").length,
      killed: data.hypotheses.filter((hypothesis) => hypothesis.status === "killed").length,
    },
    addresses: data.addresses.length,
    deadEnds: data.deadEnds.length,
    openQuestions: data.openQuestions.length,
    logLines: data.log.length,
  };
}

export async function updateNotes(workspace: Workspace, update: NotesUpdate): Promise<{ status: "ok"; action: string; summary: NotesSummary }> {
  const existing = await readNotes(workspace);
  const data = existing.data ?? { ...EMPTY_NOTES, hypotheses: [], addresses: [], deadEnds: [], openQuestions: [], log: [] };
  const stamp = nowStamp();

  switch (update.action) {
    case "goal":
      data.goal = update.text;
      data.log.push({ stamp, text: `goal set: ${update.text}` });
      break;
    case "log":
      data.log.push({ stamp, text: update.text });
      break;
    case "hypothesis": {
      // Same text = status evolution (replace in place); new text = append.
      const existingIndex = data.hypotheses.findIndex((hypothesis) => hypothesis.text === update.text);
      const entry = { status: update.status, text: update.text, stamp };
      if (existingIndex === -1) data.hypotheses.push(entry);
      else data.hypotheses[existingIndex] = entry;
      break;
    }
    case "address":
      if (!data.addresses.some((entry) => entry.address === update.address)) {
        data.addresses.push({ address: update.address, name: update.name });
      }
      break;
    case "dead_end":
      data.deadEnds.push({ text: update.text, stamp });
      break;
    case "question":
      if (!data.openQuestions.includes(update.text)) data.openQuestions.push(update.text);
      break;
    case "resolve_question": {
      const before = data.openQuestions.length;
      data.openQuestions = data.openQuestions.filter((question) => question !== update.text && !question.includes(update.text));
      const removed = before - data.openQuestions.length;
      data.log.push({ stamp, text: removed > 0 ? `question resolved: ${update.text}` : `no open question matched: ${update.text}` });
      break;
    }
  }

  data.updated = stamp;
  await ensureCampaignDir(workspace);
  await atomicWriteFile(notesPath(workspace), renderNotes(data));
  return { status: "ok", action: update.action, summary: summarize(data) };
}

export function summarizeNotes(data: NotesData): NotesSummary {
  return summarize(data);
}
