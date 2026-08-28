/**
 * Workspace configuration (`.minusone/config.json`). The owner arms the
 * dynamic plane once with `minusOne arm` and every dsh launch on that
 * workspace is operational afterwards — no per-invocation env ceremony.
 * `resolveDynamicTarget` reads this as the fallback below env-var overrides.
 * `trustedRoots` lists owner-authorized READ-ONLY external sample
 * directories (`minusOne trust <dir>`): resolveFile accepts paths inside
 * them, writes never do (see workspace.ts).
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Workspace } from "./workspace.js";

export type DynamicMode = "none" | "local";
/** Model ranking plane: opt-in because it needs Python+torch the host may not have. */
export type ModelsMode = "off" | "on";

export interface WorkspaceConfig {
  version: 1;
  dynamic: DynamicMode;
  trustedRoots: string[];
  models: ModelsMode;
  updatedAt: number;
}

const CONFIG_FILE = "config.json";

export function configPath(workspace: Workspace): string {
  return path.join(workspace.root, ".minusone", CONFIG_FILE);
}

export async function readWorkspaceConfig(workspace: Workspace): Promise<WorkspaceConfig> {
  try {
    const raw = await readFile(configPath(workspace), "utf8");
    const parsed = JSON.parse(raw) as Partial<WorkspaceConfig>;
    const trustedRoots = Array.isArray(parsed.trustedRoots)
      ? parsed.trustedRoots.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "")
      : [];
    return {
      version: 1,
      dynamic: parsed.dynamic === "local" ? "local" : "none",
      trustedRoots: [...new Set(trustedRoots)],
      models: parsed.models === "on" ? "on" : "off",
      updatedAt: typeof parsed.updatedAt === "number" ? parsed.updatedAt : 0,
    };
  } catch {
    return { version: 1, dynamic: "none", trustedRoots: [], models: "off", updatedAt: 0 };
  }
}

async function writeConfig(workspace: Workspace, config: WorkspaceConfig): Promise<WorkspaceConfig> {
  await mkdir(path.dirname(configPath(workspace)), { recursive: true });
  const next: WorkspaceConfig = { ...config, updatedAt: Date.now() };
  await writeFile(configPath(workspace), JSON.stringify(next, null, 2), "utf8");
  return next;
}

export async function writeWorkspaceConfig(workspace: Workspace, dynamic: DynamicMode): Promise<WorkspaceConfig> {
  const current = await readWorkspaceConfig(workspace);
  return writeConfig(workspace, { ...current, dynamic });
}

/** Toggle the model-ranking plane (models: "off" | "on"). */
export async function writeModelsMode(workspace: Workspace, models: ModelsMode): Promise<WorkspaceConfig> {
  const current = await readWorkspaceConfig(workspace);
  return writeConfig(workspace, { ...current, models });
}

/** Add a trusted read-only root (idempotent); returns the updated config. */
export async function trustRoot(workspace: Workspace, directory: string): Promise<WorkspaceConfig> {
  const current = await readWorkspaceConfig(workspace);
  return writeConfig(workspace, {
    ...current,
    trustedRoots: [...new Set([...current.trustedRoots, path.resolve(directory)])],
  });
}

/** Remove a trusted root; returns the updated config. */
export async function untrustRoot(workspace: Workspace, directory: string): Promise<WorkspaceConfig> {
  const current = await readWorkspaceConfig(workspace);
  const resolved = path.resolve(directory);
  return writeConfig(workspace, {
    ...current,
    trustedRoots: current.trustedRoots.filter((entry) => entry !== resolved),
  });
}
