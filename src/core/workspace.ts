import { mkdir, readFile, realpath, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export class WorkspaceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkspaceError";
  }
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/**
 * Owner-authorized external roots: directories OUTSIDE the workspace the
 * agent may READ samples from (never write to). Sources: the
 * MINUSONE_TRUSTED_ROOTS env var (path.delimiter-separated, `~` expanded)
 * and the workspace's .minusone/config.json `trustedRoots` list (managed
 * by `minusone trust`). Read-only asymmetry: resolveFile accepts trusted
 * roots; resolveWritablePath / resolveWritableDir never do — writes stay
 * inside the workspace, always.
 */
async function resolveTrustedRoots(root: string): Promise<string[]> {
  const raw = new Set<string>();

  const envValue = process.env.MINUSONE_TRUSTED_ROOTS;
  if (envValue !== undefined && envValue !== "") {
    for (const entry of envValue.split(path.delimiter)) {
      const trimmed = entry.trim();
      if (trimmed !== "") raw.add(expandHome(trimmed));
    }
  }

  try {
    const parsed = JSON.parse(await readFile(path.join(root, ".minusone", "config.json"), "utf8")) as {
      trustedRoots?: unknown;
    };
    if (Array.isArray(parsed.trustedRoots)) {
      for (const entry of parsed.trustedRoots) {
        if (typeof entry === "string" && entry.trim() !== "") raw.add(expandHome(entry.trim()));
      }
    }
  } catch {
    // No config file (or unreadable) — env roots only.
  }

  const resolved: string[] = [];
  for (const candidate of raw) {
    try {
      const real = await realpath(path.resolve(candidate));
      const stats = await stat(real);
      if (stats.isDirectory() && !isWithin(root, real)) resolved.push(real);
    } catch {
      // A listed root that does not exist (yet) is skipped, not fatal.
    }
  }
  return resolved;
}

function expandHome(candidate: string): string {
  if (candidate === "~") return os.homedir();
  if (candidate.startsWith("~\\") || candidate.startsWith("~/")) {
    return path.join(os.homedir(), candidate.slice(2));
  }
  return candidate;
}

export class Workspace {
  readonly root: string;
  /** Read-only external roots (see {@link resolveTrustedRoots}). */
  readonly trustedRoots: readonly string[];

  private constructor(root: string, trustedRoots: string[]) {
    this.root = root;
    this.trustedRoots = trustedRoots;
  }

  static async create(root = process.env.MINUSONE_WORKSPACE ?? process.cwd()): Promise<Workspace> {
    const resolvedRoot = await realpath(path.resolve(root));
    const rootStats = await stat(resolvedRoot);
    if (!rootStats.isDirectory()) {
      throw new WorkspaceError(`Workspace is not a directory: ${resolvedRoot}`);
    }
    return new Workspace(resolvedRoot, await resolveTrustedRoots(resolvedRoot));
  }

  /** True when the absolute path sits inside the workspace or a trusted root. */
  isReadable(absolutePath: string): boolean {
    if (isWithin(this.root, absolutePath)) return true;
    return this.trustedRoots.some((trusted) => isWithin(trusted, absolutePath));
  }

  /** Resolve a readable file inside the workspace or a trusted root. */
  async resolveFile(userPath: string): Promise<string> {
    if (!userPath.trim()) {
      throw new WorkspaceError("A non-empty file path is required");
    }

    const lexicalPath = path.resolve(this.root, userPath);
    if (!this.isReadable(lexicalPath)) {
      throw new WorkspaceError(`Path escapes the workspace: ${userPath}`);
    }

    let resolvedPath: string;
    try {
      resolvedPath = await realpath(lexicalPath);
    } catch {
      throw new WorkspaceError(`File does not exist: ${userPath}`);
    }

    if (!this.isReadable(resolvedPath)) {
      throw new WorkspaceError(`Resolved path escapes the workspace: ${userPath}`);
    }

    const fileStats = await stat(resolvedPath);
    if (!fileStats.isFile()) {
      throw new WorkspaceError(`Path is not a regular file: ${userPath}`);
    }
    return resolvedPath;
  }

  /**
   * Resolve a path the agent may WRITE to. Unlike {@link resolveFile} this
   * does not require pre-existence: the parent directory tree is created.
   * Containment is enforced the same way — and trusted roots NEVER qualify:
   * writes stay inside the workspace, no exceptions.
   */
  async resolveWritablePath(userPath: string): Promise<string> {
    if (!userPath.trim()) {
      throw new WorkspaceError("A non-empty path is required");
    }
    const lexicalPath = path.resolve(this.root, userPath);
    if (!isWithin(this.root, lexicalPath)) {
      throw new WorkspaceError(`Path escapes the workspace: ${userPath}`);
    }
    await mkdir(path.dirname(lexicalPath), { recursive: true });
    return lexicalPath;
  }

  /**
   * Resolve a directory the agent may WRITE into, creating it (and parents).
   * Containment is enforced — the directory never escapes the workspace.
   */
  async resolveWritableDir(userPath: string): Promise<string> {
    if (!userPath.trim()) {
      throw new WorkspaceError("A non-empty directory path is required");
    }
    const lexicalPath = path.resolve(this.root, userPath);
    if (!isWithin(this.root, lexicalPath)) {
      throw new WorkspaceError(`Path escapes the workspace: ${userPath}`);
    }
    await mkdir(lexicalPath, { recursive: true });
    return lexicalPath;
  }

  /**
   * Display path for model-facing output: workspace-relative when inside,
   * absolute (a clear "this came from outside" signal) when in a trusted
   * root. Never used for containment — display only.
   */
  displayPath(absolutePath: string): string {
    if (isWithin(this.root, absolutePath)) return path.relative(this.root, absolutePath) || ".";
    return absolutePath;
  }

  relative(absolutePath: string): string {
    return path.relative(this.root, absolutePath) || ".";
  }
}
