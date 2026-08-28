/**
 * Shared types for the debugger bridge. Kept in a dedicated module so the
 * gdb driver (debugger.ts) and the cdb driver (cdb.ts) can implement the
 * same surface without a runtime import cycle.
 */

export type DebuggerKind = "gdb" | "cdb" | "x64dbg";

export interface DebugCommandResult {
  ok: boolean;
  output: string;
  seconds: number;
  timedOut?: boolean;
  error?: string;
}

export interface DebugTranscriptEntry {
  command: string;
  output: string;
  seconds: number;
}

/**
 * A debugger backend. gdb runs a live inferior under a prompt loop; cdb
 * postmortem re-runs an accumulated command batch against a frozen dump.
 * Both expose the same send/teardown surface to the session functions.
 */
export interface DebugDriver {
  readonly kind: DebuggerKind;
  readonly backendPath: string;
  readonly runDir: string;
  readonly target: string;
  send(command: string, timeoutSeconds: number): Promise<DebugCommandResult>;
  teardown(): Promise<{ commandsExecuted: number; transcript: DebugTranscriptEntry[] }>;
  /**
   * Kill the inferior WITHOUT tearing the session down (gdb only): the
   * debugger stays alive for the next run, the transcript keeps growing.
   * Drivers without a live inferior report that honestly.
   */
  killInferior?(): Promise<DebugCommandResult>;
}
