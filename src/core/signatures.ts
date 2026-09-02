/**
 * signature.verify — the legitimacy check that was missing from triage.
 * The Unity.dll field case: DIE's entropy heuristic said "packed" while a
 * VALID Authenticode signature sat in the overlay — the two are logically
 * incompatible, and the analyst burned half a session reconciling them.
 *
 * Native Windows route: Get-AuthenticodeSignature (WinVerifyTrust under the
 * hood — the OS validates the whole PKCS#7 SignedData, the certificate
 * chain and the message digest against the file). No downloads, no network
 * (offline chain policy still validates against the local trust store).
 * A structural pre-check parses the certificate table itself so the report
 * can distinguish "no signature at all" from "signature present but OS
 * says Invalid" — different analytical stories.
 */
import { open } from "node:fs/promises";
import path from "node:path";
import { runBoundedCommand } from "./command.js";
import { inspectBinary } from "./binary.js";
import type { Workspace } from "./workspace.js";

export const SIGNATURE_TIMEOUT_SECONDS = 30;

export interface SignatureResult {
  backend: "win-native" | "unavailable";
  path: string;
  sampleId: string;
  /** True when the file carries an Authenticode certificate table at all. */
  signaturePresent: boolean;
  /** OS verdict on the signature (when present): Valid/NotSigned/... */
  status: string | null;
  /** Signer subject DN (CN pulled out for a one-line summary). */
  /** Signer subject DN; empty string when not signed (hosts validate: never null). */
  signer: string;
  signerCommonName: string;
  /** True when the OS validated the file digest AND the chain — the strong claim. */
  valid: boolean;
  /** Human conclusion for triage consumption. */
  verdict: string;
  notes: string[];
  command: { exitCode: number | null; stdout: string; stderr: string } | null;
}

interface CertificateTableLocation {
  offset: number;
  size: number;
}

/**
 * Locate the Authenticode certificate table (data directory index 4,
 * CERTIFICATE_TABLE) in a PE. Data directories start at optional-header
 * offset 112 (PE32+) or 96 (PE32); every entry is 8 bytes, so index 4 sits
 * at +4*8. Exported for the structural unit test.
 */
export async function locateCertificateTable(absolutePath: string): Promise<CertificateTableLocation | null> {
  const handle = await open(absolutePath, "r");
  try {
    const head = Buffer.alloc(0x400);
    const { bytesRead } = await handle.read(head, 0, 0x400, 0);
    const buffer = head.subarray(0, bytesRead);
    if (buffer.length < 0x40 || buffer.toString("ascii", 0, 2) !== "MZ") return null;
    const peOffset = buffer.readUInt32LE(0x3c);
    if (peOffset + 24 + 112 + 40 > buffer.length) return null;
    if (buffer.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") return null;
    const optionalHeaderOffset = peOffset + 24;
    const magic = buffer.readUInt16LE(optionalHeaderOffset);
    const certDirOffset = magic === 0x20b ? optionalHeaderOffset + 112 + 4 * 8 : optionalHeaderOffset + 96 + 4 * 8;
    if (certDirOffset + 8 > buffer.length) return null;
    const rva = buffer.readUInt32LE(certDirOffset);
    const size = buffer.readUInt32LE(certDirOffset + 4);
    // The certificate table is a FILE offset (not an RVA) per the PE spec.
    if (rva === 0 || size === 0) return null;
    return { offset: rva, size };
  } finally {
    await handle.close();
  }
}

function extractCommonName(subject: string): string | null {
  const match = subject.match(/CN=([^,]+)/);
  return match === null || match[1] === undefined ? null : match[1].trim();
}

export async function verifySignature(workspace: Workspace, userPath: string): Promise<SignatureResult> {
  const absolutePath = await workspace.resolveFile(userPath);
  const binary = await inspectBinary(workspace, userPath);
  const notes: string[] = [];

  const table = await locateCertificateTable(absolutePath);
  const signaturePresent = table !== null;
  if (table !== null) {
    notes.push(`Authenticode certificate table: ${table.size} bytes at file offset 0x${table.offset.toString(16)}`);
  }

  if (process.platform !== "win32") {
    return {
      backend: "unavailable",
      path: binary.path,
      sampleId: binary.sampleId,
      signaturePresent,
      status: null,
      signer: "",
      signerCommonName: "",
      valid: false,
      verdict: "structural check only — WinVerifyTrust runs on Windows hosts",
      notes,
      command: null,
    };
  }

  const psScript = [
    "$ErrorActionPreference = 'Stop'",
    `$sig = Get-AuthenticodeSignature -FilePath '${absolutePath.replace(/'/g, "''")}'`,
    "$out = [ordered]@{",
    "  Status = [string]$sig.Status",
    "  StatusMessage = [string]$sig.StatusMessage",
    "  Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }",
    "  TimeStamper = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }",
    "}",
    "$out | ConvertTo-Json -Compress",
  ].join("\n");
  const command = await runBoundedCommand("powershell", ["-NoProfile", "-NonInteractive", "-Command", psScript], {
    timeoutMs: SIGNATURE_TIMEOUT_SECONDS * 1000,
    maxOutputBytes: 32 * 1024,
  });

  let status: string | null = null;
  let signer: string | null = null; // parsed; normalized to "" at the boundary
  let statusMessage: string | null = null;
  try {
    const parsed = JSON.parse(command.stdout.trim()) as { Status?: string; Signer?: string; StatusMessage?: string };
    status = parsed.Status ?? null;
    signer = parsed.Signer ?? null;
    statusMessage = parsed.StatusMessage ?? null;
  } catch {
    notes.push("Get-AuthenticodeSignature output was not JSON — falling back to text parse");
    const text = command.stdout;
    const statusMatch = text.match(/Status\s*[:=]\s*(\w+)/);
    if (statusMatch !== null && statusMatch[1] !== undefined) status = statusMatch[1];
  }

  if (command.exitCode !== 0 && status === null) {
    return {
      backend: "unavailable",
      path: binary.path,
      sampleId: binary.sampleId,
      signaturePresent,
      status: null,
      signer: "",
      signerCommonName: "",
      valid: false,
      verdict: "WinVerifyTrust could not run (powershell failed)",
      notes: [...notes, `stderr: ${command.stderr.slice(0, 300)}`],
      command: { exitCode: command.exitCode, stdout: command.stdout, stderr: command.stderr },
    };
  }

  const valid = status === "Valid";
  let verdict: string;
  if (!signaturePresent && (status === null || status === "NotSigned")) {
    verdict = "NOT SIGNED — no Authenticode certificate table; treat provenance as unknown";
  } else if (valid) {
    verdict = `VALID SIGNATURE${signer === null ? "" : ` by ${extractCommonName(signer) ?? signer}`} — the file digest matches the PKCS#7 SignedData and the chain resolves in the local trust store; patching ANY byte breaks it`;
  } else if (status === "HashMismatch") {
    verdict = "SIGNATURE BROKEN — a certificate table exists but the file content no longer matches the signed digest (patched/modified after signing)";
  } else {
    verdict = `SIGNATURE PRESENT but OS verdict is ${status ?? "unknown"}${statusMessage === null ? "" : ` (${statusMessage})`} — structural presence without validity`;
  }

  return {
    backend: "win-native",
    path: binary.path,
    sampleId: binary.sampleId,
    signaturePresent,
    status,
    signer: signer ?? "",
    signerCommonName: signer === null ? "" : extractCommonName(signer) ?? "",
    valid,
    verdict,
    notes,
    command: { exitCode: command.exitCode, stdout: command.stdout.slice(0, 2048), stderr: command.stderr.slice(0, 1024) },
  };
}
