export type BinaryKind = "elf" | "pe" | "mach-o" | "unknown";
export type Endianness = "little" | "big" | "unknown";

export interface BinaryFormat {
  kind: BinaryKind;
  architecture: string;
  bits: 32 | 64 | null;
  endianness: Endianness;
}

export interface BinaryInfo {
  path: string;
  sampleId: string;
  sha256: string;
  size: number;
  entropy: number;
  format: BinaryFormat;
}

export interface ExtractedString {
  offset: number;
  encoding: "ascii" | "utf16le";
  value: string;
}

export interface StringExtractionResult {
  path: string;
  scannedBytes: number;
  fileSize: number;
  scanTruncated: boolean;
  resultTruncated: boolean;
  strings: ExtractedString[];
}

export interface CommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  outputTruncated: boolean;
  aborted: boolean;
}

export interface ToolCapability {
  name: string;
  available: boolean;
  version?: string;
  path?: string;
  note?: string;
}

export interface DoctorReport {
  platform: NodeJS.Platform;
  architecture: string;
  node: string;
  workspace: string;
  capabilities: ToolCapability[];
  readyForBaselineAnalysis: boolean;
  readyForGhidra: boolean;
  dynamicAnalysisPolicy: string;
}

export interface BaselineAnalysis {
  binary: BinaryInfo;
  strings: StringExtractionResult;
  headers?: CommandResult;
  limitations: string[];
}
