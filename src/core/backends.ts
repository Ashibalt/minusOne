/**
 * Pinned Docker images for every containerized provider. The images ship with
 * the project (docker/*.Dockerfile, built via `npm run providers:build`; the
 * official radare2 image is pulled as-is), so a host with Docker serves the
 * full operation table out of the box. Each MINUSONE_*_IMAGE variable is an
 * override: a non-empty value replaces the pinned image, and an explicit empty
 * value disables the Docker backend entirely (useful on hosts without Docker,
 * or in tests that must never spawn containers).
 */
export const DEFAULT_IMAGES = {
  capa: "minusone/capa:9.4.0",
  yaraX: "minusone/yara-x:1.19.0",
  floss: "minusone/floss:3.1.1",
  die: "minusone/die:3.21",
  radare2: "radare/radare2:5.9.8",
  binwalk: "minusone/binwalk:2.3.3",
  ghidra: "minusone/ghidra:12.1.2",
  volatility3: "minusone/volatility3:2.28.0",
  peTools: "minusone/pe-tools:lief",
  unicorn: "minusone/unicorn:2.1.3",
  symbolic: "minusone/symbolic:angr9.3.3",
} as const;

export function resolveDockerImage(envValue: string | undefined, fallback: string): string | null {
  if (envValue === undefined) return fallback;
  const trimmed = envValue.trim();
  return trimmed === "" ? null : envValue;
}
