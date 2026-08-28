# YARA-X scan engine. Prebuilt release binary from VirusTotal, pinned by tag.
# Scans run with --network none and read-only sample mounts (see src/core/yara.ts).
FROM debian:bookworm-slim

ARG YARA_X_VERSION=1.19.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    | tar -xz -C /usr/local/bin \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["yr"]
