FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
ARG GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/var/cache/ghidra \
    curl --fail --location --retry 5 --retry-all-errors --continue-at - \
      --output /var/cache/ghidra/ghidra.zip "${GHIDRA_URL}" \
    && echo "${GHIDRA_SHA256}  /var/cache/ghidra/ghidra.zip" | sha256sum --check --strict \
    && unzip -q /var/cache/ghidra/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra

RUN groupadd --gid 1001 ghidra \
    && useradd --uid 1001 --gid 1001 --create-home ghidra \
    && chown -R ghidra:ghidra /opt/ghidra /home/ghidra

USER ghidra
WORKDIR /workspace
ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
