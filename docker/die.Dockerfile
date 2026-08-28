# Detect It Easy signature engine (horsicq). Static identification of
# packers, compilers, linkers, and protectors — no sample execution.
# Pinned release .deb built for Debian 12 (bookworm).
FROM debian:bookworm-slim

ARG DIE_VERSION=3.21
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/die.deb "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb" \
 && apt-get update && apt-get install -y --no-install-recommends /tmp/die.deb \
 && rm -f /tmp/die.deb \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["diec"]
