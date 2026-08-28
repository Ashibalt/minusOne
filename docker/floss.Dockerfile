# FLOSS static string deobfuscation (Mandiant). Emulates decoders statically —
# never executes the sample. Standalone release binary, pinned by tag; scans
# run with --network none and read-only sample mounts (see src/core/floss.ts).
FROM debian:bookworm-slim

ARG FLOSS_VERSION=3.1.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && curl -fsSL -o /tmp/floss.zip "https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip" \
 && unzip -j /tmp/floss.zip -d /usr/local/bin \
 && chmod +x /usr/local/bin/floss \
 && apt-get purge -y curl unzip && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /tmp/floss.zip

ENTRYPOINT ["floss"]
