# PE reconstruction toolbox (LIEF + UPX). Rebuilds a runnable PE from a
# pe-sieve dump: fixes the import table against the original sample's
# imports when the dump lost it, aligns section raw/virtual sizes, and
# writes a machine-readable report of what was repaired. UPX gives the
# static decompress fast-path (upx -d) for UPX-packed samples — pure file
# transformation, nothing in the container executes a sample. The UPX
# binary is the official release from github.com/upx/upx (pinned).
FROM python:3.12-slim-bookworm

ARG LIEF_VERSION=0.16.1
ARG UPX_VERSION=4.2.4

RUN pip install --no-cache-dir lief==${LIEF_VERSION} \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" -o /tmp/upx.tar.xz \
    && tar -xJf /tmp/upx.tar.xz -C /tmp \
    && mv "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx \
    && rm -rf /tmp/upx* \
    && upx --version | head -1

COPY docker/pe-rebuild.py /opt/minusone/pe-rebuild.py

ENTRYPOINT ["python", "/opt/minusone/pe-rebuild.py"]
