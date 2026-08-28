# Binwalk signature scanning (scan-only). Extraction is deliberately NOT
# wired: extraction needs child-count/bytes/depth limits before it can be
# exposed (see docs/architecture.md). v2.3.3 from the release tarball —
# PyPI only carries 2.1.0 and v3 has no release assets. Python 3.11 because
# v2 still imports the stdlib `imp` module, removed in 3.12.
FROM python:3.11-slim-bookworm

ARG BINWALK_VERSION=2.3.3
RUN pip install --no-cache-dir "https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v${BINWALK_VERSION}.tar.gz"

ENTRYPOINT ["binwalk"]
