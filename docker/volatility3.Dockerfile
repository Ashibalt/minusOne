# Volatility 3 memory-image analysis (Volatility Foundation). Read-only DFIR
# plugins over full RAM captures — the image is never executed. Runs with
# --network none and a read-only sample mount (see src/core/volatility.ts);
# kernel symbols are mounted from the host cache, never fetched at scan time.
FROM python:3.12-slim

ARG VOLATILITY3_VERSION=2.28.0
RUN pip install --no-cache-dir "volatility3==${VOLATILITY3_VERSION}" \
 && vol --help > /dev/null

ENTRYPOINT ["vol"]
