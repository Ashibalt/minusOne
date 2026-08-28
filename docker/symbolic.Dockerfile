# Symbolic execution backend (docker, --network none). angr answers the
# crackme question directly — "which inputs pass the check" — via concolic
# exploration of the loaded PE; Triton simplifies MBA expressions that
# static decompilers choke on. Both are pure-analysis engines: the sample
# is loaded as DATA and explored in an emulated/symbolic state, never
# executed on the host.
FROM python:3.12-slim-bookworm

ARG ANGR_VERSION=9.3.3
ARG TRITON_VERSION=1.0.0rc4

RUN pip install --no-cache-dir \
    angr==${ANGR_VERSION} \
    triton-library==${TRITON_VERSION}

COPY docker/symbolic-run.py /opt/minusone/symbolic-run.py

ENTRYPOINT ["python", "/opt/minusone/symbolic-run.py"]
