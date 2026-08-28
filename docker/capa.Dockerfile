# Reproducible capa (capabilities detection) analysis container.
# Pinned interpreter, capa release, and capa-rules revision; the rules
# revision is baked in so identical rebuilds produce identical results.
FROM python:3.12-slim-bookworm

ARG CAPA_VERSION=9.4.0
ARG CAPA_RULES_REVISION=801a792c60fb2c8ef79e1b5d61d7e3d2cab4d405

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flare-capa==${CAPA_VERSION}

# capa 9.x resolves default FLIRT signatures from <site-packages>/sigs
# (get_default_root()/sigs), not ~/.capa — install them there so no -s flag
# is needed.
RUN git clone --depth 1 --branch v${CAPA_VERSION} https://github.com/mandiant/capa /tmp/capa-src \
    && SITE_SIGS="$(python -c 'import site; print(site.getsitepackages()[0])')/sigs" \
    && mkdir -p "${SITE_SIGS}" \
    && cp -r /tmp/capa-src/sigs/. "${SITE_SIGS}/" \
    && rm -rf /tmp/capa-src

RUN git clone --no-checkout https://github.com/mandiant/capa-rules /opt/capa-rules \
    && git -C /opt/capa-rules checkout ${CAPA_RULES_REVISION} \
    && rm -rf /opt/capa-rules/.git

WORKDIR /workspace
ENTRYPOINT ["capa"]
