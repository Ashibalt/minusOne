# Unicorn engine runner (emulation plane). Executes raw code snippets —
# shellcode, decryptor stubs — with mapped memory and register capture,
# WITHOUT a process or a guest OS: the emulated code cannot touch the
# host. PyPI's unicorn package (official Unicorn engine binding) pinned.
FROM python:3.12-slim-bookworm

ARG UNICORN_VERSION=2.1.3

RUN pip install --no-cache-dir unicorn==${UNICORN_VERSION}

COPY docker/emu-run.py /opt/minusone/emu-run.py

ENTRYPOINT ["python", "/opt/minusone/emu-run.py"]
