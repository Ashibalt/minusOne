"""minusOne model-ranking sidecar.

A long-lived Python process speaking JSONL over stdin/stdout. Node spawns
it once per session when model ranking is enabled; every request is one
JSON line, every response is one JSON line. The ranker-not-oracle contract
lives here too:

  * every answer is a RANKED LIST with scores — never a single verdict;
  * failures degrade to {"status": "error", ...} on ONE request, the
    sidecar (and the rest of the pipeline) stays alive;
  * models load lazily on first use and report load errors honestly;
  * GPU is used when available, CPU otherwise (rank quality is identical,
    only latency changes).

Commands:
  ping                     -> {"status": "ok", "loaded": {...}}
  rank_assembly            -> CLAP zero-shot: classify an assembly listing
                             against candidate descriptions (crypto-ID ...)
  rank_pseudocode          -> BinSeek embedding: rank pseudocode snippets
                             against a natural-language query ("find the
                             serial validator")
  shutdown                 -> clean exit

Env:
  MINUSONE_MODELS_DIR   directory containing clap-asm/, clap-text/,
                        BinSeek-Embedding/ (default: ./models next to repo)
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import traceback
from typing import Any

MODELS_DIR = os.environ.get(
    "MINUSONE_MODELS_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models"),
)

MAX_ASM_CHARS = 60_000
MAX_SNIPPETS = 32
MAX_PROMPTS = 32
MAX_QUERY_CHARS = 4_000


class Sidecar:
    def __init__(self) -> None:
        self.loaded: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self._clap: dict[str, Any] | None = None
        self._binseek: Any = None

    # ---------- loading -------------------------------------------------

    def _load_clap(self) -> dict[str, Any]:
        if self._clap is not None:
            return self._clap
        import torch  # noqa: PLC0415 - heavy import, lazy on purpose
        from transformers import AutoModel, AutoTokenizer  # noqa: PLC0415

        device = "cuda" if torch.cuda.is_available() else "cpu"
        asm_dir = os.path.join(MODELS_DIR, "clap-asm")
        text_dir = os.path.join(MODELS_DIR, "clap-text")
        asm_tokenizer = AutoTokenizer.from_pretrained(asm_dir, trust_remote_code=True)
        text_tokenizer = AutoTokenizer.from_pretrained(text_dir, trust_remote_code=True)
        asm_encoder = AutoModel.from_pretrained(asm_dir, trust_remote_code=True).to(device)
        text_encoder = AutoModel.from_pretrained(text_dir, trust_remote_code=True).to(device)
        asm_encoder.eval()
        text_encoder.eval()
        self._clap = {
            "torch": torch,
            "device": device,
            "asm_tokenizer": asm_tokenizer,
            "text_tokenizer": text_tokenizer,
            "asm_encoder": asm_encoder,
            "text_encoder": text_encoder,
        }
        self.loaded["clap"] = f"device={device}"
        return self._clap

    def _load_binseek(self) -> Any:
        if self._binseek is not None:
            return self._binseek
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        model_dir = os.path.join(MODELS_DIR, "BinSeek-Embedding")
        model = SentenceTransformer(model_dir, device="cuda" if _cuda_available() else "cpu")
        self._binseek = model
        self.loaded["binseek"] = f"device={model.device}"
        return model

    # ---------- commands ------------------------------------------------

    def ping(self, _: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "loaded": self.loaded, "errors": self.errors}

    def rank_assembly(self, request: dict[str, Any]) -> dict[str, Any]:
        raw_assembly = request.get("assembly", "")
        prompts = [str(p) for p in request.get("prompts", [])][:MAX_PROMPTS]
        # CLAP's AsmTokenizer takes a function as a DICT of
        # {"<line-key>": "<instruction text>"} — the keys become INSTRn
        # segment tokens. Accept either that dict shape or plain assembly
        # text (one instruction per line, keys auto-numbered).
        if isinstance(raw_assembly, dict):
            function = {str(key): str(value) for key, value in raw_assembly.items()}
        else:
            lines = [line.strip() for line in str(raw_assembly).splitlines() if line.strip()]
            if len(lines) > 2000:
                lines = lines[:2000]
            function = {str(index + 1): line for index, line in enumerate(lines)}
        if not function or not prompts:
            return {"status": "error", "error": "assembly and prompts are required"}

        clap = self._load_clap()
        torch = clap["torch"]
        device = clap["device"]

        with torch.no_grad():
            # truncation happens inside tokenize_function (model_max_length);
            # pad() only accepts padding args here. Both encoders return
            # READY normalized embeddings (they mean-pool, project and
            # L2-normalize internally) — no last_hidden_state, no pooling.
            asm_input = clap["asm_tokenizer"]([function], padding=True, return_tensors="pt").to(device)
            asm_embedding = clap["asm_encoder"](**asm_input)
            text_input = clap["text_tokenizer"](prompts, padding=True, truncation=True, max_length=256, return_tensors="pt").to(device)
            text_embeddings = clap["text_encoder"](**text_input)

            logits = (asm_embedding @ text_embeddings.T) / 0.07
            probs = torch.softmax(logits, dim=1).squeeze(0).tolist()

        ranked = sorted(
            [{"prompt": prompt, "score": float(score)} for prompt, score in zip(prompts, probs)],
            key=lambda entry: entry["score"],
            reverse=True,
        )
        return {
            "status": "ok",
            "model": "clap",
            "device": device,
            "ranked": ranked,
            "note": "scores are softmax probabilities over the given prompts; verify deterministically (constant byte-search, xrefs) before acting",
        }

    def rank_pseudocode(self, request: dict[str, Any]) -> dict[str, Any]:
        query = str(request.get("query", ""))[:MAX_QUERY_CHARS]
        snippets = request.get("snippets", [])[:MAX_SNIPPETS]
        if not query or not snippets:
            return {"status": "error", "error": "query and snippets are required"}

        model = self._load_binseek()
        corpus = [str(entry.get("code", ""))[:MAX_ASM_CHARS] for entry in snippets]
        query_embedding = model.encode([query], normalize_embeddings=True)
        corpus_embeddings = model.encode(corpus, normalize_embeddings=True)
        scores = (query_embedding @ corpus_embeddings.T).squeeze(0).tolist()

        ranked = []
        for entry, score in zip(snippets, scores):
            ranked.append({
                "ref": entry.get("ref", ""),
                "score": float(score),
                "name": entry.get("name", ""),
            })
        ranked.sort(key=lambda entry: entry["score"], reverse=True)
        return {
            "status": "ok",
            "model": "binseek",
            "device": str(model.device),
            "ranked": ranked,
            "note": "cosine similarities against the query; attach xrefs and sizes and verify before acting",
        }

    def embed(self, request: dict[str, Any]) -> dict[str, Any]:
        """Raw normalized embeddings for the campaign knowledge index —
        rank_pseudocode ranks inline; this command powers persistent,
        incrementally-built vector stores (knowledge_index/query)."""
        texts = [str(t)[:MAX_ASM_CHARS] for t in request.get("texts", [])][:64]
        if not texts:
            return {"status": "error", "error": "texts is required"}
        model = self._load_binseek()
        embeddings = model.encode(texts, normalize_embeddings=True).tolist()
        return {"status": "ok", "model": "binseek", "device": str(model.device), "embeddings": embeddings}

    def shutdown(self, _: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "bye": True}


def _cuda_available() -> bool:
    try:
        import torch  # noqa: PLC0415

        return bool(torch.cuda.is_available())
    except Exception:  # noqa: BLE001
        return False


HANDLERS = {
    "ping": Sidecar.ping,
    "rank_assembly": Sidecar.rank_assembly,
    "rank_pseudocode": Sidecar.rank_pseudocode,
    "embed": Sidecar.embed,
    "shutdown": Sidecar.shutdown,
}


def main() -> int:
    sidecar = Sidecar()
    # Emit a ready line so the Node side can wait for boot.
    sys.stdout.write(json.dumps({"status": "ready", "modelsDir": MODELS_DIR}) + "\n")
    sys.stdout.flush()

    # Idle self-exit (C8): a loaded model parked in VRAM with no requests is
    # a leak the owner measured at ~1.8 GB for hours. A daemon watchdog
    # process-kills the sidecar after the idle window; every accepted request
    # line resets it (a long inference is "active", the budget starts over
    # when the response is emitted).
    idle_timeout = float(os.environ.get("MINUSONE_MODELS_IDLE_SECONDS", "900"))
    last_activity = time.monotonic()

    def watchdog() -> None:
        nonlocal last_activity
        while True:
            time.sleep(5)
            if time.monotonic() - last_activity > idle_timeout:
                sys.stderr.write(f"models sidecar: idle {idle_timeout:.0f}s without requests, exiting\n")
                sys.stderr.flush()
                os._exit(0)

    threading.Thread(target=watchdog, daemon=True).start()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        last_activity = time.monotonic()
        try:
            request = json.loads(line)
        except json.JSONDecodeError as error:
            response = {"status": "error", "error": f"invalid JSON: {error}"}
        else:
            command = str(request.get("command", ""))
            handler = HANDLERS.get(command)
            if handler is None:
                response = {"status": "error", "error": f"unknown command {command!r}"}
            else:
                try:
                    response = handler(sidecar, request)
                except Exception as error:  # noqa: BLE001 - one bad request must not kill the sidecar
                    response = {
                        "status": "error",
                        "error": f"{type(error).__name__}: {error}",
                        "traceback": traceback.format_exc(limit=4),
                    }
            # Echo the request id so the caller can match responses to
            # requests on the shared stream.
            if "id" in request:
                response["id"] = request["id"]
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        last_activity = time.monotonic()
        if response.get("bye") is True:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
