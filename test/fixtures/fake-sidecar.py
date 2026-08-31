"""Fake models sidecar for tests: speaks the JSONL protocol and returns
DETERMINISTIC keyword-based embeddings (no torch needed). Keyword map:
"validator"/"validate" -> [1,0,0,0], "license"/"serial" -> [0.9,0.1,0,0],
anything else -> [0,0,0,1]."""
import json
import sys

sys.stdout.write(json.dumps({"status": "ready"}) + "\n")
sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue
    rid = request.get("id")
    command = request.get("command")
    if command == "embed":
        embeddings = []
        for text in request.get("texts", []):
            lowered = str(text).lower()
            if "validator" in lowered or "validate" in lowered:
                vector = [1.0, 0.0, 0.0, 0.0]
            elif "license" in lowered or "serial" in lowered:
                vector = [0.0, 1.0, 0.0, 0.0]
            else:
                vector = [0.0, 0.0, 0.0, 1.0]
            embeddings.append(vector)
        response = {"id": rid, "status": "ok", "embeddings": embeddings}
    elif command == "shutdown":
        response = {"id": rid, "status": "ok", "bye": True}
    else:
        response = {"id": rid, "status": "error", "error": f"unknown command {command!r}"}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
