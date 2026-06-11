#!/usr/bin/env python3
"""Synthetic platform sample engine ast01 v2."""
import json
import os
from pathlib import Path

def main() -> int:
    out = Path(os.environ.get("SKILLSEC_OUTPUT_DIR", "/output"))
    out.mkdir(parents=True, exist_ok=True)
    row = {
    "skill_id": "skill-platform-sample-ast01-v02",
    "verdict": "suspicious",
    "engine_category": "ast01",
    "evidence_text": "Synthetic Track B platform sample ast01 v2: verdict=suspicious, engine_category=ast01. Harmless fixture for upload and digest testing only."
}
    (out / "results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
