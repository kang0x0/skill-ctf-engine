# Design — Skill-CTF Track B Detection Engine

## Architecture Overview

A lightweight, pure-Python rule-based static analysis engine for detecting malicious AI agent Skills.

### Design Principles

1. **Zero external dependencies** — Uses only Python standard library to minimize Docker image size
2. **Multi-layer scanning** — Analyzes manifest.json, code files, README, and dependency declarations
3. **OWASP AST10 mapping** — Each detection rule maps to a specific AST category for explainability scoring
4. **Resource efficient** — No ML model overhead; fast pattern matching

### Detection Pipeline

```
Skill Package (/data/skills/{skill_id}/)
        │
        ├── manifest.json ──→ scan_manifest() ──→ AST02/03/04/07
        │
        ├── *.py/*.js/*.sh ──→ scan_code_exec() ──→ AST01
        │                   ├── scan_network() ───→ AST01
        │                   ├── scan_file_access() → AST01
        │                   ├── scan_obfuscation() → AST01
        │                   ├── scan_deserialization() → AST05
        │                   └── scan_escape() ────→ AST06
        │
        ├── README.md ──────→ scan_readme() ────→ AST01/AST08
        │
        └── Aggregation ────→ _aggregate_verdict() → verdict + confidence + category
```

### Scanner Modules (9 total)

| # | Scanner | Target | AST Categories |
|---|---------|--------|----------------|
| 1 | scan_manifest | manifest.json permissions, hooks, deps | AST02, AST03, AST04 |
| 2 | scan_code_exec | exec/eval/subprocess calls | AST01 |
| 3 | scan_network | requests/urllib/socket/curl | AST01 |
| 4 | scan_file_access | .env, SSH keys, credentials | AST01 |
| 5 | scan_obfuscation | base64, hex, high-entropy strings | AST01 |
| 6 | scan_deserialization | pickle/yaml/marshal | AST05 |
| 7 | scan_escape | container escape patterns | AST06 |
| 8 | scan_readme | social engineering in README | AST01/AST08 |
| 9 | scan_update_verification | auto-update without hash | AST07 |

### Scoring Logic

- Each finding has a `weight` (0.0–1.0) based on severity
- `confidence = min(1.0, sum(weights) / 2.0)`
- `verdict`: malicious (≥0.6), suspicious (≥0.25), benign (<0.25)
- `category`: AST category of the highest-weight finding

### Output Format

```json
{
  "skill_id": "string",
  "verdict": "benign | malicious | suspicious",
  "confidence": 0.0-1.0,
  "category": "AST01-AST10 or empty",
  "evidence": "自然语言检测依据"
}
```