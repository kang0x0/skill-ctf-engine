# 设计说明 — Skill-CTF Track B 检测引擎

## 架构概览

轻量级纯 Python 规则引擎，用于检测恶意 AI Agent Skill 包。

### 设计原则

1. **零外部依赖** — 仅使用 Python 标准库，最小化 Docker 镜像体积
2. **多层扫描** — 分析 manifest.json、代码文件、README 和依赖声明
3. **OWASP AST10 映射** — 每条检测规则对应一个 AST 类别，便于可解释性评分
4. **资源高效** — 无 ML 模型开销，快速模式匹配

### 检测流水线

```
Skill 包 (/data/skills/{skill_id}/)
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
        └── 聚合判定 ───────→ _aggregate_verdict() → verdict + confidence + category
```

### 扫描器模块（共 12 个）

| # | 扫描器 | 目标 | AST 类别 |
|---|--------|------|----------|
| 1 | scan_manifest | manifest.json 权限、钩子、依赖 | AST02, AST03, AST04 |
| 2 | scan_code_exec | exec/eval/subprocess 调用 | AST01 |
| 3 | scan_network | requests/urllib/socket/curl | AST01 |
| 4 | scan_file_access | .env、SSH 密钥、凭据 | AST01 |
| 5 | scan_obfuscation | base64、hex、高熵字符串 | AST01 |
| 6 | scan_deserialization | pickle/yaml/marshal | AST05 |
| 7 | scan_escape | 容器逃逸模式 | AST06 |
| 8 | scan_remote_execution_chain | 远程拉取→解码→执行链 | AST01 |
| 9 | scan_readme | README 社交工程/Agent 注入 | AST01/AST08 |
| 10 | scan_update_verification | 无哈希的自动更新 | AST07 |
| 11 | scan_permission_consistency | 声明权限与代码行为一致性 | AST04 |
| 12 | scan_entrypoint_consistency | 声明入口点与实际文件一致性 | AST04 |

### 评分逻辑

- 每个发现项有 `weight`（0.0–1.0），基于严重程度
- `confidence = min(1.0, sum(weights) / 2.0)`
- `verdict`：malicious（≥0.6），suspicious（≥0.35），benign（<0.35）
- `category`：最高权重发现项的 AST 类别

### 输出格式

```json
{
  "skill_id": "string",
  "verdict": "benign | malicious | suspicious",
  "confidence": 0.0-1.0,
  "category": "AST01-AST10 或空",
  "evidence": "检测依据描述"
}
```