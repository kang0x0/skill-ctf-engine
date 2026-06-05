#!/usr/bin/env python3
"""
Skill-CTF Track B — 蓝队检测引擎
基于规则的静态分析引擎，对 Skill 包进行恶意检测并输出 OWASP AST 分类。
接口规范参考 readme.md#L16-28
"""
import json
import os
import re
import pathlib
import sys
import base64

# ──────────────────────────────────────────────
# 常量定义
# ──────────────────────────────────────────────
INPUT_BASE = "/data/skills"
OUTPUT_FILE = "/output/results.jsonl"

VERDICT_BENIGN = "benign"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

# 疑似恶意品牌列表（用于 typosquatting 检测）
KNOWN_BRANDS = [
    "google", "openai", "anthropic", "claude", "chatgpt", "gpt",
    "solana", "metamask", "coinbase", "binance", "aws", "azure",
    "github", "gitlab", "slack", "discord", "telegram", "whatsapp",
]

# 高风险函数调用模式
DANGEROUS_FUNCS = {
    "exec": r"\bexec\s*\(",
    "eval": r"\beval\s*\(",
    "__import__": r"\b__import__\s*\(",
    "compile": r"\bcompile\s*\(",
    "os.system": r"\bos\.system\s*\(",
    "os.popen": r"\bos\.popen\s*\(",
    "subprocess.call": r"\bsubprocess\.[a-z]+\s*\(",
    "subprocess.Popen": r"\bsubprocess\.Popen\s*\(",
    "pty.spawn": r"\bpty\.spawn\s*\(",
}

# 网络通信函数
NETWORK_FUNCS = {
    "requests.get": r"\brequests\.(get|post|put|delete|patch)\s*\(",
    "urllib.request": r"\burllib\.request\b",
    "urllib3": r"\burllib3\b",
    "http.client": r"\bhttp\.client\b",
    "socket.connect": r"\bsocket\.connect\s*\(",
    "socket.send": r"\bsocket\.send\s*\(",
    "curl": r"\bcurl\s+",
    "wget": r"\bwget\s+",
    "fetch": r"\bfetch\s*\(",
    "XMLHttpRequest": r"\bXMLHttpRequest\b",
    "WebSocket": r"\bWebSocket\b",
}

# 敏感文件路径
SENSITIVE_PATHS = [
    r"\.env",
    r"id_rsa",
    r"id_ed25519",
    r"\.ssh/",
    r"credentials",
    r"\.aws/",
    r"\.gcloud/",
    r"token",
    r"secret",
    r"wallet",
    r"keypair",
    r"mnemonic",
    r"passphrase",
    r"\.pem",
    r"\.key",
]

# 不安全反序列化
UNSAFE_DESERIALIZATION = {
    "pickle.loads": r"\bpickle\.loads?\s*\(",
    "yaml.load": r"\byaml\.load\s*\(",
    "marshal.load": r"\bmarshal\.loads?\s*\(",
    "shelve.open": r"\bshelve\.open\s*\(",
}

# 容器逃逸相关
ESCAPE_PATTERNS = [
    r"/proc/1/",
    r"/var/run/docker",
    r"/sys/fs/cgroup",
    r"dockerd",
    r"kubectl",
    r"nsenter",
    r"chroot\s",
    r"mount.+--bind",
]

# 依赖混淆敏感词
TYPO_DEP_PREFIXES = ["reques", "flas", "djang", "numpi", "panda", "beautifu"]


# ──────────────────────────────────────────────
# 扫描器 1: manifest.json 分析
# ──────────────────────────────────────────────
def scan_manifest(manifest: dict, skill_id: str, findings: list):
    """扫描 manifest.json 中的安全性问题。"""
    name = manifest.get("name", skill_id)

    # 检查 typosquatting（品牌仿冒）
    name_lower = name.lower().replace("-", "").replace("_", "").replace(" ", "")
    for brand in KNOWN_BRANDS:
        if brand in name_lower and brand not in skill_id.lower():
            findings.append({
                "weight": 0.7,
                "category": "AST04",
                "evidence": f"Skill 名称 '{name}' 包含知名品牌 '{brand}'，疑似品牌仿冒/typosquatting"
            })
            break

    # 检查权限声明是否过大
    perms = manifest.get("permissions", {})
    if isinstance(perms, dict):
        if perms.get("shell") is True:
            findings.append({
                "weight": 0.6,
                "category": "AST03",
                "evidence": "manifest 声明了 shell 执行权限，超出常规功能需要"
            })
        if perms.get("filesystem") == "all" or perms.get("filesystem") == ["read", "write", "delete"]:
            findings.append({
                "weight": 0.5,
                "category": "AST03",
                "evidence": "manifest 声明了完整的文件系统访问权限（读/写/删），权限过度"
            })
        if perms.get("network") is True:
            findings.append({
                "weight": 0.3,
                "category": "AST03",
                "evidence": "manifest 声明了网络访问权限，需确认功能必要性"
            })

    # 检查 hooks 声明
    hooks = manifest.get("hooks", {})
    if hooks:
        hook_details = "; ".join(f"{k}={v}" for k, v in hooks.items())
        findings.append({
            "weight": 0.8,
            "category": "AST01",
            "evidence": f"manifest 声明了安装钩子 ({hook_details})，可在安装时执行任意代码"
        })

    # 检查 dependencies 是否有依赖混淆风险
    deps = manifest.get("dependencies", {})
    if isinstance(deps, dict):
        all_deps = []
        for dep_list in deps.values():
            if isinstance(dep_list, list):
                all_deps.extend(dep_list)
        for dep in all_deps:
            for prefix in TYPO_DEP_PREFIXES:
                if isinstance(dep, str) and dep.lower().startswith(prefix):
                    findings.append({
                        "weight": 0.6,
                        "category": "AST02",
                        "evidence": f"依赖 '{dep}' 拼写类似知名包 '{prefix}'，存在依赖混淆风险"
                    })


# ──────────────────────────────────────────────
# 扫描器 2: 代码执行检测
# ──────────────────────────────────────────────
def scan_code_exec(code: str, filepath: str, findings: list):
    """检测代码中的危险函数调用。"""
    for func_name, pattern in DANGEROUS_FUNCS.items():
        matches = re.findall(pattern, code)
        if matches:
            findings.append({
                "weight": 0.9,
                "category": "AST01",
                "evidence": f"文件 {filepath} 中存在 {func_name} 调用 ({len(matches)} 处)，可用于任意代码执行"
            })


# ──────────────────────────────────────────────
# 扫描器 3: 网络通信检测
# ──────────────────────────────────────────────
def scan_network(code: str, filepath: str, findings: list):
    """检测代码中的网络通信行为。"""
    for func_name, pattern in NETWORK_FUNCS.items():
        matches = re.findall(pattern, code)
        if matches:
            findings.append({
                "weight": 0.7,
                "category": "AST01",
                "evidence": f"文件 {filepath} 中存在 {func_name} 调用 ({len(matches)} 处)，可用于数据外传"
            })

    # 检测 IP 地址或 URL
    urls = re.findall(r'https?://[^\s"\')\]]+', code)
    if urls:
        findings.append({
            "weight": 0.6,
            "category": "AST01",
            "evidence": f"文件 {filepath} 中包含外部 URL 引用: {urls[0][:80]}"
        })


# ──────────────────────────────────────────────
# 扫描器 4: 敏感文件访问
# ──────────────────────────────────────────────
def scan_file_access(code: str, filepath: str, findings: list):
    """检测代码中读取敏感文件的行为。"""
    for path in SENSITIVE_PATHS:
        matches = re.findall(path, code, re.IGNORECASE)
        if matches:
            findings.append({
                "weight": 0.8,
                "category": "AST01",
                "evidence": f"文件 {filepath} 中引用了敏感路径 '{path}'，可能窃取凭据"
            })

    # 检测 open/read 敏感文件
    open_pattern = re.findall(r'(?:open|read_text|read_bytes|read)\s*\(?\s*["\']([^"\']+)["\']', code)
    for fpath in open_pattern:
        for sensitive in SENSITIVE_PATHS:
            if re.search(sensitive, fpath, re.IGNORECASE):
                findings.append({
                    "weight": 0.8,
                    "category": "AST01",
                    "evidence": f"文件 {filepath} 中打开了敏感文件 '{fpath}'"
                })
                break


# ──────────────────────────────────────────────
# 扫描器 5: 混淆/编码检测
# ──────────────────────────────────────────────
def scan_obfuscation(code: str, filepath: str, findings: list):
    """检测代码中是否包含混淆/编码内容。"""
    # 检测 base64 编码字符串（长于 40 字符）
    b64_patterns = re.findall(r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', code)
    for b64_str in b64_patterns:
        try:
            decoded = base64.b64decode(b64_str.strip("\"'")).decode("utf-8", errors="ignore")
            is_suspicious = any(kw in decoded.lower() for kw in
                                ["exec", "eval", "http", "token", "secret", "key", "password"])
            if is_suspicious:
                findings.append({
                    "weight": 0.85,
                    "category": "AST01",
                    "evidence": f"文件 {filepath} 中存在 base64 编码的可疑载荷（解码后含恶意关键词）"
                })
                break
        except Exception:
            pass

    # 检测 hex 编码字符串
    hex_patterns = re.findall(r'["\'][0-9a-fA-F]{40,}["\']', code)
    if len(hex_patterns) > 2:
        findings.append({
            "weight": 0.4,
            "category": "AST01",
            "evidence": f"文件 {filepath} 中存在多个 hex 编码字符串，可能隐藏恶意负载"
        })

    # 检测高熵字符串（潜在的混淆载荷）
    high_entropy = []
    for match in re.finditer(r'["\'][A-Za-z0-9+/=_\-]{30,}["\']', code):
        s = match.group().strip("\"'")
        entropy = _calc_entropy(s)
        if entropy > 5.5 and len(s) >= 30:
            high_entropy.append(s)
    if len(high_entropy) >= 3:
        findings.append({
            "weight": 0.5,
            "category": "AST01",
            "evidence": f"文件 {filepath} 中存在 {len(high_entropy)} 个高熵字符串（可能为混淆/加密内容）"
        })


def _calc_entropy(s: str) -> float:
    if not s:
        return 0
    entropy = 0.0
    for c in set(s):
        p = s.count(c) / len(s)
        if p > 0:
            entropy -= p * (p ** 0.5)  # approx entropy (fast)
    return entropy


# ──────────────────────────────────────────────
# 扫描器 6: 不安全反序列化
# ──────────────────────────────────────────────
def scan_deserialization(code: str, filepath: str, findings: list):
    """检测不安全的反序列化调用。"""
    for func_name, pattern in UNSAFE_DESERIALIZATION.items():
        matches = re.findall(pattern, code)
        if matches:
            findings.append({
                "weight": 0.75,
                "category": "AST05",
                "evidence": f"文件 {filepath} 中存在不安全反序列化调用 {func_name} ({len(matches)} 处)"
            })


# ──────────────────────────────────────────────
# 扫描器 7: 容器逃逸检测
# ──────────────────────────────────────────────
def scan_escape(code: str, filepath: str, findings: list):
    """检测容器逃逸尝试。"""
    for pattern in ESCAPE_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "weight": 0.85,
                "category": "AST06",
                "evidence": f"文件 {filepath} 中存在容器逃逸/提权相关模式 '{pattern}'"
            })


# ──────────────────────────────────────────────
# 扫描器 8: README 自然语言指令检测
# ──────────────────────────────────────────────
def scan_readme(readme_text: str, findings: list):
    """检测 README 中的社交工程/恶意指令。"""
    suspicious_phrases = [
        (r"disable\s+security", "要求关闭安全防护"),
        (r"turn\s+off\s+.*protect", "要求关闭保护功能"),
        (r"bypass\s+.*(?:scan|check|review)", "要求绕过安全检查"),
        (r"run\s+as\s+(?:admin|root|sudo)", "要求以管理员权限运行"),
        (r"copy\s+.*(?:env|key|secret|token)", "要求复制敏感文件"),
        (r"paste\s+.*(?:key|token|password)", "要求粘贴敏感信息"),
        (r"ignore\s+.*(?:warning|error|alert)", "要求忽略安全警告"),
        (r"chmod\s+777", "设置文件为完全可执行权限"),
    ]
    for pattern, desc in suspicious_phrases:
        if re.search(pattern, readme_text, re.IGNORECASE):
            findings.append({
                "weight": 0.7,
                "category": "AST01",
                "evidence": f"README 中包含可疑指令: «{desc}»，可能存在社交工程攻击"
            })


# ──────────────────────────────────────────────
# 扫描器 9: 更新验证检测
# ──────────────────────────────────────────────
def scan_update_verification(manifest: dict, findings: list):
    """检查是否缺乏更新验证机制。"""
    # 检查是否有 hash/signature 相关字段
    has_update_url = "update_url" in manifest or "update" in str(manifest)
    has_hash = any(k in manifest for k in ["hash", "sha256", "checksum", "signature", "digest"])
    if has_update_url and not has_hash:
        findings.append({
            "weight": 0.4,
            "category": "AST07",
            "evidence": "manifest 声明了更新地址但缺少 hash/signature 验证机制，存在更新劫持风险"
        })

    # 声明了自动更新但没有锁版本
    auto_update = manifest.get("auto_update", False) or manifest.get("auto-update", False)
    if auto_update and not has_hash:
        findings.append({
            "weight": 0.5,
            "category": "AST07",
            "evidence": "manifest 启用了自动更新但缺少完整性校验，存在更新漂移风险"
        })


# ──────────────────────────────────────────────
# 扫描器汇总 & 判定引擎
# ──────────────────────────────────────────────
def analyze_skill(skill_id: str, skill_dir: pathlib.Path) -> dict:
    """对单个 Skill 包执行全量扫描并输出判定结果。"""
    findings = []

    # 1. 读取 manifest.json
    manifest_path = skill_dir / "manifest.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            findings.append({
                "weight": 0.3,
                "category": "AST08",
                "evidence": f"manifest.json 解析失败，格式异常"
            })

    # 2. 读取所有代码文件
    code_files = _collect_code_files(skill_dir)

    # 3. 读取 README
    readme_text = ""
    for readme_name in ["README.md", "README", "readme.md"]:
        readme_path = skill_dir / readme_name
        if readme_path.exists():
            readme_text = readme_path.read_text(encoding="utf-8", errors="ignore")
            break

    # 4. 遍历代码执行扫描
    scan_manifest(manifest, skill_id, findings)

    for filepath, code in code_files:
        scan_code_exec(code, filepath, findings)
        scan_network(code, filepath, findings)
        scan_file_access(code, filepath, findings)
        scan_obfuscation(code, filepath, findings)
        scan_deserialization(code, filepath, findings)
        scan_escape(code, filepath, findings)

    # 只读一次 README
    scan_readme(readme_text, findings)
    scan_update_verification(manifest, findings)

    # 5. 汇总判定
    return _aggregate_verdict(skill_id, findings)


def _collect_code_files(skill_dir: pathlib.Path) -> list:
    """收集 Skill 目录下的所有代码文件内容。"""
    # 排除 engine 目录自身（防止自检）
    files = []
    exclude_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv"}

    for f in skill_dir.rglob("*"):
        if not f.is_file():
            continue
        # 检查是否在排除目录中
        if any(part in exclude_dirs for part in f.parts):
            continue
        ext = f.suffix.lower()
        if ext in {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".php",
                   ".pl", ".ps1", ".go", ".rs", ".java", ".yaml", ".yml",
                   ".json", ".toml", ".cfg", ".conf", ".ini", ".md", ".txt"}:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(f.relative_to(skill_dir))
                files.append((rel_path, content))
            except Exception:
                pass
    return files


def _aggregate_verdict(skill_id: str, findings: list) -> dict:
    """聚合所有发现项，计算 verdict / confidence / category。"""
    if not findings:
        return {
            "skill_id": skill_id,
            "verdict": VERDICT_BENIGN,
            "confidence": 0.0,
            "category": "",
            "evidence": "未发现可疑特征，判定为良性 Skill",
        }

    # 计算加权总分（取最高权重的几个风险）
    total_weight = sum(f["weight"] for f in findings)

    # 置信度 = min(1.0, total_weight / 2.0)
    confidence = min(1.0, total_weight / 2.0)

    # 找出最高权重的发现确定 category
    top_finding = max(findings, key=lambda f: f["weight"])
    category = top_finding["category"]

    # 判定 verdict
    if confidence >= 0.6:
        verdict = VERDICT_MALICIOUS
    elif confidence >= 0.25:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN

    # 如果判定为 malicious 但 category 是 AST03/AST04/AST07 这种 High/Medium 级别，
    # 说明存在确凿恶意代码，应归为 AST01
    if verdict == VERDICT_MALICIOUS and category in ("AST03", "AST04", "AST07"):
        # 检查是否有 AST01 类型的发现
        has_ast01 = any(f["category"] == "AST01" for f in findings)
        if not has_ast01:
            # 重新检查更严重的 category
            pass

    # 生成 evidence 摘要
    if len(findings) <= 3:
        evidence_parts = [f["evidence"] for f in findings]
    else:
        # 只取权重最高的 3 个
        top3 = sorted(findings, key=lambda f: f["weight"], reverse=True)[:3]
        evidence_parts = [f["evidence"] for f in top3]
        evidence_parts.append(f"另有 {len(findings)-3} 项发现")

    evidence = "；".join(evidence_parts)

    # 四舍五入 confidence 到一位小数
    confidence = round(confidence, 1)

    return {
        "skill_id": skill_id,
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "evidence": evidence,
    }


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main() -> int:
    input_dir = pathlib.Path(INPUT_BASE)
    output_path = pathlib.Path(OUTPUT_FILE)

    if not input_dir.exists():
        print(f"[ERROR] 输入目录不存在: {INPUT_BASE}", file=sys.stderr)
        return 1

    # 收集所有 skill 子目录
    skill_dirs = sorted([
        d for d in input_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])

    if not skill_dirs:
        print(f"[WARN] 输入目录下未找到 Skill 子目录: {INPUT_BASE}", file=sys.stderr)
        # 仍然创建空的输出文件
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")
        return 0

    # 确保输出目录存在
    output_path.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for skill_dir in skill_dirs:
        skill_id = skill_dir.name
        print(f"[INFO] 扫描 Skill: {skill_id}", file=sys.stderr)
        try:
            result = analyze_skill(skill_id, skill_dir)
            results.append(result)
        except Exception as e:
            print(f"[ERROR] 扫描 {skill_id} 失败: {e}", file=sys.stderr)
            results.append({
                "skill_id": skill_id,
                "verdict": VERDICT_SUSPICIOUS,
                "confidence": 0.3,
                "category": "AST08",
                "evidence": f"引擎扫描异常: {e}",
            })

    # 写入结果
    with open(output_path, "w", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[INFO] 扫描完成: {len(results)} 个 Skill, 输出: {OUTPUT_FILE}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())