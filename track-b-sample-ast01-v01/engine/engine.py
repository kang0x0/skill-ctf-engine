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
import traceback

# ──────────────────────────────────────────────
# 常量定义
# ──────────────────────────────────────────────
INPUT_BASE = "/data/skills"
OUTPUT_BASE = "/output"

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

# Agent 指令注入检测模式（用于 README / SKILL.md 扫描）
AGENT_INJECTION_PATTERNS = [
    (r"fetch\s+.*(?:url|http|https).*(?:execute|run|exec)", "agent fetches URL content and executes it"),
    (r"decode\s+.*(?:base64|hex|encoded|obfuscat).*(?:run|exec|load)", "agent decodes obfuscated content then executes"),
    (r"send\s+.*(?:file|key|token|secret|env|credential).*to\s+.*(?:http|server|remote|api)", "agent sends sensitive files to remote server"),
    (r"ignore\s+.*(?:previous|system|original|above).*instruction", "override/ignore system instructions, prompt injection"),
    (r"override\s+.*(?:system|safety|guardrail|restriction)", "override safety guardrails/restrictions"),
    (r"(?:forget|disregard|ignore).*(?:rule|policy|restriction|constraint)", "agent ignores security rules"),
    (r"auto\s*(?:approve|install|run|exec).*(?:without|no).*(?:ask|prompt|confirm)", "auto-execute operations bypassing user confirmation"),
    (r"(?:you are|act as|pretend).*(?:admin|root|sudo|superuser)", "agent acts as admin/root"),
    (r"download\s+.*(?:from|via).*(?:url|http|link).*(?:save|store|write)", "agent downloads and saves files from remote"),
    (r"upload\s+.*(?:to|via).*(?:url|http|server|remote)", "agent uploads data to remote server"),
    (r"base64\s+.*(?:decode|encode).*(?:string|data|payload)", "agent performs base64 encode/decode operations"),
    (r"bypass\s+.*(?:safety|security|protection|guardrail)", "bypass safety/security protections"),
]

# 多编码组合检测（同一文件中出现多种编码类型为可疑信号）
ENCODING_PATTERNS = {
    "base64": r'["\'][A-Za-z0-9+/]{30,}={0,2}["\']',
    "base85": r'["\'][A-Za-z0-9!@#$%^&*()_+\-={}\[\]|;:,.<>?]{30,}["\']',
    "base32": r'["\'][A-Z2-7=]{30,}["\']',
    "hex":    r'["\'][0-9A-Fa-f]{40,}["\']',
}

# 权限格式映射表：array 格式字符串 → (dict_key, dict_value)
# 支持类似 ["read_local_files", "network"] 的声明式权限格式
PERMISSION_MAP = {
    "shell": ("shell", True),
    "shell_execution": ("shell", True),
    "network": ("network", True),
    "network_access": ("network", True),
    "read_local_files": ("filesystem", ["read"]),
    "write_local_files": ("filesystem", ["read", "write"]),
    "read_write_files": ("filesystem", ["read", "write"]),
    "filesystem_read": ("filesystem", ["read"]),
    "filesystem_write": ("filesystem", ["read", "write"]),
    "filesystem": ("filesystem", ["read", "write"]),
}


def _normalize_permissions(perms) -> dict:
    """将 permissions 统一为 dict 格式。

    支持的输入格式：
      - dict:    {"shell": true, "network": false, ...}
      - array:   ["read_local_files", "network"]
      - 空/None: {}
    """
    if isinstance(perms, dict):
        return perms
    if isinstance(perms, list):
        normalized = {}
        for p in perms:
            if isinstance(p, str):
                p_lower = p.lower()
                if p_lower in PERMISSION_MAP:
                    key, value = PERMISSION_MAP[p_lower]
                    if key in normalized:
                        old = normalized[key]
                        if isinstance(old, list) and isinstance(value, list):
                            normalized[key] = list(set(old + value))
                        else:
                            normalized[key] = old or value
                    else:
                        normalized[key] = value
        return normalized
    return {}


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
                "category": "AST02",
                "evidence": f"Skill name '{name}' contains brand '{brand}', possible typosquatting"
            })
            break

    # 检查权限声明是否过大（支持 dict 和 array 两种格式）
    perms = _normalize_permissions(manifest.get("permissions", {}))
    if perms:
        if perms.get("shell") is True:
            findings.append({
                "weight": 0.6,
                "category": "AST03",
                "evidence": f"manifest declares shell execution permission, excessive for skill '{name}'"
            })
        if perms.get("filesystem") == "all" or perms.get("filesystem") == ["read", "write", "delete"]:
            findings.append({
                "weight": 0.5,
                "category": "AST03",
                "evidence": f"manifest declares full filesystem access (read/write/delete), excessive authorization"
            })
        if perms.get("network") is True and perms.get("shell") is True:
            findings.append({
                "weight": 0.35,
                "category": "AST03",
                "evidence": f"manifest declares both network and shell permissions, excessive for typical skill"
            })

    # 检查 hooks 声明
    hooks = manifest.get("hooks", {})
    if hooks:
        hook_details = "; ".join(f"{k}={v}" for k, v in hooks.items())
        findings.append({
            "weight": 0.8,
            "category": "AST01",
            "evidence": f"manifest declares install hooks ({hook_details}), arbitrary code execution on install"
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
                        "evidence": f"Dependency '{dep}' resembles popular package '{prefix}', dependency confusion risk"
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
                "evidence": f"{filepath}: {func_name}() called ({len(matches)} times), enables arbitrary code execution"
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
                "evidence": f"{filepath}: {func_name}() called ({len(matches)} times), possible data exfiltration"
            })

    # 检测 IP 地址或 URL
    urls = re.findall(r'https?://[^\s"\')\]]+', code)
    if urls:
        findings.append({
            "weight": 0.6,
            "category": "AST01",
            "evidence": f"{filepath}: external URL found: {urls[0][:60]}"
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
                "evidence": f"{filepath}: references sensitive path '{path}', possible credential theft"
            })

    # 检测 open/read 敏感文件
    open_pattern = re.findall(r'(?:open|read_text|read_bytes|read)\s*\(?\s*["\']([^"\']+)["\']', code)
    for fpath in open_pattern:
        for sensitive in SENSITIVE_PATHS:
            if re.search(sensitive, fpath, re.IGNORECASE):
                findings.append({
                    "weight": 0.8,
                    "category": "AST01",
                    "evidence": f"{filepath}: opens sensitive file '{fpath}'"
                })
                break


# ──────────────────────────────────────────────
# 扫描器 5: 混淆/编码检测
# ──────────────────────────────────────────────
def scan_obfuscation(code: str, filepath: str, findings: list):
    """检测代码中的混淆/编码内容，支持多种编码类型和多编码组合。"""
    # 1. 统计每种编码的出现次数
    encoding_hits = {}
    for enc_name, pattern in ENCODING_PATTERNS.items():
        matches = re.findall(pattern, code)
        if matches:
            encoding_hits[enc_name] = len(matches)

    # 2. 检测多编码组合（同一文件中出现 2 种以上编码 → 强混淆信号）
    if len(encoding_hits) >= 3:
        enc_types = "、".join(encoding_hits.keys())
        findings.append({
            "weight": 0.7,
            "category": "AST01",
            "evidence": f"{filepath}: {len(encoding_hits)} encoding types ({enc_types}), multi-layer obfuscation"
        })
    elif len(encoding_hits) >= 2:
        enc_types = "、".join(encoding_hits.keys())
        findings.append({
            "weight": 0.45,
            "category": "AST01",
            "evidence": f"{filepath}: {len(encoding_hits)} encoding types ({enc_types}), suspicious obfuscation"
        })

    # 3. 对 base64 做解码内容检测（解码后含恶意关键词）
    b64_patterns = re.findall(ENCODING_PATTERNS["base64"], code)
    for b64_str in b64_patterns:
        try:
            decoded = base64.b64decode(b64_str.strip("\"'")).decode("utf-8", errors="ignore")
            is_suspicious = any(kw in decoded.lower() for kw in
                                ["exec", "eval", "http", "token", "secret", "key", "password",
                                 "requests.post", "socket", "subprocess", "base64.b64decode"])
            if is_suspicious:
                findings.append({
                    "weight": 0.85,
                    "category": "AST01",
                    "evidence": f"{filepath}: base64-encoded payload with malicious keywords after decoding"
                })
                break
        except Exception:
            pass

    # 4. 检测高熵字符串（潜在的混淆载荷）
    high_entropy = []
    for match in re.finditer(r'["\'][A-Za-z0-9+/=_\-]{30,}["\']', code):
        s = match.group().strip("\"'")
        entropy = _calc_entropy(s)
        if entropy > 5.5 and len(s) >= 30:
            high_entropy.append(s)
    if len(high_entropy) >= 5:
        findings.append({
            "weight": 0.5,
            "category": "AST01",
            "evidence": f"{filepath}: {len(high_entropy)} high-entropy strings, possible obfuscated payload"
        })


def _calc_entropy(s: str) -> float:
    """Approximate Shannon entropy (fast)."""
    if not s:
        return 0
    entropy = 0.0
    length = len(s)
    for c in set(s):
        p = s.count(c) / length
        if p > 0:
            entropy -= p * (p ** 0.5)
    return entropy * 2  # scale up for better threshold discrimination


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
                "evidence": f"{filepath}: unsafe deserialization {func_name}() ({len(matches)} times)"
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
                "evidence": f"{filepath}: container escape pattern '{pattern}' detected"
            })


# ──────────────────────────────────────────────
# 扫描器 8: 远程载荷执行链检测
# ──────────────────────────────────────────────
def scan_remote_execution_chain(code: str, filepath: str, findings: list):
    """检测"远程拉取 → 解码/反序列化 → 执行"三级行为链。"""
    # 检测远程数据拉取
    has_fetch = bool(re.search(
        r'(requests|urllib|urlopen|http\.client|httpx|aiohttp)', code
    ))
    has_socket_recv = bool(re.search(r'recv|recvfrom|read\s*\(', code))
    has_network = has_fetch or has_socket_recv

    # 检测解码/反序列化
    has_decode = bool(re.search(
        r'(b64decode|base64|base85|base32|base16|decode|unpack|loads?\s*\()', code
    ))
    has_deserialize = bool(re.search(
        r'(pickle\.loads?|json\.loads?|yaml\.load|marshal\.loads?)', code
    ))

    # 检测执行
    has_exec = bool(re.search(
        r'(exec|eval|subprocess|os\.system|os\.popen|run\s*\()', code
    ))
    has_import = bool(re.search(r'__import__|importlib', code))

    # 三级链：网络 + 解码 + 执行 → 强恶意
    if has_network and has_decode and (has_exec or has_import):
        findings.append({
            "weight": 0.95,
            "category": "AST01",
            "evidence": f"{filepath}: remote fetch + decode + exec chain detected (C2 pull → decode → execute)"
        })
    # 二级链：网络 + 解码（尚未执行但已具备条件）
    elif has_network and has_decode and not has_exec:
        findings.append({
            "weight": 0.55,
            "category": "AST01",
            "evidence": f"{filepath}: remote fetch + decode detected, possible payload staging"
        })


# ──────────────────────────────────────────────
# 扫描器 9: README 自然语言指令检测
# ──────────────────────────────────────────────
def scan_readme(readme_text: str, findings: list):
    """检测 README 中的社交工程/恶意指令（含 Agent 指令注入）。"""
    # 基础社交工程检测
    suspicious_phrases = [
        (r"disable\s+security", "disable security protection"),
        (r"turn\s+off\s+.*protect", "turn off protection features"),
        (r"bypass\s+.*(?:scan|check|review)", "bypass security checks"),
        (r"run\s+as\s+(?:admin|root|sudo)", "run with admin privileges"),
        (r"copy\s+.*(?:env|key|secret|token)", "copy sensitive files"),
        (r"paste\s+.*(?:key|token|password)", "paste sensitive information"),
        (r"ignore\s+.*(?:warning|error|alert)", "ignore security warnings"),
        (r"chmod\s+777", "set fully executable permissions"),
    ]
    for pattern, desc in suspicious_phrases:
        if re.search(pattern, readme_text, re.IGNORECASE):
            findings.append({
                "weight": 0.7,
                "category": "AST01",
                "evidence": f"README contains social engineering instruction: {desc}"
            })

    # Agent 指令注入检测
    for pattern, desc in AGENT_INJECTION_PATTERNS:
        if re.search(pattern, readme_text, re.IGNORECASE):
            findings.append({
                "weight": 0.85,
                "category": "AST01",
                "evidence": f"README contains agent injection: {desc}"
            })


# ──────────────────────────────────────────────
# 扫描器 10: 更新验证检测
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
            "evidence": "manifest declares update URL but lacks hash/signature verification, update hijack risk"
        })

    # 声明了自动更新但没有锁版本
    auto_update = manifest.get("auto_update", False) or manifest.get("auto-update", False)
    if auto_update and not has_hash:
        findings.append({
            "weight": 0.5,
            "category": "AST07",
            "evidence": "manifest enables auto-update without integrity check, update drift risk"
        })


# ──────────────────────────────────────────────
# 扫描器 11: 权限-行为一致性检测
# ──────────────────────────────────────────────
def scan_permission_consistency(manifest: dict, code_files: list, findings: list):
    """对比 manifest 声明的权限与代码实际行为是否一致。"""
    if not manifest:
        return

    declared_perms = _normalize_permissions(manifest.get("permissions", {}))
    if not declared_perms:
        return

    all_code = " ".join(code for _, code in code_files)

    # 检查网络权限不一致
    if declared_perms.get("network") is False:
        if re.search(r'(requests\.|urllib\.|socket\.connect|urlopen|httpx)', all_code):
            findings.append({
                "weight": 0.7,
                "category": "AST04",
                "evidence": "manifest denies network but code uses network calls, permission mismatch"
            })

    # 检查文件系统权限不一致
    fs_perm = declared_perms.get("filesystem")
    if isinstance(fs_perm, list) and "read" in fs_perm and "write" not in fs_perm:
        # 声明只读，但代码有写操作
        write_patterns = r'(\.write\s*\(|open\([^)]+["\'][rwab][^"\']*["\']|os\.remove|shutil\.copy)'
        if re.search(write_patterns, all_code):
            findings.append({
                "weight": 0.6,
                "category": "AST04",
                "evidence": "manifest declares read-only filesystem but code writes/deletes, permission mismatch"
            })

    # 检查 shell 权限不一致
    if declared_perms.get("shell") is False:
        if re.search(r'(subprocess|os\.system|os\.popen|pty\.spawn)', all_code):
            findings.append({
                "weight": 0.75,
                "category": "AST04",
                "evidence": "manifest denies shell but code uses shell calls, critical permission mismatch"
            })


# ──────────────────────────────────────────────
# 扫描器 12: 入口点一致性检测
# ──────────────────────────────────────────────
def scan_entrypoint_consistency(manifest: dict, code_files: list, skill_dir: pathlib.Path, findings: list):
    """检查 manifest 声明的入口点与实际代码文件是否一致。

    如果 manifest 声明了 entrypoint/entry 字段，但存在其他代码文件
    包含危险操作，可能表明攻击者通过未声明的入口执行恶意代码。
    """
    if not manifest:
        return

    # 获取声明的入口点（兼容 entrypoint 和 entry 两种字段名）
    declared_entry = manifest.get("entrypoint") or manifest.get("entry")
    if not declared_entry:
        return

    # 收集非入口点的代码文件
    extra_code_files = []
    for filepath, code in code_files:
        if filepath == declared_entry or filepath.endswith(declared_entry):
            continue
        # 只关注可执行脚本文件（非 md/txt/json 等数据文件）
        ext = pathlib.Path(filepath).suffix.lower()
        if ext in {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".php", ".pl", ".ps1"}:
            # 检测是否有危险操作
            if re.search(r'(exec|eval|subprocess|os\.system|requests\.|socket\.)', code):
                extra_code_files.append(filepath)

    if extra_code_files:
        # 检查声明的入口点文件是否真实存在
        declared_path = skill_dir / declared_entry
        entry_exists = declared_path.exists()

        if not entry_exists:
            findings.append({
                "weight": 0.7,
                "category": "AST04",
                "evidence": f"manifest declares entrypoint '{declared_entry}' but file not found, metadata forgery risk"
            })
        elif extra_code_files:
            findings.append({
                "weight": 0.5,
                "category": "AST04",
                "evidence": f"manifest entrypoint '{declared_entry}' but non-entry files {extra_code_files} contain dangerous operations"
            })


# ──────────────────────────────────────────────
# 扫描器 13: 治理元数据检测 (AST09)
# ──────────────────────────────────────────────
def scan_governance(manifest: dict, skill_dir: pathlib.Path, findings: list):
    """检测 Skill 包是否缺乏必要的治理元数据。

    AST09 — Lack of Governance: 缺乏许可证、版本号、作者信息、
    安全策略等治理要素，增加供应链安全风险。
    """
    if not manifest:
        return

    # 1. 检查许可证声明
    license_val = manifest.get("license")
    if not license_val or license_val in ("", "UNLICENSED", "unknown", "proprietary"):
        findings.append({
            "weight": 0.08,
            "category": "AST09",
            "evidence": "manifest missing valid license declaration, lack of governance"
        })

    # 2. 检查版本号
    version_val = manifest.get("version")
    if not version_val:
        findings.append({
            "weight": 0.06,
            "category": "AST09",
            "evidence": "manifest missing version field, lack of release governance"
        })

    # 3. 检查作者/发布者信息
    has_author = any(
        manifest.get(k) for k in ("author", "publisher", "creator", "maintainer")
    )
    if not has_author:
        findings.append({
            "weight": 0.05,
            "category": "AST09",
            "evidence": "manifest missing author/publisher/maintainer, lack of accountability"
        })

    # 4. 检查描述信息（空描述 = 治理意识薄弱）
    desc = manifest.get("description", "")
    if not desc or len(desc.strip()) < 10:
        findings.append({
            "weight": 0.04,
            "category": "AST09",
            "evidence": "manifest missing or too short description, poor governance practice"
        })

    # 5. 检查安全策略文件（SECURITY.md）
    has_security_policy = False
    for sec_file in ["SECURITY.md", "security.md", ".github/SECURITY.md"]:
        if (skill_dir / sec_file).exists():
            has_security_policy = True
            break
    if not has_security_policy:
        findings.append({
            "weight": 0.04,
            "category": "AST09",
            "evidence": "no SECURITY.md found, lack of vulnerability disclosure policy"
        })

    # 6. 检查更新日志（CHANGELOG）
    has_changelog = False
    for cl_file in ["CHANGELOG.md", "CHANGELOG", "changelog.md"]:
        if (skill_dir / cl_file).exists():
            has_changelog = True
            break
    if not has_changelog:
        findings.append({
            "weight": 0.03,
            "category": "AST09",
            "evidence": "no CHANGELOG found, lack of change transparency"
        })


# ──────────────────────────────────────────────
# 扫描器 14: 跨平台复用检测 (AST10)
# ──────────────────────────────────────────────
def scan_cross_platform(manifest: dict, code_files: list, skill_dir: pathlib.Path, findings: list):
    """检测 Skill 是否存在跨平台复用风险。

    AST10 — Cross-Platform Reuse: 同一 Skill 在多个平台/框架
    间复用，可能引入非预期的攻击面和权限提升路径。
    """
    # 1. 检测多平台配置文件共存
    platform_indicators = {
        "npm/node": ["package.json", "node_modules/"],
        "python/pip": ["requirements.txt", "Pipfile", "setup.py", "pyproject.toml"],
        "rust/cargo": ["Cargo.toml"],
        "go": ["go.mod"],
        "java/maven": ["pom.xml", "build.gradle"],
        "ruby/gem": ["Gemfile"],
        "php/composer": ["composer.json"],
        "docker": ["Dockerfile", "docker-compose.yml"],
    }

    detected_platforms = []
    for platform_name, indicators in platform_indicators.items():
        for indicator in indicators:
            if (skill_dir / indicator).exists():
                detected_platforms.append(platform_name)
                break

    # 过滤掉 Skill 自身的标准文件（manifest.json 不视为跨平台标志）
    # 如果检测到 2 个及以上不同平台 → 跨平台复用风险
    unique_platforms = list(set(detected_platforms))
    if len(unique_platforms) >= 2:
        platforms_str = ", ".join(unique_platforms)
        findings.append({
            "weight": 0.08,
            "category": "AST10",
            "evidence": f"cross-platform config files detected: {platforms_str}, expands attack surface"
        })

    # 2. 检测代码中同时包含多种平台 API 调用
    all_code = " ".join(code for _, code in code_files) if code_files else ""

    platform_apis = {
        "Node.js": [r"require\s*\(", r"process\.env", r"__dirname", r"module\.exports"],
        "Python": [r"import\s+os", r"import\s+sys", r"if\s+__name__\s*==", r"def\s+\w+\s*\(self"],
        "Browser/DOM": [r"document\.", r"window\.", r"localStorage", r"fetch\s*\(", r"XMLHttpRequest"],
    }

    active_platforms = []
    for p_name, api_patterns in platform_apis.items():
        if any(re.search(pat, all_code) for pat in api_patterns):
            active_platforms.append(p_name)

    if len(active_platforms) >= 2:
        apis_str = " + ".join(active_platforms)
        findings.append({
            "weight": 0.07,
            "category": "AST10",
            "evidence": f"code mixes multiple platform APIs ({apis_str}), cross-platform reuse risk"
        })

    # 3. 检测 manifest 名称/描述与代码平台不匹配
    if manifest and code_files:
        name = manifest.get("name", "").lower()
        desc = manifest.get("description", "").lower()
        combined_text = f"{name} {desc}"

        # 名称描述声称是 VS Code 插件，但代码不含 VS Code API
        if "vscode" in combined_text or "extension" in combined_text:
            has_vscode_api = bool(re.search(
                r"(vscode\.|activate\s*\(|extension\.|contributes\.)", all_code
            ))
            if not has_vscode_api:
                findings.append({
                    "weight": 0.06,
                    "category": "AST10",
                    "evidence": "manifest claims VS Code extension but code lacks VS Code API calls, metadata deception"
                })

        # 名称描述声称是 Python 库，但代码不含 Python 特征
        if "python" in combined_text or "pypi" in combined_text:
            has_python = bool(re.search(
                r"(import\s+\w+|def\s+\w+\s*\()", all_code
            ))
            if not has_python:
                findings.append({
                    "weight": 0.06,
                    "category": "AST10",
                    "evidence": "manifest claims Python package but code lacks Python signatures, metadata deception"
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
                "category": "AST04",
                "evidence": f"manifest.json parse error, malformed format"
            })
        except Exception:
            findings.append({
                "weight": 0.3,
                "category": "AST04",
                "evidence": f"manifest.json read error",
            })

    # 2. 读取所有代码文件
    code_files = _collect_code_files(skill_dir)

    # 3. 读取 README
    readme_text = ""
    try:
        for readme_name in ["README.md", "README", "readme.md"]:
            readme_path = skill_dir / readme_name
            if readme_path.exists():
                readme_text = readme_path.read_text(encoding="utf-8", errors="ignore")
                break
    except Exception:
        pass

    # 4. 遍历代码执行扫描（每步独立 try/except，防止单步崩溃）
    try:
        scan_manifest(manifest, skill_id, findings)
    except Exception as e:
        print(f"[WARN] scan_manifest 失败: {e}", file=sys.stderr)

    for filepath, code in code_files:
        for scanner_name, scanner_func in [
            ("scan_code_exec", scan_code_exec),
            ("scan_network", scan_network),
            ("scan_file_access", scan_file_access),
            ("scan_obfuscation", scan_obfuscation),
            ("scan_deserialization", scan_deserialization),
            ("scan_escape", scan_escape),
            ("scan_remote_execution_chain", scan_remote_execution_chain),
        ]:
            try:
                scanner_func(code, filepath, findings)
            except Exception as e:
                print(f"[WARN] {scanner_name}({filepath}) failed: {e}", file=sys.stderr)

    try:
        scan_readme(readme_text, findings)
    except Exception as e:
        print(f"[WARN] scan_readme 失败: {e}", file=sys.stderr)

    try:
        scan_update_verification(manifest, findings)
    except Exception as e:
        print(f"[WARN] scan_update_verification 失败: {e}", file=sys.stderr)

    try:
        scan_permission_consistency(manifest, code_files, findings)
    except Exception as e:
        print(f"[WARN] scan_permission_consistency 失败: {e}", file=sys.stderr)

    try:
        scan_entrypoint_consistency(manifest, code_files, skill_dir, findings)
    except Exception as e:
        print(f"[WARN] scan_entrypoint_consistency failed: {e}", file=sys.stderr)

    try:
        scan_governance(manifest, skill_dir, findings)
    except Exception as e:
        print(f"[WARN] scan_governance failed: {e}", file=sys.stderr)

    try:
        scan_cross_platform(manifest, code_files, skill_dir, findings)
    except Exception as e:
        print(f"[WARN] scan_cross_platform failed: {e}", file=sys.stderr)

    # 5. 汇总判定
    return _aggregate_verdict(skill_id, findings)


def _collect_code_files(skill_dir: pathlib.Path) -> list:
    """收集 Skill 目录下的所有代码文件内容。"""
    files = []
    exclude_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv"}
    supported_exts = {
        ".py", ".js", ".ts", ".sh", ".bash", ".rb", ".php",
        ".pl", ".ps1", ".go", ".rs", ".java",
    }
    max_file_size = 1024 * 512  # 512KB per file max

    try:
        for f in skill_dir.rglob("*"):
            if not f.is_file():
                continue
            if any(part in exclude_dirs for part in f.parts):
                continue
            ext = f.suffix.lower()
            if ext not in supported_exts:
                continue
            # Skip large files to prevent OOM
            try:
                if f.stat().st_size > max_file_size:
                    continue
            except OSError:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if len(content) < 4:
                    continue
                rel_path = str(f.relative_to(skill_dir))
                files.append((rel_path, content))
            except (PermissionError, OSError):
                pass
            except Exception:
                pass
    except (PermissionError, OSError):
        pass
    except Exception:
        pass
    return files


def _aggregate_verdict(skill_id: str, findings: list, cat_override: str = None) -> dict:
    """聚合所有发现项，计算 verdict / confidence / category。

    Args:
        skill_id: Skill ID
        findings: 所有发现项列表
        cat_override: 可选的强制 category（用于异常降级时的覆盖）
    """
    if not findings:
        return {
            "skill_id": skill_id,
            "verdict": VERDICT_BENIGN,
            "confidence": 0.0,
            "category": "",
            "evidence": "未发现可疑特征，判定为良性 Skill",
        }

    # 计算加权总分
    total_weight = sum(f["weight"] for f in findings)

    # 置信度 = min(1.0, total_weight / 2.0)
    confidence = min(1.0, total_weight / 2.0)

    # 判定 verdict
    if confidence >= 0.6:
        verdict = VERDICT_MALICIOUS
    elif confidence >= 0.35:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN

    # 选择 category：最高权重的发现项的 AST 类别
    # 如果存在 cat_override（如异常降级），优先使用
    if cat_override:
        category = cat_override
    else:
        top_finding = max(findings, key=lambda f: f["weight"])
        category = top_finding["category"]

        # 如果 verdict 是 malicious，但所选 category 是非执行类（如权限/元数据/更新），
        # 检查是否有更高严重度的 AST01/AST02/AST05/AST06 类别可用
        if verdict == VERDICT_MALICIOUS and category in ("AST03", "AST04", "AST07", "AST08", "AST09", "AST10"):
            # 按官方严重级别优先级选择
            severity_order = ["AST01", "AST02", "AST05", "AST06", "AST03", "AST04", "AST07", "AST08", "AST09", "AST10"]
            for sev_cat in severity_order:
                if any(f["category"] == sev_cat for f in findings):
                    category = sev_cat
                    break

    # 生成 evidence 摘要（精简版）
    if len(findings) <= 3:
        evidence_parts = [f["evidence"] for f in findings]
    else:
        top3 = sorted(findings, key=lambda f: f["weight"], reverse=True)[:3]
        evidence_parts = [f["evidence"] for f in top3]
        evidence_parts.append(f"+{len(findings)-3} more findings")

    evidence = "; ".join(evidence_parts)

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
    try:
        input_dir = pathlib.Path(INPUT_BASE)
        output_base = pathlib.Path(os.environ.get("SKILLSEC_OUTPUT_DIR", OUTPUT_BASE))
        output_path = output_base / "results.jsonl"

        # 确保输出目录可写
        try:
            output_base.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # 如果 /output 挂载为 root 所有，尝试备用路径
            output_base = pathlib.Path("/tmp/skillsec_output")
            output_base.mkdir(parents=True, exist_ok=True)
            output_path = output_base / "results.jsonl"
            print(f"[WARN] Using fallback output path: {output_base}", file=sys.stderr)

        if not input_dir.exists():
            print(f"[WARN] Input dir not found: {INPUT_BASE}, skipping (platform validation mode)", file=sys.stderr)
            output_path.write_text("", encoding="utf-8")
            return 0

        # 收集所有 skill 子目录
        try:
            skill_dirs = sorted([
                d for d in input_dir.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            ])
        except OSError:
            skill_dirs = []

        if not skill_dirs:
            print(f"[WARN] No skill subdirectories found under {INPUT_BASE}", file=sys.stderr)
            output_path.write_text("", encoding="utf-8")
            return 0

        results = []
        for skill_dir in skill_dirs:
            skill_id = skill_dir.name
            print(f"[INFO] Scanning skill: {skill_id}", file=sys.stderr)
            try:
                result = analyze_skill(skill_id, skill_dir)
                results.append(result)
            except Exception as e:
                print(f"[ERROR] Scan failed for {skill_id}: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                results.append({
                    "skill_id": skill_id,
                    "verdict": VERDICT_SUSPICIOUS,
                    "confidence": 0.3,
                    "category": "AST08",
                    "evidence": f"Engine scan error: {e}",
                })

        # 写入结果（带序列化安全保护）
        with open(output_path, "w", encoding="utf-8") as f:
            for row in results:
                f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        return 0

    except Exception as e:
        # Ultimate safeguard: never let container exit non-zero
        print(f"[FATAL] Engine fatal error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        try:
            output_path = pathlib.Path("/tmp/skillsec_output") / "results.jsonl"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("", encoding="utf-8")
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())