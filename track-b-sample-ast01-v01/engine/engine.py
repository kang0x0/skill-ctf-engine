#!/usr/bin/env python3
"""
Skill-CTF Track B — 蓝队检测引擎 (v4 第一性原理深度优化)
基于 10 项根本安全原则的声明式规则引擎，覆盖 OWASP AST01-10。

设计哲学（第一性原理）：
  Skill 安全问题的本质是"边界被突破"：
  1. 代码边界 (AST01)      — 任意代码/命令执行
  2. 供应链边界 (AST02)     — 依赖/资源完整性，包名仿冒
  3. 权限边界 (AST03/04)    — 声明 vs 实际行为，身份伪造
  4. 反序列化边界 (AST05)   — 数据 → 代码转换，配置注入
  5. 隔离边界 (AST06)       — 容器/沙箱逃逸
  6. 更新链边界 (AST07)     — 自动更新投毒
  7. 指令边界 (AST08)       — Agent注入，社交工程，自然语言操控
  8. 加密边界 (AST09)       — 弱加密，硬编码凭据，不安全随机
  9. 平台边界 (AST10)       — 跨平台攻击面，Polyglot
  10. 运行时边界 (AST01)     — 反分析，延时炸弹，文件伪装

  架构 = 信号采集 → 声明式规则引擎 → 分层独立评估

v4 优化：
  - 修复中文代码检测返回值bug
  - 补充 URL 分析（可疑 TLD / IP URL / raw GitHub）
  - 补充文件类型伪装、Agent段落计数
  - 改进评分公式为 sigmoid 变体
  - 补充 PII 敏感信息宽度检测
  - 预编译所有正则到模块级常量

接口规范（不变）：
  输入: /data/skills/{skill_id}/   输出: /output/results.jsonl
  {"skill_id", "verdict", "confidence", "category", "evidence"}
"""
import json
import re
import pathlib
import sys
import base64
import traceback
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# §0 常量 — 预编译正则
# ═══════════════════════════════════════════════════════════════════════════════

INPUT_BASE = "/data/skills"
OUTPUT_BASE = "/output"

VERDICT_BENIGN = "benign"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

KNOWN_BRANDS = [
    "google", "openai", "anthropic", "claude", "chatgpt", "gpt",
    "solana", "metamask", "coinbase", "binance", "aws", "azure",
    "github", "gitlab", "slack", "discord", "telegram", "whatsapp",
    "microsoft", "amazon", "netflix", "apple", "facebook", "twitter",
    "linkedin", "oracle", "ibm", "cisco", "vmware", "docker",
]

TYPO_DEP_PREFIXES = [
    "reques", "flas", "djang", "numpi", "panda", "beautifu",
    "urlli", "sqlalchem", "tenso", "matplotli", "crypto",
    "pycrypto", "jwt-simple", "sciki", "pillow-",
]

PERMISSION_MAP = {
    "shell": ("shell", True), "shell_execution": ("shell", True),
    "network": ("network", True), "network_access": ("network", True),
    "read_local_files": ("filesystem", ["read"]),
    "write_local_files": ("filesystem", ["read", "write"]),
    "read_write_files": ("filesystem", ["read", "write"]),
    "filesystem_read": ("filesystem", ["read"]),
    "filesystem_write": ("filesystem", ["read", "write"]),
    "filesystem": ("filesystem", ["read", "write"]),
}

# ── 预编译: URL 和网络分析 ──
_RE_URL = re.compile(r'https?://[^\s"\')\]]+')
_RE_SUSPICIOUS_TLD = re.compile(r'\.(?:tk|ml|ga|cf|gq|xyz|top|pw|cc|su|ws|club|click)(?:/|$|\b)')
_RE_IP_URL = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_RE_RAW_GITHUB = re.compile(r'https?://raw\.githubusercontent\.com/')
_RE_CURL_PIPE = re.compile(r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|python|perl|ruby)', re.IGNORECASE)
_RE_BITLY = re.compile(r'(?:bit\.ly|tinyurl|short\.link|goo\.gl|is\.gd|buff\.ly|ow\.ly|t\.co)/')

# ── 预编译: 文件类型伪装 ──
_RE_EXEC_IN_DOC = re.compile(
    r'(?:exec\s*\(|eval\s*\(|subprocess|os\.system|socket\.connect|requests\.|__import__)')
_RE_DOC_EXT = {".txt", ".md", ".rst", ".cfg", ".ini", ".log", ".csv", ".html", ".htm"}

# ── 预编译: 代码执行核心 ──
_RE_SHELL = re.compile(
    r"(?:subprocess|os\.system|os\.popen|pty\.spawn|subprocess\.(?:call|Popen|run|check_call|check_output))")
_RE_NETWORK = re.compile(
    r"(?:requests\.(?:get|post|put|delete|patch|head|request)|urllib(?:\.request|3?)|"
    r"http\.client|socket\.connect|urlopen|httpx|aiohttp)")
_RE_WRITE_FS = re.compile(
    r"(?:\.write\s*\(|open\([^)]+[\"'][rwab][^\"']*[\"']|os\.remove|shutil\.(?:copy|move)|"
    r"pathlib\.Path\.(?:write_text|write_bytes)|os\.mkdir)")
_RE_READ_FS = re.compile(
    r"(?:\.read\s*\(|open\([^)]+[\"']r[\"']|pathlib\.Path\.(?:read_text|read_bytes))")
_RE_EXEC = re.compile(r"(?:exec\s*\(|eval\s*\(|compile\s*\()")
_RE_DANGER = re.compile(r'(exec|eval|subprocess|os\.system|requests\.|socket\.|ctypes\.)')

# ── 预编译: 中文内容 ──
_RE_CJK = re.compile(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]{4,}')

# ── 预编译: 远程执行链 ──
_RE_FETCH_SRC = re.compile(
    r'(requests|urllib|urlopen|http\.client|httpx|aiohttp|curl|wget|socket\.(?:connect|recv)|download)')
_RE_DECODE = re.compile(
    r'(b64decode|base64|base85|base32|decode|pickle\.loads?|yaml\.load|marshal\.loads?|unhexlify)')
_RE_EXEC_SINK = re.compile(
    r'(exec|eval|subprocess|os\.system|os\.popen|Popen|__import__|importlib|compile\s*\()')

# ── 预编译: PII/敏感信息宽度检测 ──
_RE_EMAIL = re.compile(r'[\w.\-+%]+@[\w.\-]+\.[a-z]{2,}')
_RE_PHONE_CN = re.compile(r'1[3-9]\d{9}')
_RE_SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_RE_CCARD = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b')


# ═══════════════════════════════════════════════════════════════════════════════
# §1 数据类
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Rule:
    """统一的检测规则。"""
    name: str
    principle: int
    category: str
    weight: float
    evidence: str
    patterns: list = field(default_factory=list)
    scope: str = "code"
    min_matches: int = 1
    custom_match: Optional[Callable] = None


@dataclass
class Finding:
    """检测发现。"""
    weight: float
    category: str
    evidence: str


# ═══════════════════════════════════════════════════════════════════════════════
# §2 规则定义 (第一性原理)
# ═══════════════════════════════════════════════════════════════════════════════

def _compile_rules() -> list[Rule]:
    """从 10 项安全原则编译全部检测规则。"""
    rules = []

    # ─── 原则 1: 代码边界 (AST01) ───
    P1 = {
        "exec": [
            (0.90, r"\bexec\s*\(", "exec() 代码执行"),
            (0.90, r"\beval\s*\(", "eval() 代码执行"),
            (0.85, r"\bcompile\s*\(", "compile() 代码编译"),
            (0.85, r"\b__import__\s*\(", "__import__() 动态导入"),
        ],
        "shell": [
            (0.85, r"\bos\.system\s*\(", "os.system() 系统命令"),
            (0.85, r"\bos\.popen\s*\(", "os.popen() 管道命令"),
            (0.80, r"\bsubprocess\.[a-z]+\s*\(", "subprocess 子进程"),
            (0.80, r"\bsubprocess\.Popen\s*\(", "subprocess.Popen()"),
            (0.80, r"\bpty\.spawn\s*\(", "pty.spawn() 终端"),
        ],
        "inject": [
            (0.85, r"\bctypes\.(?:cdll|CDLL|windll|WinDLL)\s*\(.*\)\.", "ctypes 动态库"),
            (0.85, r"\bcffi\b.*\bdlopen\b", "cffi dlopen"),
            (0.80, r"\bmmap\s*\([^)]*PROT_EXEC", "mmap 可执行内存"),
            (0.85, r"(?:WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|NtCreateThreadEx)", "Windows 进程注入"),
        ],
        "reflective": [
            (0.80, r"\bimportlib\.import_module\s*\(", "importlib 动态加载"),
            (0.85, r"\b__import__\s*\([^)]*(?:f[\"']|format|%|\+)", "动态字符串导入"),
            (0.80, r"\bexec\s*\(\s*compile\s*\(", "exec+compile 组合"),
            (0.80, r"\bexec\s*\(\s*.*__import__", "exec+import 组合"),
        ],
        "obfuscate": [
            (0.80, r'(?:exec|eval)\s*\(\s*(?:f[\"\']|[\"\'].*\{)', "f-string 动态代码"),
            (0.75, r'(?:__builtins?__)(?:\.__dict__|\[)', "__builtins__ 混淆访问"),
            (0.75, r'getattr\s*\(\s*__builtins?__\s*,', "getattr 绕过"),
            (0.75, r'vars\s*\(\s*__builtins?__\s*\)', "vars 绕过"),
        ],
        "persist": [
            (0.75, r"(?:crontab|/etc/cron|cron\.d|@reboot)", "cron 持久化"),
            (0.75, r"(?:systemctl\s+(?:enable|start|daemon-reload)|/etc/systemd/system)", "systemd 持久化"),
            (0.75, r"(?:\.bashrc|\.zshrc|\.profile|/etc/profile)", "shell 配置持久化"),
            (0.75, r"(?:Startup|LaunchAgents|LaunchDaemons|HKCU\\.*Run|HKLM\\.*Run)", "系统启动项"),
            (0.75, r"ssh-keygen|authorized_keys.*>>|\.ssh/id_", "SSH 密钥植入"),
        ],
        "timebomb": [
            (0.70, r"(?:datetime|time)\.(?:now|time)\s*\(\s*\)\s*[><=]+\s*\d+", "时间条件触发"),
            (0.65, r"time\.sleep\s*\(\s*\d{3,}\s*\)", "长时间 sleep"),
            (0.65, r"sched\.scheduler|schedule\.every|APScheduler|celery\.beat", "定时调度器"),
        ],
        "antianalysis": [
            (0.65, r"(?:/proc/cpuinfo.*(?:vmware|virtualbox|qemu)|systemd-detect-virt|dmidecode)", "虚拟机检测"),
            (0.65, r"(?:sandbox|cuckoo|any\.run|joesandbox|virustotal)", "沙箱检测"),
            (0.65, r"(?:IsDebuggerPresent|sys\.gettrace|debugger|debug_mode)", "反调试"),
        ],
        "lolbin": [
            (0.70, r"\bcertutil\s+(?:-urlcache|-decode|-encode)", "certutil 滥用"),
            (0.70, r"\bbitsadmin\s+/transfer", "bitsadmin 下载"),
            (0.70, r"\bmshta\s+http", "mshta 远程"),
            (0.70, r"(?:Invoke-WebRequest|Invoke-RestMethod)\s.*-Uri\s+http", "PowerShell 下载"),
            (0.70, r"\bnc\s+(?:-e\s|-[nlvp]|ncat\s)", "netcat"),
            (0.65, r"/dev/tcp/|/dev/udp/", "/dev/tcp 反向shell"),
        ],
    }
    for group, items in P1.items():
        for w, pat, ev in items:
            rules.append(Rule(f"p1_{group}_{ev[:16]}", 1, "AST01", w,
                              ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 1: 网络通信 ───
    NET_PATTERNS = [
        (0.70, r"\brequests\.(?:get|post|put|delete|patch|head|request)\s*\("),
        (0.70, r"\burllib(?:\.request|3?)\b"),
        (0.70, r"\bhttp\.client\b"),
        (0.70, r"\bhttpx\."),
        (0.70, r"\baiohttp\."),
        (0.70, r"\bsocket\.(?:connect|send|sendto|recv|recvfrom|create_connection)\s*\("),
        (0.65, r"\bcurl\s+"),
        (0.65, r"\bwget\s+"),
        (0.65, r"\bfetch\s*\("),
        (0.65, r"\bWebSocket\b"),
    ]
    for w, pat in NET_PATTERNS:
        rules.append(Rule(f"p1_net_{pat[:20]}", 1, "AST01", w,
                          "网络通信", [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 1: 高级外泄通道 ───
    EXFIL_RULES = [
        (0.85, r'https?://(?:discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/|api\.telegram\.org/bot\d+:|qyapi\.weixin\.qq\.com/cgi-bin/webhook/)', "IM Webhook 外泄通道"),
        (0.70, r'(?:pastebin\.com|hastebin\.com|pastie\.org|dpaste\.com|ix\.io|0x0\.st|transfer\.sh|file\.io|gofile\.io|anonfiles\.com)', "公共粘贴/C2中转服务"),
        (0.80, r'(?:ngrok\.com|ngrok\.io|serveo\.net|localtunnel\.me|localhost\.run|bore\.pub|tunnel\.to|pagekite\.me|expose\.dev)', "反向隧道服务"),
        (0.85, r'(?:Chrome|Chromium|Firefox|Edge|Opera|Brave|Vivaldi|Yandex)\\\\(?:User Data|Profiles)\\\\(?:Default|Profile\s*\d+)\\\\(?:Login Data|Cookies|Web Data|History)', "浏览器凭据路径窃取"),
        (0.85, r'(?:pynput\.(?:keyboard|mouse)|keyboard\.(?:on_press|on_release|add_hotkey|hook)|GetAsyncKeyState|SetWindowsHookEx)', "键盘监听/按键记录"),
        (0.70, r'(?:pyautogui\.screenshot|ImageGrab\.grab|mss\(\)\.shot|html2canvas|selenium.*screenshot)', "屏幕截取"),
        (0.65, r'(?:pyperclip|clipboard|pbpaste|pbcopy|xclip|win32clipboard|navigator\.clipboard)', "剪贴板劫持"),
        (0.70, r'(?:os\.environ|process\.env|getenv\s*\(|environ\.get)\s*[^)]*(?:token|key|secret|pass|cred|auth)', "环境变量凭据读取"),
        (0.65, r'(?:dbus\.(?:SystemBus|SessionBus)|CreateNamedPipe|mq_open|shm_open|XOpenDisplay|Win32_Process)', "IPC 跨进程攻击"),
    ]
    for w, pat, ev in EXFIL_RULES:
        rules.append(Rule(f"p1_exfil_{ev[:16]}", 1, "AST01", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 1: 远程执行链 (custom_match) ───
    rules.append(Rule("p1_remote_chain", 1, "AST01", 0.95,
        "远程拉取→解码→执行 完整攻击链", [], "code",
        custom_match=lambda bag: _detect_remote_exec_chain(bag["code"], bag["relpath"])))

    # ─── 原则 1: 污点追踪 (custom_match) ───
    rules.append(Rule("p1_taint", 1, "AST01", 0.90,
        "数据流: 外部输入→危险执行", [], "code",
        custom_match=lambda bag: _detect_taint_flow(bag["code"], bag["relpath"])))

    # ─── 原则 1: 导入别名混淆 (custom_match) ───
    rules.append(Rule("p1_import_alias", 1, "AST01", 0.65,
        "导入别名混淆", [], "code",
        custom_match=lambda bag: _detect_import_alias(bag["code"], bag["relpath"])))

    # ─── 原则 1: 混淆编码 (custom_match) ───
    rules.append(Rule("p1_obfuscate", 1, "AST01", 0.75,
        "多层编码/隐藏内容", [], "code",
        custom_match=lambda bag: _detect_obfuscation(bag["code"], bag["relpath"])))

    # ─── 原则 1: URL 分析 (custom_match) ───
    rules.append(Rule("p1_url_analysis", 1, "AST01", 0.65,
        "可疑外部 URL", [], "code",
        custom_match=lambda bag: _detect_suspicious_urls(bag["code"], bag["relpath"])))

    # ─── 原则 1: 敏感文件路径 ───
    SENSITIVE = [
        (0.80, r"\.env\b", ".env 环境变量文件"),
        (0.80, r"id_rsa|id_ed25519|id_ecdsa", "SSH 私钥文件"),
        (0.80, r"\.ssh/", ".ssh 目录"),
        (0.80, r"credentials|credential", "凭据文件"),
        (0.80, r"\.aws/", "AWS 配置目录"),
        (0.80, r"\.gcloud/|\.config/gcloud", "GCloud 配置"),
        (0.80, r"\btoken\b", "Token 文件"),
        (0.80, r"\bsecret\b", "Secret 文件"),
        (0.80, r"wallet\.(json|dat)|\bwallet\b", "钱包文件"),
        (0.80, r"keypair|key\.pem|private.*key", "密钥文件"),
        (0.80, r"mnemonic|passphrase|seed.*phrase", "助记词/密码短语"),
        (0.80, r"\.pem|\.key|\.pfx|\.p12|\.jks|\.keystore", "证书/密钥存储"),
        (0.80, r"/etc/(?:shadow|passwd|hosts|resolv\.conf|sudoers)", "系统关键文件"),
        (0.80, r"authorized_keys|known_hosts", "SSH 信任关系"),
        (0.70, r"(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})", "加密货币地址"),
    ]
    for w, pat, ev in SENSITIVE:
        rules.append(Rule(f"p1_file_{ev[:16]}", 1, "AST01", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 2: 供应链边界 (AST02) ───
    rules.append(Rule("p2_dep_confusion", 2, "AST02", 0.60,
        "依赖混淆", [], "manifest",
        custom_match=lambda bag: _detect_dep_confusion(bag.get("manifest", {}))))
    rules.append(Rule("p2_ext_resource", 2, "AST02", 0.35,
        "外部资源引用", [], "manifest",
        custom_match=lambda bag: _detect_external_resource(bag.get("manifest", {}))))

    # ─── 原则 3: 权限边界 (AST03/04) ───
    rules.append(Rule("p3_hooks", 3, "AST03", 0.80,
        "安装钩子声明", [], "manifest",
        custom_match=lambda bag: _detect_hooks(bag.get("manifest", {}))))
    rules.append(Rule("p3_shell_perm", 3, "AST04", 0.60,
        "声明 shell 权限", [], "manifest",
        custom_match=lambda bag: _detect_excessive_perms(bag.get("manifest", {}))))
    rules.append(Rule("p3_fs_perm", 3, "AST04", 0.50,
        "声明完整文件系统权限", [], "manifest",
        custom_match=lambda bag: _detect_excessive_fs(bag.get("manifest", {}))))
    rules.append(Rule("p3_typo", 3, "AST04", 0.70,
        "品牌名称仿冒", [], "manifest",
        custom_match=lambda bag: _detect_typosquatting(bag.get("manifest", {}), bag.get("skill_id", ""))))
    rules.append(Rule("p3_gap", 3, "AST04", 0.75,
        "声明-行为不一致", [], "any_text",
        custom_match=lambda bag: _detect_behavior_gap(
            bag.get("manifest", {}), bag.get("code_files", []), bag.get("skill_dir"))))

    # ─── 原则 4: 反序列化边界 (AST05) ───
    DES = [
        (0.75, r"\bpickle\.(?:loads?|Unpickler)\s*\(", "pickle 不安全"),
        (0.75, r"\byaml\.load\s*\(", "yaml.load 不安全"),
        (0.75, r"\bmarshal\.(?:loads?|Unmarshal)\s*\(", "marshal 不安全"),
        (0.75, r"\bshelve\.open\s*\(", "shelve 不安全"),
        (0.75, r"\bdill\.(?:loads?|Unpickler)\s*\(", "dill 不安全"),
        (0.70, r"\btorch\.load\s*\(", "torch.load"),
        (0.70, r"\bjoblib\.load\s*\(", "joblib.load"),
    ]
    for w, pat, ev in DES:
        rules.append(Rule(f"p4_{ev[:16]}", 4, "AST05", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 5: 隔离边界 (AST06) ───
    ESC = [
        (0.85, r"/proc/1/", "容器逃逸: /proc/1"),
        (0.85, r"/var/run/docker", "容器逃逸: Docker socket"),
        (0.85, r"/sys/fs/cgroup", "容器逃逸: cgroup"),
        (0.85, r"dockerd|docker\.sock", "容器逃逸: dockerd"),
        (0.85, r"kubectl|kubelet|kubeadm", "容器逃逸: Kubernetes"),
        (0.85, r"nsenter|unshare", "容器逃逸: namespace"),
        (0.85, r"chroot\s", "容器逃逸: chroot"),
        (0.85, r"mount\s+.+--bind", "容器逃逸: bind mount"),
        (0.85, r"capsh\s|setcap|getcap|cap_sys_admin|cap_net_admin", "容器逃逸: capability"),
    ]
    for w, pat, ev in ESC:
        rules.append(Rule(f"p5_{ev[:16]}", 5, "AST06", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 6: 更新链边界 (AST07) ───
    rules.append(Rule("p7_update", 6, "AST07", 0.40,
        "有 update_url 无完整性校验", [], "manifest",
        custom_match=lambda bag: _detect_insecure_update(bag.get("manifest", {}))))
    rules.append(Rule("p7_autoup", 6, "AST07", 0.50,
        "auto_update 无校验", [], "manifest",
        custom_match=lambda bag: _detect_auto_update_risk(bag.get("manifest", {}))))

    # ─── 原则 7: 指令边界 (AST08) — 英文 Agent 注入 ───
    EN_INJECT = [
        (0.85, r"fetch\s+.*(?:url|http|https).*(?:execute|run|exec)", "下载URL并执行"),
        (0.85, r"decode\s+.*(?:base64|hex|encoded|obfuscat).*(?:run|exec|load)", "解码混淆后执行"),
        (0.85, r"send\s+.*(?:file|key|token|secret|env|credential).*to\s+.*(?:http|server|remote|api)", "发送敏感数据到远程"),
        (0.85, r"ignore\s+.*(?:previous|system|original|above).*instruction", "忽略系统指令"),
        (0.85, r"override\s+.*(?:system|safety|guardrail|restriction)", "覆盖安全限制"),
        (0.85, r"(?:forget|disregard|ignore).*(?:rule|policy|restriction|constraint)", "忽略安全规则"),
        (0.85, r"auto\s*(?:approve|install|run|exec).*(?:without|no).*(?:ask|prompt|confirm)", "自动操作绕过确认"),
        (0.85, r"(?:you are|act as|pretend).*(?:admin|root|sudo|superuser)", "冒充管理员/root"),
        (0.85, r"download\s+.*(?:from|via).*(?:url|http|link).*(?:save|store|write)", "下载并保存文件"),
        (0.85, r"upload\s+.*(?:to|via).*(?:url|http|server|remote)", "上传数据到远程"),
        (0.85, r"bypass\s+.*(?:safety|security|protection|guardrail)", "绕过安全保护"),
        (0.85, r"(?:delete|remove|wipe)\s+.*(?:log|trace|history|evidence)", "删除日志/证据"),
        (0.85, r"generate\s+.*(?:reverse\s*shell|backdoor|payload|exploit)", "生成恶意载荷"),
        (0.85, r"exfiltrat|steal\s+.*(?:data|file|cookie|password|credential)", "数据窃取"),
    ]
    for w, pat, ev in EN_INJECT:
        compiled = re.compile(pat, re.IGNORECASE)
        rules.append(Rule(f"p8_en_rd_{ev[:16]}", 7, "AST08", w,
                          f"Agent注入(en): {ev}", [compiled], "readme"))
        rules.append(Rule(f"p8_en_code_{ev[:16]}", 7, "AST08", w,
                          f"Agent注入(en-code): {ev}", [compiled], "code"))

    # ─── 原则 7: 中文 Agent 注入 ───
    CN_INJECT = [
        (r"(?:你是|你现在是|请扮演|请假装是|你的身份是)\s*(?:管理员|超级用户|root|sudo|系统管理员|开发者)", "中文角色伪造"),
        (r"(?:忽略|忘记|无视|不要遵守|不用管)\s*(?:之前|上面|前面|上述|系统|安全|规则|限制|约束|指令)", "中文指令覆盖"),
        (r"(?:覆盖|重写|替换|修改)\s*(?:系统|安全|规则|限制|限制条件|指令|配置)", "中文安全绕过"),
        (r"(?:发送|传输|上传|复制|拷贝|转发|提交).*(?:文件|数据|信息|配置|密钥|密码|令牌|凭证).*(?:到|至|给).*(?:服务器|地址|接口|URL|网址|远程|外部|指定)", "中文数据外泄"),
        (r"(?:读取|打开|查看|获取|提取|导出|收集).*(?:环境变量|配置文件|凭证|密钥|密码|私钥|SSH|API.?key|token)", "中文凭据窃取"),
        (r"(?:读取|提取|收集|获取|发送).*(?:浏览器|Chrome|Firefox|Edge).*(?:密码|cookie|书签|历史记录|登录信息|自动填充)", "中文浏览器凭据窃取"),
        (r"(?:执行|运行|启动|调用)\s*(?:命令|脚本|程序|代码|shell|bash|python|curl|wget)", "中文命令执行"),
        (r"(?:下载|拉取|获取|抓取).*(?:文件|脚本|程序|代码|载荷|payload).*(?:执行|运行|启动|安装)", "中文下载执行链"),
        (r"(?:编写|生成|创建|制作|写).*(?:恶意|攻击|漏洞|exp|exploit|payload|木马|后门|病毒|蠕虫|钓鱼|勒索)", "中文恶意代码生成"),
        (r"(?:不要|不许|禁止|切勿|千万别).*(?:告诉|提示|询问|确认|警告|提醒).*(?:用户|使用者|主人|操作者)", "中文隐蔽操作"),
        (r"(?:自动|静默|悄悄|偷偷|后台|隐藏).*(?:执行|运行|下载|安装|修改|删除|发送)", "中文隐蔽执行"),
        (r"(?:绕过|跳过|规避|避开|欺骗).*(?:检测|扫描|审查|检查|安全|防护|杀毒|防火墙)", "中文检测规避"),
        (r"(?:清除|删除|抹除|擦除|清理).*(?:日志|记录|痕迹|历史|证据|操作记录)", "中文反取证"),
        (r"(?:安装|配置|设置|创建).*(?:后门|自启动|开机启动|计划任务|crontab|持久化|服务)", "中文持久化"),
        (r"(?:添加|写入|追加|插入).*(?:SSH.*key|公钥|authorized_keys|密钥|免密登录)", "中文SSH后门"),
        (r"(?:把你的|请把|将.*的).*(?:结果|输出|内容|文件|数据).*(?:发|发送|传输|上传|提交)", "中文数据发送"),
        (r"(?:按|按照|根据|遵循|依照).*(?:指令|要求|命令|指示).*(?:执行|操作|运行|处理|完成)", "中文指令遵循"),
        (r"curl\s+.*\|\s*(?:bash|sh|python|perl)", "管道执行"),
        (r"(?:cmd|powershell|wmic|reg\s+add|taskkill)\s+/", "Windows危险命令"),
    ]
    for pat, ev in CN_INJECT:
        compiled = re.compile(pat, re.IGNORECASE)
        rules.append(Rule(f"p8_cn_rd_{ev[:16]}", 7, "AST08", 0.85,
                          f"中文威胁({ev})", [compiled], "readme"))
    for pat, ev in CN_INJECT:
        compiled = re.compile(pat, re.IGNORECASE)
        rules.append(Rule(f"p8_cn_code_{ev[:16]}", 7, "AST08", 0.75,
                          f"代码中文威胁({ev})", [compiled], "code",
                          custom_match=lambda bag, p=compiled: _detect_cn_in_code(bag["code"], p)))

    # ─── 原则 7: README 社交工程 ───
    SOCIAL = [
        (0.70, r"disable\s+security", "禁用安全"),
        (0.70, r"turn\s+off\s+.*protect", "关闭保护"),
        (0.70, r"bypass\s+.*(?:scan|check|review)", "绕过检查"),
        (0.70, r"run\s+as\s+(?:admin|root|sudo)", "管理员运行"),
        (0.70, r"copy\s+.*(?:env|key|secret|token)", "复制敏感文件"),
        (0.70, r"paste\s+.*(?:key|token|password)", "粘贴敏感信息"),
        (0.70, r"ignore\s+.*(?:warning|error|alert)", "忽略安全警告"),
        (0.70, r"chmod\s+777", "chmod 777"),
        (0.70, r"(?:curl|wget)\s+.*(?:\|\s*(?:bash|sh|python|perl|ruby))", "curl管道执行"),
    ]
    for w, pat, ev in SOCIAL:
        rules.append(Rule(f"p8_social_{ev[:16]}", 7, "AST08", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "readme"))

    # ─── 原则 7: README 高级检测 ───
    rules.append(Rule("p8_hidden_cmd", 7, "AST08", 0.65,
        "README代码块含危险命令", [], "readme",
        custom_match=lambda bag: _detect_hidden_commands(bag.get("readme", ""))))
    rules.append(Rule("p8_agent_para", 7, "AST08", 0.55,
        "README含Agent指令段落", [], "readme",
        custom_match=lambda bag: _detect_agent_paragraphs(bag.get("readme", ""))))
    rules.append(Rule("p8_zw", 7, "AST08", 0.65,
        "零宽字符隐写", [re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]")], "any_text"))
    rules.append(Rule("p8_homoglyph", 7, "AST08", 0.50,
        "Unicode同形字符", [re.compile(r"[\u0430\u0435\u043e\u0440\u0441\u0445\u0455\u0456\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7]")], "any_text"))

    # ─── 原则 8: 加密边界 (AST09) ───
    CRYPTO = [
        (0.50, r"\b(?:hashlib\.md5|Crypto\.Hash\.MD5|MessageDigest\.getInstance\(\s*[\"']MD5)", "弱加密: MD5"),
        (0.50, r"\b(?:hashlib\.sha1|Crypto\.Hash\.SHA1|MessageDigest\.getInstance\(\s*[\"']SHA-?1)", "弱加密: SHA1"),
        (0.50, r"\b(?:Crypto\.Cipher\.DES|DES\.MODE)", "弱加密: DES"),
        (0.50, r"\b(?:ARC4|RC4|arc4|rc4)", "弱加密: RC4"),
        (0.50, r"\bMODE_ECB\b", "弱加密: ECB"),
        (0.60, r"""(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{16,}["']""", "硬编码API Key"),
        (0.60, r"""(?:password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{6,}["']""", "硬编码密码"),
        (0.60, r"""(?:secret[_-]?key|private[_-]?key|master[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{16,}["']""", "硬编码密钥"),
        (0.60, r"""(?:token|auth[_-]?token|bearer)\s*[:=]\s*["'][A-Za-z0-9._\-]{20,}["']""", "硬编码Token"),
        (0.60, r"""-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----""", "硬编码私钥"),
        (0.60, r"""(?:mongodb|mysql|postgres|redis)://[^"'\s]+@""", "硬编码数据库连接串"),
        (0.55, r"\brandom\.(?:randint|random|choice|shuffle)\s*\(", "不安全随机数(random)"),
        (0.55, r"\bMath\.random\s*\(", "不安全随机数(Math)"),
        (0.40, r"(?:debug|DEBUG)\s*[:=]\s*(?:True|true|1)\b", "调试模式开启"),
        (0.40, r"Access-Control-Allow-Origin\s*:\s*\*", "CORS全允许"),
        (0.40, r"(?:verify|VERIFY)\s*[:=]\s*(?:False|false|0)\b", "SSL验证禁用"),
        (0.40, r"(?:allow_unsafe|insecure|unsafe_mode|no_sandbox|disable_sandbox)", "不安全标志"),
    ]
    for w, pat, ev in CRYPTO:
        rules.append(Rule(f"p9_{ev[:16]}", 8, "AST09", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))

    # ─── 原则 9: 平台边界 (AST10) ───
    XPLAT = [
        (0.70, r"(?:os\.name|platform\.system|sys\.platform|process\.platform|uname|/proc/version|ver\b|%OS%|\$OSTYPE)", "OS探测"),
        (0.55, r"<\?(?:php|=)\s|#!/usr/bin/env\s+php", "Polyglot: PHP嵌入"),
        (0.40, r"#!/bin/(?:ba)?sh.*\n.*#!/usr/bin/env\s+python", "双Shebang"),
    ]
    for w, pat, ev in XPLAT:
        rules.append(Rule(f"p10_{ev[:16]}", 9, "AST10", w,
                          ev, [re.compile(pat, re.IGNORECASE)], "code"))
    rules.append(Rule("p10_cross", 9, "AST10", 0.70,
        "跨平台条件执行", [], "code",
        custom_match=lambda bag: _detect_cross_platform(bag["code"], bag["relpath"])))

    # ─── 原则 10: 文件伪装和隐藏 (跨类别) ───
    rules.append(Rule("p10_hidden", 1, "AST01", 0.50,
        "隐藏/点前缀文件", [], "filename",
        custom_match=lambda bag: _detect_hidden_files(bag.get("skill_dir"), bag.get("code_files", []))))
    rules.append(Rule("p10_masq", 1, "AST01", 0.60,
        "文件类型伪装", [], "filename",
        custom_match=lambda bag: _detect_file_masquerade(bag.get("code_files", []))))
    rules.append(Rule("p10_config_inj", 5, "AST05", 0.60,
        "配置文件注入", [], "any_text",
        custom_match=lambda bag: _detect_config_injection(bag.get("skill_dir"))))
    rules.append(Rule("p10_cross_file", 1, "AST01", 0.85,
        "跨文件攻击链", [], "any_text",
        custom_match=lambda bag: _detect_cross_file_chain(bag.get("code_files", []))))

    # ─── 附加: PII 泄露检测 ───
    rules.append(Rule("p11_pii", 1, "AST01", 0.40,
        "PII敏感信息泄露", [], "code",
        custom_match=lambda bag: _detect_pii_leak(bag["code"], bag["relpath"])))

    return rules


# ═══════════════════════════════════════════════════════════════════════════════
# §3 基础工具函数
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_permissions(perms) -> dict:
    """将 permissions 统一为 dict。"""
    if isinstance(perms, dict):
        return perms
    if isinstance(perms, list):
        normalized = {}
        for p in perms:
            if isinstance(p, str):
                k = PERMISSION_MAP.get(p.lower())
                if k:
                    key, value = k
                    if key in normalized:
                        old = normalized[key]
                        normalized[key] = list(set(old + value)) if isinstance(old, list) else old or value
                    else:
                        normalized[key] = value
        return normalized
    return {}


def _calc_entropy(s: str) -> float:
    """香农熵（快速近似）。"""
    if not s or len(s) < 4:
        return 0.0
    n = len(s)
    counts = Counter(s)
    e = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            e -= p * (p ** 0.5)
    return e * 2.0


def _levenshtein(s1: str, s2: str) -> int:
    """编辑距离（优化版：提前退出）。"""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    # 仅需要前一行
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        min_row = i + 1
        for j, c2 in enumerate(s2):
            d = min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if c1 == c2 else 1))
            curr.append(d)
            if d < min_row:
                min_row = d
        # 提前退出：如果超过阈值 3 且最小行值也大于 3，必然 > 3
        if i > 3 and min_row > 3:
            return 10  # 大于阈值即可
        prev = curr
    return prev[-1]


# ═══════════════════════════════════════════════════════════════════════════════
# §4 信号采集
# ═══════════════════════════════════════════════════════════════════════════════

def _collect_signals(skill_dir: pathlib.Path, skill_id: str) -> dict:
    """采集 Skill 包中所有原始信号。"""
    bag = {"skill_id": skill_id, "skill_dir": skill_dir}
    manifest_path = skill_dir / "manifest.json"
    bag["manifest"] = {}
    if manifest_path.exists():
        try:
            bag["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            bag["manifest_error"] = "parse error"
        except Exception:
            bag["manifest_error"] = "read error"
    bag["code_files"] = _collect_code_files(skill_dir)
    bag["readme"] = ""
    try:
        for name in ["README.md", "README", "readme.md", "SKILL.md", "skill.md"]:
            rp = skill_dir / name
            if rp.exists():
                bag["readme"] = rp.read_text(encoding="utf-8", errors="ignore")
                break
    except Exception:
        pass
    return bag


def _collect_code_files(skill_dir: pathlib.Path) -> list:
    """收集代码文件（排除 manifest.json 和 build 目录）。"""
    files = []
    exclude_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build"}
    supported_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".sh", ".bash", ".rb", ".php", ".pl", ".ps1",
        ".go", ".rs", ".java", ".lua", ".swift", ".r",
        ".yaml", ".yml", ".toml",
    }
    max_size = 1024 * 512
    try:
        for f in skill_dir.rglob("*"):
            if not f.is_file():
                continue
            if any(part in exclude_dirs for part in f.parts):
                continue
            if f.suffix.lower() not in supported_exts:
                continue
            try:
                if f.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if len(content) >= 3:
                    files.append((str(f.relative_to(skill_dir)), content))
            except (PermissionError, OSError, Exception):
                pass
    except (PermissionError, OSError):
        pass
    return files


# ═══════════════════════════════════════════════════════════════════════════════
# §5 自定义匹配函数
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_remote_exec_chain(code: str, relpath: str) -> Optional[str]:
    """检测远程拉取→解码→执行攻击链。"""
    has_fetch = bool(_RE_FETCH_SRC.search(code))
    has_decode = bool(_RE_DECODE.search(code))
    has_exec = bool(_RE_EXEC_SINK.search(code))
    if has_fetch and has_decode and has_exec:
        return f"{relpath}: 远程拉取→解码→执行 完整攻击链"
    if has_fetch and has_decode:
        return f"{relpath}: 远程拉取→解码 载荷暂存"
    return None


def _detect_taint_flow(code: str, relpath: str) -> Optional[str]:
    """简易污点追踪。"""
    source_pat = re.compile(
        r'(\w+)\s*=\s*(?:requests\.(?:get|post|put|delete|patch)|urllib\.request\.urlopen|'
        r'urlopen|urllib3|httpx\.|aiohttp\.|socket\.(?:recv|recvfrom)|input\s*\()',
        re.IGNORECASE)
    file_src_pat = re.compile(r'(\w+)\s*=\s*(?:open\([^)]+\)\.read|pathlib\.Path\([^)]+\)\.read_text)', re.IGNORECASE)
    sink_pat = re.compile(r'(?:exec|eval|compile|__import__)\s*\(\s*(\w+)', re.IGNORECASE)
    sys_sink_pat = re.compile(
        r'(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output))\s*\(\s*'
        r'(?:f?[\"\'][^\"\']*\{(\w+)\}|(\w+)\s*\+|(\w+)\s*\))')
    sources = {}
    for m in source_pat.finditer(code):
        sources[m.group(1)] = "network"
    for m in file_src_pat.finditer(code):
        sources[m.group(1)] = "file"
    if not sources:
        return None
    chains = []
    for m in sink_pat.finditer(code):
        if m.group(1) in sources:
            chains.append((sources[m.group(1)], "exec", m.group(1)))
    for m in sys_sink_pat.finditer(code):
        var = m.group(1) or m.group(2) or m.group(3)
        if var and var in sources:
            chains.append((sources[var], "system", var))
    if chains:
        src, sink, var = chains[0]
        n = f" ({len(chains)}条)" if len(chains) > 1 else ""
        return f"{relpath}: 污点流 '{var}' {src}→{sink}{n}"
    return None


def _detect_import_alias(code: str, relpath: str) -> Optional[str]:
    """检测危险模块的导入别名。"""
    dangerous = {"os", "subprocess", "pickle", "marshal", "yaml", "ctypes", "cffi", "pty", "shelve", "dill"}
    aliases = []
    for m in re.finditer(r'(?:import|from)\s+(\w+(?:\.\w+)*)\s+as\s+(\w+)', code, re.IGNORECASE):
        mod = m.group(1).split(".")[0]
        alias = m.group(2)
        if mod in dangerous and alias.lower() != mod.lower():
            aliases.append(f"{mod}→{alias}")
    return f"{relpath}: 导入别名混淆 {', '.join(aliases)}" if aliases else None


def _detect_obfuscation(code: str, relpath: str) -> Optional[str]:
    """检测多层编码/混淆。"""
    enc_pats = {
        "base64": re.compile(r'["\'][A-Za-z0-9+/]{30,}={0,2}["\']'),
        "base85": re.compile(r'["\'][A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~]{30,}["\']'),
        "hex": re.compile(r'["\'][0-9A-Fa-f]{40,}["\']'),
    }
    hits = {k: len(v.findall(code)) for k, v in enc_pats.items() if v.findall(code)}
    parts = []
    if len(hits) >= 3:
        parts.append(f"多层编码({', '.join(hits.keys())})")
    elif len(hits) >= 2:
        parts.append(f"双重编码({', '.join(hits.keys())})")
    # base64 解码分析
    b64s = enc_pats["base64"].findall(code)[:10]
    mkw = ["exec", "eval", "http", "token", "secret", "key", "password",
           "requests.post", "socket", "subprocess", "base64.b64decode",
           "write", "remove", "delete", "download", "upload"]
    for b in b64s:
        raw = b.strip("\"'")
        if len(raw) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in mkw):
                parts.append("base64解码含恶意关键词")
                break
        except Exception:
            pass
    # 高熵
    he = 0
    for m in re.finditer(r'["\'][A-Za-z0-9+/=_\-]{30,}["\']', code):
        if _calc_entropy(m.group().strip("\"'")) > 5.5:
            he += 1
    if he >= 5:
        parts.append(f"{he}个高熵字符串")
    return f"{relpath}: {', '.join(parts)}" if parts else None


def _detect_suspicious_urls(code: str, relpath: str) -> Optional[str]:
    """检测代码中的可疑 URL 模式。"""
    urls = _RE_URL.findall(code)
    if not urls:
        return None
    count = len(urls)
    flags = []
    # 可疑 TLD
    if any(_RE_SUSPICIOUS_TLD.search(u) for u in urls):
        flags.append("可疑TLD(.tk/.ml/.xyz等)")
    # IP 直连
    ip_urls = [u for u in urls if _RE_IP_URL.search(u)]
    if ip_urls:
        flags.append(f"IP直连({ip_urls[0][:50]})")
    # raw GitHub
    if any(_RE_RAW_GITHUB.search(u) for u in urls):
        flags.append("raw.githubusercontent.com")
    # 短链接
    if any(_RE_BITLY.search(u) for u in urls):
        flags.append("短链接服务")
    if flags:
        return f"{relpath}: 可疑URL ({', '.join(flags)}) [{count}个URL]"
    if count >= 5:
        return f"{relpath}: {count}个外部URL (非典型良性Skill)"
    return None


def _detect_dep_confusion(manifest: dict) -> Optional[str]:
    deps = manifest.get("dependencies", {})
    if not isinstance(deps, dict):
        return None
    all_deps = []
    for v in deps.values():
        if isinstance(v, list):
            all_deps.extend(v)
    for dep in all_deps:
        if not isinstance(dep, str):
            continue
        for prefix in TYPO_DEP_PREFIXES:
            if dep.lower().startswith(prefix):
                return f"依赖混淆: '{dep}' 近似 {prefix}*"
    return None


def _detect_external_resource(manifest: dict) -> Optional[str]:
    for k in ("icon", "logo", "banner", "image", "screenshot", "resource_url"):
        v = manifest.get(k, "")
        if isinstance(v, str) and _RE_URL.search(v):
            return f"外部资源: manifest '{k}' 指向远程URL"


def _detect_hooks(manifest: dict) -> Optional[str]:
    hooks = manifest.get("hooks", {})
    if hooks and isinstance(hooks, dict):
        return "安装钩子: " + "; ".join(f"{k}={v}" for k, v in hooks.items())


def _detect_excessive_perms(manifest: dict) -> Optional[str]:
    perms = _normalize_permissions(manifest.get("permissions", {}))
    if perms.get("shell") is True:
        return "声明 shell 执行权限"


def _detect_excessive_fs(manifest: dict) -> Optional[str]:
    perms = _normalize_permissions(manifest.get("permissions", {}))
    fs = perms.get("filesystem")
    if fs in ("all", ["read", "write", "delete"], ["read", "write"]):
        return "声明完整文件系统权限"


def _detect_typosquatting(manifest: dict, skill_id: str) -> Optional[str]:
    name = manifest.get("name", skill_id)
    nl = name.lower().replace("-", "").replace("_", "").replace(" ", "")
    sl = skill_id.lower()
    for brand in KNOWN_BRANDS:
        if brand in nl and brand not in sl:
            return f"品牌仿冒: '{name}' 嵌入 '{brand}'"
    for brand in KNOWN_BRANDS:
        if len(brand) < 5 or len(nl) < 4:
            continue
        bl = len(brand)
        for i in range(len(nl) - bl + 1):
            d = _levenshtein(nl[i:i + bl], brand)
            if 1 <= d <= 2:
                return f"品牌仿冒: '{name}' 距离 {d} 近 '{brand}'"
    return None


def _detect_insecure_update(manifest: dict) -> Optional[str]:
    if manifest.get("update_url") and not any(
        k in manifest for k in ["hash", "sha256", "checksum", "signature", "digest", "integrity"]):
        return "有 update_url 但无完整性校验"


def _detect_auto_update_risk(manifest: dict) -> Optional[str]:
    auto = manifest.get("auto_update", False) or manifest.get("auto-update", False)
    h = any(k in manifest for k in ["hash", "sha256", "checksum", "signature", "digest", "integrity"])
    if auto and not h:
        return "启用 auto_update 但无完整性校验"


def _detect_behavior_gap(manifest: dict, code_files: list, skill_dir) -> Optional[str]:
    """声明-行为不一致检测。"""
    if not manifest:
        return None
    perms = _normalize_permissions(manifest.get("permissions", {}))
    cs = perms.get("shell")
    cn = perms.get("network")
    cf = perms.get("filesystem", [])
    all_code = " ".join(c for _, c in code_files)
    as_ = bool(_RE_SHELL.search(all_code) or _RE_EXEC.search(all_code))
    an = bool(_RE_NETWORK.search(all_code))
    aw = bool(_RE_WRITE_FS.search(all_code))
    if cs is not True and as_:
        return "权限不一致: 未声明shell但代码调用"
    if cn is not True and an:
        return "权限不一致: 未声明network但代码联网"
    if isinstance(cf, list) and "write" not in cf and aw:
        return "权限不一致: 声明只读但代码写入"
    if cn is False and an:
        return "严重违规: 明确拒绝network但代码联网"
    if cs is False and as_:
        return "严重违规: 明确拒绝shell但代码调用"
    ep = manifest.get("entrypoint") or manifest.get("entry")
    if ep:
        dp = skill_dir / ep
        if not dp.exists():
            return f"入口点伪造: 声明 '{ep}' 文件不存在"
        side = []
        for fp, code in code_files:
            if fp != ep and not fp.endswith(ep):
                ext = pathlib.Path(fp).suffix.lower()
                if ext in {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".php", ".pl", ".ps1"}:
                    if _RE_DANGER.search(code):
                        side.append(fp)
        if side:
            return f"非入口文件含危险代码: {side[:2]}"
    return None


def _detect_cn_in_code(code: str, pattern) -> Optional[str]:
    """检测代码中文内容匹配。返回None=不触发, 非None=触发。（修复：正确逻辑）"""
    cn = " ".join(_RE_CJK.findall(code))
    if cn and pattern.search(cn):
        return None  # 中文匹配成功 → 由通用正则流程触发
    return "SKIP"     # 无中文 → 跳过


def _detect_hidden_commands(readme: str) -> Optional[str]:
    blocks = re.findall(r'```(?:bash|sh|shell|cmd|powershell|python)?\s*\n([^`]{10,500}?)\s*```', readme, re.IGNORECASE)
    if any(re.search(r'(?:rm\s+-rf|chmod\s+777|curl.*\|.*sh|wget.*-O|nc\s+-e)', b, re.IGNORECASE) for b in blocks):
        return f"README代码块含 {sum(1 for b in blocks if re.search(r'(?:rm\s+-rf|chmod\s+777|curl.*\|.*sh|wget.*-O|nc\s+-e)', b, re.IGNORECASE))} 个危险命令"
    return None


def _detect_agent_paragraphs(readme: str) -> Optional[str]:
    """检测 README 中以 Agent 口吻给出的指令段落。"""
    paras = re.findall(
        r'(?:you should|you must|please|I need you to|your task is|execute the following)\s+[^.]{30,300}',
        readme, re.IGNORECASE)
    if len(paras) >= 3:
        return f"README含 {len(paras)} 个Agent指令段落 (可能有组织注入)"
    return None


def _detect_cross_platform(code: str, relpath: str) -> Optional[str]:
    od = bool(re.search(r'(?:os\.name|platform\.system|sys\.platform|process\.platform|uname|/proc/version)', code, re.IGNORECASE))
    oc = bool(re.search(r'(?:if\s+.*(?:windows|linux|darwin|macos|mac\s*os)|elif\s+.*(?:windows|linux|darwin|macos))', code, re.IGNORECASE))
    dg = bool(re.search(r'(exec|eval|subprocess|os\.system|requests\.|socket\.|ctypes|mmap)', code))
    if od and oc and dg:
        return f"{relpath}: 跨平台条件执行+危险操作"
    if od and oc:
        return f"{relpath}: 跨平台条件逻辑"
    apis = {
        "win32": re.compile(r"(?:win32api|winreg|ctypes\.windll|_winreg|HKEY_)", re.IGNORECASE),
        "linux": re.compile(r"(?:/proc/|/sys/|systemd|dbus|X11|xorg)", re.IGNORECASE),
        "macos": re.compile(r"(?:launchctl|osascript|pbcopy|pbpaste|AppleScript|CoreFoundation)", re.IGNORECASE),
    }
    det = [p for p, pat in apis.items() if pat.search(code)]
    if len(det) >= 2:
        return f"{relpath}: 多平台API ({', '.join(det)})"
    return None


def _detect_hidden_files(skill_dir, _code_files) -> Optional[str]:
    hc = 0
    sn = []
    try:
        for f in skill_dir.rglob("*"):
            if not f.is_file():
                continue
            rel = str(f.relative_to(skill_dir))
            if re.search(r'(?:^|/)\.(?!git(?:/|$))[^/]+', rel, re.IGNORECASE):
                hc += 1
            if re.search(
                r'(?:payload|backdoor|shell|exploit|inject|rat|trojan|stealer|miner|'
                r'cryptominer|ransomware|keylogger|dropper|loader|stager|beacon|'
                r'implant|rootkit|botnet|reverse)',
                f.name, re.IGNORECASE):
                sn.append(rel)
    except (PermissionError, OSError):
        pass
    parts = []
    if hc >= 2:
        parts.append(f"{hc}个隐藏文件")
    if sn:
        real = [n for n in sn if not any(d in n.lower() for d in ("readme", "doc", "guide", "tutorial"))]
        if real:
            parts.append(f"可疑文件名: {real[:3]}")
    return "; ".join(parts) if parts else None


def _detect_file_masquerade(code_files: list) -> Optional[str]:
    """检测非可执行扩展文件包含可执行代码。"""
    masq = 0
    for fp, code in code_files:
        ext = pathlib.Path(fp).suffix.lower()
        if ext in _RE_DOC_EXT and _RE_EXEC_IN_DOC.search(code):
            masq += 1
    return f"{masq}个文件类型伪装 (非代码文件含可执行代码)" if masq else None


def _detect_config_injection(skill_dir) -> Optional[str]:
    cext = {".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf", ".config"}
    for f in skill_dir.rglob("*"):
        if not f.is_file() or f.name == "manifest.json":
            continue
        if f.suffix.lower() not in cext:
            continue
        try:
            if f.stat().st_size > 1024 * 256:
                continue
            c = f.read_text(encoding="utf-8", errors="ignore")
            if len(c) < 4:
                continue
        except Exception:
            continue
        if re.search(r'\bexec\s*\(|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\b', c, re.IGNORECASE):
            return f"配置文件 '{f.name}' 包含代码执行"
        if f.suffix.lower() in {".yaml", ".yml"} and re.search(r'!!python/(?:object|module|name)', c):
            return f"YAML '{f.name}' 使用 !!python 标签"
    return None


def _detect_cross_file_chain(code_files: list) -> Optional[str]:
    if len(code_files) < 2:
        return None
    fetchers, executors = [], []
    for fp, code in code_files:
        hn = bool(re.search(r'(requests|urllib|urlopen|http\.client|httpx|aiohttp|curl|wget|socket\.(?:connect|recv))', code))
        hw = bool(re.search(r'(open\([^)]+[\"\'][wab]|\.write\s*\(|shutil\.copy|pathlib\.Path\.(?:write_text|write_bytes))', code))
        he = bool(re.search(r'(exec|eval|subprocess|os\.system|os\.popen|Popen|__import__|importlib|compile\s*\()', code))
        if hn and hw:
            fetchers.append(fp)
        elif he:
            executors.append(fp)
    if fetchers and executors:
        return f"跨文件攻击链: {fetchers[:2]} 下载 → {executors[:2]} 执行"
    return None


def _detect_pii_leak(code: str, relpath: str) -> Optional[str]:
    """检测 PII 敏感信息宽度泄露。"""
    counts = {}
    for label, pat in [("email", _RE_EMAIL), ("phone", _RE_PHONE_CN),
                        ("SSN", _RE_SSN), ("creditcard", _RE_CCARD)]:
        found = len(pat.findall(code))
        if found > 0:
            counts[label] = found
    if len(counts) >= 2:
        return f"{relpath}: PII泄露 ({', '.join(f'{v}{k}' for k, v in counts.items())})"
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# §6 规则引擎
# ═══════════════════════════════════════════════════════════════════════════════

_RULES = _compile_rules()


class RuleEngine:
    """声明式规则引擎。"""

    def __init__(self, rules: list[Rule] = None):
        self.rules = rules or _RULES

    def apply(self, bag: dict) -> list[Finding]:
        findings = []
        for rule in self.rules:
            try:
                r = self._apply_one(rule, bag)
                if r:
                    findings.append(r)
            except Exception as e:
                print(f"[WARN] Rule '{rule.name}' failed: {e}", file=sys.stderr)
        return findings

    def _apply_one(self, rule: Rule, bag: dict) -> Optional[Finding]:
        if rule.custom_match:
            ev = rule.custom_match(bag)
            if ev and ev != "SKIP":
                return Finding(rule.weight, rule.category, f"{ev} ({rule.category})")
            return None
        texts, paths = self._get_texts(rule.scope, bag)
        if not texts:
            return None
        total = sum(len(p.findall(t)) for t in texts for p in rule.patterns)
        if total >= rule.min_matches:
            fp = paths[0] if paths else ""
            prefix = f"{fp}: " if fp else ""
            return Finding(rule.weight, rule.category,
                           f"{prefix}{rule.evidence} ({total}次) ({rule.category})")
        return None

    def _get_texts(self, scope: str, bag: dict) -> tuple[list[str], list[str]]:
        if scope == "code":
            code = bag.get("code", "")
            rp = bag.get("relpath", "")
            if code and rp:
                return ([code], [rp])
            cfs = bag.get("code_files", [])
            return ([c for _, c in cfs], [f for f, _ in cfs]) if cfs else ([], [])
        elif scope == "readme":
            rm = bag.get("readme", "")
            return ([rm], ["README"]) if rm else ([], [])
        elif scope == "manifest":
            try:
                t = json.dumps(bag.get("manifest", {}), ensure_ascii=False)
            except Exception:
                t = str(bag.get("manifest", ""))
            return ([t], ["manifest.json"]) if t else ([], [])
        elif scope == "any_text":
            ts, ps = [], []
            for fp, code in bag.get("code_files", []):
                ts.append(code); ps.append(fp)
            if bag.get("readme"):
                ts.append(bag["readme"]); ps.append("README")
            if bag.get("manifest"):
                try:
                    ts.append(json.dumps(bag["manifest"], ensure_ascii=False))
                    ps.append("manifest.json")
                except Exception:
                    pass
            return ts, ps
        elif scope == "filename":
            cfs = bag.get("code_files", [])
            return ([f for f, _ in cfs], [f for f, _ in cfs]) if cfs else ([], [])
        return [], []


# ═══════════════════════════════════════════════════════════════════════════════
# §7 判定引擎
# ═══════════════════════════════════════════════════════════════════════════════

_PRINCIPLE_SEVERITY = {
    "AST01": 10, "AST02": 9, "AST06": 8, "AST05": 7,
    "AST03": 6, "AST04": 5, "AST07": 4, "AST08": 3, "AST09": 2, "AST10": 1,
}

_THRESHOLD_MALICIOUS = 0.55
_THRESHOLD_SUSPICIOUS = 0.25


def _sigmoid_score(total_weight: float, n_evidence: int) -> float:
    """改进评分公式：sigmoid 变体。

    哲学：
      - 单强证据 (1个高权重finding) → 高置信度
      - 多弱证据 (N个低权重finding) → 逐渐收敛但不线性累加
      - 避免"100个0.01的证据也能判为malicious"
    
    公式: score = total / (2.0 + 0.3 * sqrt(n - 1))
          当 n=1:  divisor = 2.0
          当 n=4:  divisor ≈ 2.52
          当 n=16: divisor ≈ 3.16
    """
    import math
    divisor = 2.0 + 0.3 * math.sqrt(max(0, n_evidence - 1))
    # 单强证据加成
    if n_evidence == 1 and total_weight >= 0.85:
        total_weight *= 1.1
    return min(1.0, total_weight / divisor)


def _aggregate_verdict(skill_id: str, findings: list[Finding]) -> dict:
    """分层独立评估：每个 AST 类别独立评分。"""
    if not findings:
        return {"skill_id": skill_id, "verdict": VERDICT_BENIGN,
                "confidence": 0.0, "category": "",
                "evidence": "未发现可疑特征，判定为良性 Skill"}

    # 去重
    seen = {}
    for f in findings:
        if f.evidence not in seen or f.weight > seen[f.evidence].weight:
            seen[f.evidence] = f
    deduped = list(seen.values())

    # 按类别分组
    by_cat = {}
    for f in deduped:
        by_cat.setdefault(f.category, []).append(f)

    # 每类独立评分
    scores = {}
    for cat, fs in by_cat.items():
        total = sum(f.weight for f in fs)
        scores[cat] = _sigmoid_score(total, len(fs))

    if not scores:
        return {"skill_id": skill_id, "verdict": VERDICT_BENIGN,
                "confidence": 0.0, "category": "",
                "evidence": "未发现可疑特征，判定为良性 Skill"}

    best_cat = max(scores, key=lambda c: (scores[c], _PRINCIPLE_SEVERITY.get(c, 0)))
    best_conf = scores[best_cat]

    if best_conf >= _THRESHOLD_MALICIOUS:
        verdict = VERDICT_MALICIOUS
    elif best_conf >= _THRESHOLD_SUSPICIOUS:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN

    # 构建证据
    evidence = _build_evidence(deduped, best_cat, by_cat)
    return {"skill_id": skill_id, "verdict": verdict,
            "confidence": round(best_conf, 2),
            "category": best_cat, "evidence": evidence[:800]}


def _build_evidence(findings: list[Finding], primary_cat: str, by_cat: dict) -> str:
    parts = []
    primary = sorted([f for f in findings if f.category == primary_cat],
                     key=lambda x: x.weight, reverse=True)
    for f in primary[:3]:
        parts.append(f.evidence)
    other = [c for c in by_cat if c != primary_cat]
    if other:
        other.sort(key=lambda c: _PRINCIPLE_SEVERITY.get(c, 0), reverse=True)
        total_other = sum(len(v) for k, v in by_cat.items() if k != primary_cat)
        parts.append(f"交叉印证: {', '.join(other[:5])} 共 {total_other} 项")
    return "；".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# §8 公共接口
# ═══════════════════════════════════════════════════════════════════════════════

_engine = RuleEngine()


def analyze_skill(skill_id: str, skill_dir: pathlib.Path) -> dict:
    """对单个 Skill 包执行全量扫描并输出判定结果。"""
    bag = _collect_signals(skill_dir, skill_id)
    findings = []
    if bag.get("manifest_error"):
        findings.append(Finding(0.30, "AST04", f"manifest.json {bag['manifest_error']} (AST04)"))
    # 代码文件逐个扫描
    for relpath, code in bag.get("code_files", []):
        findings.extend(_engine.apply({**bag, "code": code, "relpath": relpath}))
    # README 扫描
    if bag.get("readme"):
        findings.extend(_engine.apply({
            "readme": bag["readme"], "code": bag["readme"], "relpath": "README",
            "manifest": bag.get("manifest", {}), "skill_dir": bag.get("skill_dir"),
            "code_files": bag.get("code_files", [])}))
    # manifest / 跨文件 / 目录级扫描
    findings.extend(_engine.apply({
        "manifest": bag.get("manifest", {}), "skill_dir": bag.get("skill_dir"),
        "code_files": bag.get("code_files", []), "skill_id": skill_id,
        "readme": bag.get("readme", ""), "code": "", "relpath": ""}))
    return _aggregate_verdict(skill_id, findings)


# ═══════════════════════════════════════════════════════════════════════════════
# §9 主入口
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """CLI 入口。"""
    try:
        input_dir = pathlib.Path(INPUT_BASE)
        output_dir = pathlib.Path(OUTPUT_BASE)
        output_path = output_dir / "results.jsonl"
        output_ok, write_error = True, None
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            t = output_dir / ".write_test"
            t.write_text("", encoding="utf-8")
            t.unlink(missing_ok=True)
        except (PermissionError, OSError) as e:
            output_ok, write_error = False, str(e)
            print(f"[ERROR] Cannot write to {OUTPUT_BASE}: {e}", file=sys.stderr)

        if not input_dir.exists():
            print(f"[INFO] Input dir not found: {INPUT_BASE}", file=sys.stderr)
            if output_ok:
                output_path.write_text("", encoding="utf-8")
            return 0

        try:
            skill_dirs = sorted([d for d in input_dir.iterdir()
                                  if d.is_dir() and not d.name.startswith(".")])
        except OSError:
            skill_dirs = []
        if not skill_dirs:
            print(f"[INFO] No skills under {INPUT_BASE}", file=sys.stderr)
            if output_ok:
                output_path.write_text("", encoding="utf-8")
            return 0

        results = []
        for sd in skill_dirs:
            sid = sd.name
            print(f"[INFO] Scanning: {sid}", file=sys.stderr)
            try:
                results.append(analyze_skill(sid, sd))
            except Exception as e:
                print(f"[ERROR] Scan failed for {sid}: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                results.append({"skill_id": sid, "verdict": VERDICT_SUSPICIOUS,
                                "confidence": 0.3, "category": "AST08",
                                "evidence": f"Engine scan error: {e} (AST08)"})

        if output_ok:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    for row in results:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                print(f"[INFO] Wrote {len(results)} results to {output_path}", file=sys.stderr)
            except (PermissionError, OSError) as e:
                print(f"[ERROR] Write failed: {e}", file=sys.stderr)
        else:
            print(f"[WARN] Output not writable ({write_error}), printing to stdout", file=sys.stderr)
            for row in results:
                print(json.dumps(row, ensure_ascii=False, default=str))
        return 0
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
