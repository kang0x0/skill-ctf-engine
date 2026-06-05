# OWASP Agentic Skills Top 10 (AST01-10) 分类参考

> 来源：OWASP Agentic Skills Top 10（OWASP Foundation, Q1 2026）
> 项目地址：https://github.com/kenhuangus/agentic-skills-top-10

## 概述

这是 **OWASP Agentic Skills Top 10（AST10）** 标准，覆盖 AI Agent Skills 生态中 10 个最关键的安全风险。
Skill-CTF 赛道 B 的可解释性评分要求引擎输出的 `category` 字段与标准答案的 OWASP AST 主类别精确匹配。

---

## 十类风险详细说明

### AST01 — Malicious Skills（恶意技能）
- **严重性**: Critical
- **攻击机制**: 攻击者在 Skills 市场发布看似合法的技能包，实际嵌入隐藏的恶意 Payload——凭据窃取器、反向 shell、后门、社交工程指令
- **特点**: 同时利用代码层（shell 脚本、Python 调用）和自然语言指令层（Markdown 文本指示 Agent 执行窃取操作）
- **真实案例**: ClawHavoc 活动（2026/01）——1,184 个恶意 Skills，投递 AMOS 窃取加密钱包、SSH keys、浏览器凭据
- 对应检查要点：恶意代码注入、凭据窃取、后门植入、隐蔽执行

### AST02 — Supply Chain Compromise（供应链攻陷）
- **严重性**: Critical
- **攻击机制**: Skills 注册表和分发渠道缺乏成熟生态已有的 provenance 控制。攻击者通过注册为开发者发布恶意包，或对已有流行 Skills 进行供应链注入
- **真实案例**: ClawHavoc：12 个 publisher 账户发布了 1,184 个恶意 Skills；CVE-2025-59536（CVSS 8.7）
- 对应检查要点：依赖链污染、注册表投毒、配置文件劫持

### AST03 — Over-Privileged Skills（权限过载）
- **严重性**: High
- **攻击机制**: Skills 声明了超出其功能所需的系统权限，导致即使是无意恶意的 Skill 也能造成大规模凭据泄露
- **真实案例**: Snyk（2026/02）发现 280+ 个" leaky Skills"——权限过度扩张导致 API keys 和 PII 大规模暴露
- 对应检查要点：权限声明过大、过度文件/网络访问、超出功能需要

### AST04 — Insecure Metadata（不安全元数据）
- **严重性**: High
- **攻击机制**: Skill 的元数据（名称、描述、版本号）可被攻击者操控，用于 typosquatting（相似名称伪造）和 brand impersonation（品牌仿冒）
- **真实案例**: ClawHub 上的仿冒"Google""Solana wallet tracker"等恶意 Skills
- 对应检查要点：名称仿冒、品牌冒充、元数据篡改

### AST05 — Unsafe Deserialization（不安全反序列化）
- **严重性**: High
- **攻击机制**: Skills 依赖 YAML/JSON 反序列化传递配置和脚本引用，攻击者可在这些文件中注入 Payload，利用不安全的反序列化触发代码执行
- 对应检查要点：不安全反序列化、YAML/JSON 注入、配置数据篡改

### AST06 — Weak Isolation（弱隔离）
- **严重性**: High
- **攻击机制**: Skills 执行时缺乏强隔离，恶意或半恶意 Skills 可突破容器边界访问宿主机资源
- **真实案例**: OpenClaw host-mode 执行 + 135,000+ 公网暴露实例
- 对应检查要点：容器逃逸、沙箱绕过、宿主机资源访问

### AST07 — Update Drift（更新漂移）
- **严重性**: Medium
- **攻击机制**: 已安装的 Skills 在作者发布更新后自动接收更新，但缺乏 hash 验证机制——攻击者可推送恶意更新版本，覆盖原本审查通过的版本
- **真实案例**: ClawJacked（CVE-2026-28363，CVSS 9.9）
- 对应检查要点：自动更新劫持、hash 校验绕过、版本回滚攻击

### AST08 — Poor Scanning（劣质扫描）
- **严重性**: Medium
- **攻击机制**: 现有的 Skill 安全扫描工具依赖模式匹配，无法检测利用自然语言指令操控的威胁
- **真实案例**: Snyk（2026/02）演示 pattern-matcher 如何被自然语言指令注入绕过
- 对应检查要点：自然语言指令注入、语义层面的恶意行为、非代码特征攻击

### AST09 — No Governance（无治理）
- **严重性**: Medium
- **攻击机制**: 企业缺乏 Skills 清单和 Agent 身份控制机制，导致影子 AI Agent 部署蔓延，安全团队毫无感知
- **真实案例**: 53,000+ OpenClaw 实例关联至先前入侵活动，企业 SOC 无可见性
- 对应检查要点：影子部署、无审计记录、越权使用

### AST10 — Cross-Platform Reuse（跨平台复用）
- **严重性**: Medium
- **攻击机制**: 恶意 Skills 可低成本移植到不同平台的 Skills 注册表，复用同一套攻击手法
- 对应检查要点：多平台恶意 Skill 传播、跨平台攻击手法复用

---

## 评分映射说明

在比赛中，你的检测引擎对每个 Skill 包输出 verdict（benign/malicious/suspicious）的同时，
**必须**输出 `category` 字段（AST01-10 中的一个），才能获得可解释性分数。

| 检测出的恶意行为类型 | 应输出的 category |
|---------------------|-------------------|
| 包含隐藏恶意代码/后门/窃密器 | AST01 |
| 存在依赖投毒/供应链篡改 | AST02 |
| 权限声明远超实际需要 | AST03 |
| 仿冒知名品牌/typosquatting | AST04 |
| 利用不安全反序列化的配置 | AST05 |
| 尝试突破沙箱/容器隔离 | AST06 |
| 缺乏更新验证机制 | AST07 |
| 使用模式匹配绕过/指令注入绕过 | AST08 |
| 无治理/审计痕迹的影子部署 | AST09 |
| 跨平台复用的恶意 Skill | AST10 |

> **注意**: 对于 benign 的 Skill，可以输出 `"category": ""` 或省略 category 字段。
> 对于 suspicious 的 Skill，根据疑似的恶意类型输出最匹配的 AST 类别。