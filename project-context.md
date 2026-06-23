# Skill-CTF Track B — 蓝队检测引擎项目说明

> 本文件用于在其他设备上重新提供给 AI，快速恢复项目上下文。

---

## 一、项目概述

- **比赛**：Skill-CTF 赛道 B（蓝队检测挑战）
- **任务**：开发基于规则的静态分析引擎，检测 AI Agent Skill 包中的恶意行为
- **评分标准**：F₂ 分数（召回率权重为精确率的 4 倍，偏向减少漏报）
- **镜像限制**：压缩后 ≤ 16MB
- **镜像仓库**：`ghcr.io/kang0x0/skill-ctf-engine:latest`

### 关键链接

- 腾讯安全文章（改进参考）：https://security.tencent.com/index.php/blog/msg/224
- OWASP Agentic Skills Top 10：自行搜索 "OWASP AST10"

---

## 二、目录结构

```
skill-ctf/                              ← 项目根目录
├── readme.md                           ← 项目说明文档
├── test_local.sh                       ← 本地自测脚本
├── .gitignore                          ← Git 忽略规则
├── project-context.md                  ← 本文件（AI 上下文）
│
├── engine/                             ← 引擎提交目录
│   ├── Dockerfile                      ← 镜像构建文件（python:3.12.8-slim-bookworm）
│   ├── engine/
│   │   └── engine.py                   ← 核心检测引擎（声明式规则引擎，v4）
│   ├── design.md                       ← 设计方案说明
│   ├── self_test_report.md             ← 自测报告
│   ├── results.example.jsonl           ← 输出示例
│   └── submission.json                 ← 提交元数据（已填 team_id/image_digest/image_ref）
│
├── docs/                               ← 参考资料
│   ├── owasp-ast01-10-reference.md
│   └── skill-package-format.md
│
├── test_samples/                       ← 测试样本（不提交，gitignored）
│   ├── skill-benign-001/               ← 良性样本（Hello World）
│   ├── skill-malicious-001/            ← 恶意样本（os.system + hooks + 敏感文件）
│   ├── skill-suspicious-001/           ← 可疑样本（权限过度）
│   └── skill-injection-001/            ← Agent 注入测试样本
│
└── test_output/                        ← 测试输出（不提交，gitignored）
    └── results.jsonl
```

---

## 三、引擎架构

### 输入/输出接口

- **输入目录**：`/data/skills/{skill_id}/`
- **输出文件**：`/output/results.jsonl`（每行一个 JSON 对象）
- **输出格式**：

```json
{
  "skill_id": "skill-xxx",
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0~1.0,
  "category": "AST01|AST02|...",
  "evidence": "自然语言描述"
}
```

### 判定逻辑

```
总权重 = sum(all findings[weight])
置信度 = sigmoid(总权重, evidence_count)

判定阈值：
  confidence ≥ 0.55 → malicious
  confidence ≥ 0.25 → suspicious
  其余             → benign

category = 权重最高的发现项的 AST 类别
```

### 设计哲学（第一性原理）

Skill 安全问题的本质是"边界被突破"，引擎围绕 10 项安全原则构建：

1. **代码边界 (AST01)** — 任意代码/命令执行
2. **供应链边界 (AST02)** — 依赖/资源完整性，包名仿冒
3. **权限边界 (AST03/04)** — 声明 vs 实际行为，身份伪造
4. **反序列化边界 (AST05)** — 数据 → 代码转换，配置注入
5. **隔离边界 (AST06)** — 容器/沙箱逃逸
6. **更新链边界 (AST07)** — 自动更新投毒
7. **指令边界 (AST08)** — Agent 注入，社交工程，自然语言操控
8. **加密边界 (AST09)** — 弱加密，硬编码凭据，不安全随机
9. **平台边界 (AST10)** — 跨平台攻击面，Polyglot
10. **运行时边界 (AST01)** — 反分析，延时炸弹，文件伪装

### 架构 = 信号采集 → 声明式规则引擎 → 分层独立评估

### 引擎核心特性

- **声明式规则系统**：规则与执行逻辑分离，通过 `Rule` 数据类定义，支持正则匹配和自定义检测函数
- **预编译正则**：所有正则表达式编译为模块级常量，提升运行时性能
- **Sigmoid 评分公式**：替代简单的线性累加，更平滑的置信度分布
- **跨文件分析**：检测跨文件的攻击链（下载器 + 执行器分离）
- **深度检测**：远程执行链分析、污点追踪、导入别名混淆、PII 泄露检测

### 检测流水线

```
Skill 包 (/data/skills/{skill_id}/)
        │
        ├── manifest.json ──→ manifest 扫描 ──→ AST02/03/04
        │
        ├── *.py/*.js/*.sh ──→ 声明式规则引擎 ──→ AST01/05/06/09/10
        │
        ├── README.md ──────→ README 扫描 ────→ AST01/AST08
        │
        └── 聚合判定 ───────→ _aggregate_verdict() → verdict + confidence + category
```

---

## 四、改进历程（基于腾讯安全文章）

参考文章 https://security.tencent.com/index.php/blog/msg/224 中实际恶意样本绕过了 ClawHub 官方检测，暴露的短板及修复：

| 短板 | 原引擎 | 改进后 |
|------|-------|--------|
| 仅检测 Base64 | 只匹配 `[A-Za-z0-9+/]{40,}` | 支持 Base64/85/32/16 + 多编码组合检测 |
| 未检测行为链 | 单独检测网络/解码/执行 | 远程执行链检测（三级链，权重 0.95） |
| README 检测不足 | 8 条短语 | 新增 12 条 Agent 指令注入模式 |
| 权限一致性 | 只检"权限过大" | 新增声明与行为不一致检测（网络/文件系统/shell） |

### v4 版本主要优化

- 修复中文代码检测返回值 bug
- 补充 URL 分析（可疑 TLD / IP URL / raw GitHub）
- 补充文件类型伪装、Agent 段落计数
- 改进评分公式为 sigmoid 变体
- 补充 PII 敏感信息宽度检测
- 预编译所有正则到模块级常量
- 新增污点追踪检测（外部输入→危险执行数据流）
- 新增导入别名混淆检测

---

## 五、Docker 构建

### Dockerfile 要点

```dockerfile
FROM python:3.12.8-slim-bookworm

RUN groupadd --system skillsec && useradd --system --gid skillsec --create-home --home-dir /home/skillsec skillsec

WORKDIR /app
COPY --chown=skillsec:skillsec engine/engine.py /app/engine.py

RUN mkdir -p /output && chown skillsec:skillsec /output && chmod 755 /output

ENV PYTHONUNBUFFERED=1
USER skillsec
ENTRYPOINT ["python", "/app/engine.py"]
```

- 基础镜像：`python:3.12.8-slim-bookworm`
- 非 root 用户运行（skillsec）
- 镜像压缩后大小：**11.76MB**（< 16MB 限制 ✅）

### 构建与测试命令

```bash
# 构建
docker build -t skill-engine:latest engine

# 运行（Git Bash 中，用 Windows 路径格式）
docker run --rm \
  -v "d:/育根/学习/网络安全/skill-ctf/test_samples:/data/skills" \
  -v "d:/育根/学习/网络安全/skill-ctf/test_output:/output" \
  skill-engine:latest

# 查看结果
cat "d:/育根/学习/网络安全/skill-ctf/test_output/results.jsonl"

# 检查镜像压缩后大小
docker save skill-engine:latest | gzip | wc -c | python -c "import sys; print(f'{int(sys.stdin.read()) / 1024 / 1024:.2f}MB')"
```

---

## 六、Docker 镜像推送

```bash
# 登录 ghcr.io
echo "你的GITHUB_TOKEN" | docker login ghcr.io -u 你的GitHub用户名 --password-stdin

# 打标签 && 推送
docker tag skill-engine:latest ghcr.io/你的GitHub用户名/skill-ctf-engine:latest
docker push ghcr.io/你的GitHub用户名/skill-ctf-engine:latest

# 获取 digest
docker inspect ghcr.io/你的GitHub用户名/skill-ctf-engine:latest \
  --format='{{index .RepoDigests 0}}'
```

⚠️ 镜像需设为 **Public**（GitHub Packages 设置中修改），否则比赛平台无法拉取。

---

## 七、Git 仓库

- **远程仓库**: https://github.com/kang0x0/skill-ctf-engine
- **默认分支**: `main`

---

## 八、已填写的提交信息

**文件**：`engine/submission.json`

| 字段 | 值 |
|------|-----|
| `team_id` | `lx_c6834e` |
| `engine_version` | `1.0.0` |
| `image_digest` | `sha256:0d70006c8edd5925023d64faadf56f5aa648d5b383d05cf881e227b240ebd96e` |
| `design_ref` | `design.md` |
| `self_test_report_ref` | `self_test_report.md` |

---

## 九、自测结果

| 测试用例 | 判定 | 置信度 | 类别 |
|---------|------|--------|------|
| skill-benign-001 | benign | 0.0 | — |
| skill-malicious-001 | malicious | 0.9 | AST01 |
| skill-suspicious-001 | suspicious | 0.4 | AST03 |

- 召回率：100%
- 精确率：100%
- F₂ Score：1.0