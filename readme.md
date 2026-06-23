# Skill-CTF Track B — 蓝队检测引擎

基于**第一性原理**的声明式静态分析引擎，用于检测 AI Agent Skill 包中的恶意行为。参加 Skill-CTF 赛道 B（蓝队检测挑战）的提交作品。

---

## 项目结构

```
skill-ctf/
├── engine/                          ← 引擎提交目录
│   ├── Dockerfile                   ← 镜像构建文件
│   ├── engine/engine.py             ← 核心检测引擎
│   ├── design.md                    ← 设计方案说明
│   ├── self_test_report.md          ← 自测报告
│   ├── results.example.jsonl        ← 输出示例
│   └── submission.json              ← 提交元数据
│
├── docs/                            ← 参考资料
│   ├── owasp-ast01-10-reference.md
│   └── skill-package-format.md
│
├── test_samples/                    ← 测试样本（gitignored）
├── test_output/                     ← 测试输出（gitignored）
├── test_local.sh                    ← 本地测试脚本
├── project-context.md               ← AI 项目上下文
└── readme.md                        ← 本文件
```

## 引擎概述

纯 Python 规则引擎，**零外部依赖**，通过多层静态分析检测恶意 Skill 包：

- **10 项安全原则**覆盖 OWASP AST01-10
- **声明式规则引擎** — 规则与执行逻辑分离，易于扩展
- **纵深防御** — manifest / 代码 / README 三个独立检测层面
- **召回率优先** — 阈值偏低（0.55/0.25），匹配 F₂ 评分体系

### 核心检测能力

| 安全边界 | 覆盖的 AST 类别 | 检测要点 |
|----------|----------------|---------|
| 代码边界 | AST01 | exec/eval/subprocess/os.system 等危险函数 |
| 网络边界 | AST01 | 请求外发、C2 通信、反向隧道、IM webhook |
| 供应链边界 | AST02 | 依赖混淆、包名仿冒（typosquatting） |
| 权限边界 | AST03/04 | 声明 vs 实际行为一致性、身份伪造 |
| 反序列化边界 | AST05 | pickle/yaml/marshal 不安全反序列化 |
| 隔离边界 | AST06 | 容器逃逸（/proc/1/、docker socket、nsenter） |
| 更新链边界 | AST07 | 自动更新无完整性校验 |
| 指令边界 | AST08 | Agent 注入、社交工程指令 |
| 加密边界 | AST09 | 弱加密、硬编码凭据、不安全随机 |
| 平台边界 | AST10 | 跨平台攻击面、Polyglot 文件 |

### 检测流水线

```
Skill 包 → manifest 扫描 → 代码多模式扫描 → README 扫描 → 聚合判定
```

## 快速开始

### 构建镜像

```bash
docker build -t skill-engine:latest engine
```

### 运行检测

```bash
docker run --rm \
  -v "/path/to/test_samples:/data/skills" \
  -v "/path/to/test_output:/output" \
  skill-engine:latest
```

### 查看结果

```bash
cat /path/to/test_output/results.jsonl
```

### 检查镜像大小

```bash
docker save skill-engine:latest | gzip | wc -c | python -c \
  "import sys; print(f'{int(sys.stdin.read()) / 1024 / 1024:.2f}MB')"
```

## 输出格式

每行一个 JSON 对象（JSONL 格式）：

```json
{
  "skill_id": "skill-xxx",
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0~1.0,
  "category": "AST01~AST10",
  "evidence": "检测依据描述"
}
```

## 技术栈

- **语言**: Python 3.12
- **依赖**: 零外部依赖（仅 Python 标准库）
- **基础镜像**: `python:3.12.8-slim-bookworm`
- **镜像大小**: ~11.76MB（压缩后）