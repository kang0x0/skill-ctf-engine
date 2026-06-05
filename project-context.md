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
├── readme.md                           ← 比赛规则文档
├── test_local.sh                       ← 本地自测脚本
├── .gitignore                          ← Git 忽略规则
│
├── track-b-sample-ast01-v01/           ← 提交目录（比赛提交材料）
│   ├── Dockerfile                      ← 镜像构建文件（alpine:3.20 + python3）
│   ├── engine/
│   │   └── engine.py                   ← 核心检测引擎（11 个扫描器）
│   ├── design.md                       ← 设计方案说明
│   ├── self_test_report.md             ← 自测报告
│   ├── results.example.jsonl           ← 输出示例
│   └── submission.json                 ← 提交元数据（已填 team_id/image_digest/image_ref）
│
├── docs/                               ← 参考资料
│   ├── owasp-ast01-10-reference.md
│   └── skill-package-format.md
│
├── test_samples/                       ← 测试样本（不提交）
│   ├── skill-benign-001/               ← 良性样本
│   ├── skill-malicious-001/            ← 恶意样本（os.system + hooks + 敏感文件）
│   ├── skill-suspicious-001/           ← 可疑样本（权限过度）
│   └── skill-stealth-002/              ← 隐蔽恶意样本（远程载荷执行链 + 权限不一致 + Agent 注入）
│
└── test_output/                        ← 测试输出（不提交）
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
置信度 = min(1.0, 总权重 / 2.0)

判定阈值：
  confidence ≥ 0.6  → malicious
  confidence ≥ 0.25 → suspicious
  其余             → benign

category = 权重最高的发现项的 AST 类别
```

### 11 个扫描器清单

| # | 扫描器 | 检测内容 | 主要 AST |
|---|--------|---------|---------|
| 1 | `scan_manifest` | manifest.json — typosquatting、权限过度、hooks、依赖混淆 | AST02/03/04 |
| 2 | `scan_code_exec` | exec/eval/os.system/subprocess 等危险函数 | AST01 |
| 3 | `scan_network` | requests/urllib/socket/硬编码 URL | AST01 |
| 4 | `scan_file_access` | .env/id_rsa/credentials/token 等敏感路径 | AST01 |
| 5 | `scan_obfuscation` | Base64/85/32/16 编码、多编码组合、高熵字符串 | AST01 |
| 6 | `scan_deserialization` | pickle/yaml/marshal 不安全反序列化 | AST05 |
| 7 | `scan_escape` | 容器逃逸 — /proc/1/、docker socket、nsenter | AST06 |
| 8 | `scan_remote_execution_chain` 🆕 | 远程拉取 + 解码 + 执行三级行为链 | AST01 |
| 9 | `scan_readme` | 社交工程指令 + Agent 指令注入（12 种模式） | AST01 |
| 10 | `scan_update_verification` | 自动更新无完整性校验 | AST07 |
| 11 | `scan_permission_consistency` 🆕 | manifest 权限声明与代码行为不一致 | AST08 |

### 设计哲学

- **纵深防御**：manifest / 代码 / README 三个独立层面，单一维度被绕过仍有其他维度兜底
- **召回率优先**：阈值偏低（0.6），匹配 F₂ 评分
- **可解释性**：每条发现带 evidence 字段
- **零外部依赖**：纯 Python 标准库 + 正则匹配

---

## 四、改进历程（基于腾讯安全文章）

参考文章 https://security.tencent.com/index.php/blog/msg/224 中实际恶意样本绕过了 ClawHub 官方检测，暴露的短板及修复：

| 短板 | 原引擎 | 改进后 |
|------|-------|--------|
| 仅检测 Base64 | 只匹配 `[A-Za-z0-9+/]{40,}` | 支持 Base64/85/32/16 + 多编码组合检测 |
| 未检测行为链 | 单独检测网络/解码/执行 | `scan_remote_execution_chain` 检测三级链（权重 0.95）|
| README 检测不足 | 8 条短语 | 新增 12 条 Agent 指令注入模式 |
| 权限一致性 | 只检"权限过大" | 新增"声明与行为不一致"检测（网络/文件系统/shell） |

---

## 五、Docker 构建

### Dockerfile 要点

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache python3 && \
    rm -rf /usr/lib/python3.12/test/ /usr/lib/python3.12/idlelib/ \
           /usr/lib/python3.12/turtledemo/ /usr/lib/python3.12/ensurepip/ \
           /usr/lib/python3.12/pip-*/ /usr/lib/python3.12/site-packages/pip/ \
           /var/cache/apk/*
COPY engine/engine.py /app/engine.py
ENTRYPOINT ["python3", "/app/engine.py"]
```

- 镜像压缩后大小：**11.76MB**（< 16MB 限制 ✅）

### 构建与测试命令

```bash
# 构建
docker build -t skill-engine:latest track-b-sample-ast01-v01

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

## 六、Git 操作

```bash
# 初始化
cd d:/育根/学习/网络安全/skill-ctf
git init
git add .
git commit -m "feat: Skill-CTF Track B detection engine"

# 推送到 GitHub
git remote add origin https://github.com/你的用户名/skill-ctf-engine.git
git push -u origin main
```

---

## 七、Docker 镜像推送

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

## 八、已填写的提交信息

**文件**：`track-b-sample-ast01-v01/submission.json`

| 字段 | 值 |
|------|-----|
| `team_id` | `lx_c6834e` |
| `image_digest` | `sha256:7c164116739e002caace43a5b73fadb155445098b6c96d13d736bb60146ee239` |
| `image_ref` | `ghcr.io/kang0x0/skill-ctf-engine:latest` |
| `design_ref` | `design.md` |
| `self_test_report_ref` | `self_test_report.md` |

---

## 九、待办 / 下一步

- [ ] 确认比赛提交平台 URL 及提交流程，完成最终提交
- [ ] 补充性能基准数据（单 Skill 检测耗时、Token 消耗量）到 `self_test_report.md`
- [ ] 如需更新镜像，重新构建 → 推送 → 更新 submission.json 中的 digest
- [ ] 如需更新代码，commit → push → 重新构建 & 推送镜像