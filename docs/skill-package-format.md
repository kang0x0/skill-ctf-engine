# Skill 包格式说明

> 比赛输入路径: `/data/skills/{skill_id}/`
> 每个 Skill 包包含: `manifest.json` + 代码 + 资源

## 一、什么是 Skill 包？

Skill（技能包）是 AI Agent 的可复用行为单元，用于编码完整的工作流程，包括：
- 任务理解与目标分解
- 多步骤规划与工具编排
- 文件系统、网络和 Shell 访问
- 安全护栏与输出格式化
- 持久化记忆与跨会话状态

比赛的 Skill 包采用类似 Claude Code / OpenClaw 生态的打包格式。

---

## 二、Skill 包目录结构（预期）

```
/data/skills/{skill_id}/
├── manifest.json          # 元数据清单（必需）
├── *.py / *.js / *.sh     # 代码文件（Skill 逻辑）
├── assets/                # 资源目录（可选）
│   ├── images/
│   ├── templates/
│   └── config/
└── README.md              # 说明文档（可选）
```

---

## 三、manifest.json 字段定义（预期格式）

比赛中的 manifest.json 参考了 AI Agent Skills 生态的通用格式，关键字段包括：

```json
{
  "name": "skill-名称",
  "version": "1.0.0",
  "description": "技能描述",
  "author": {
    "name": "作者名",
    "id": "publisher-id"
  },
  "permissions": {
    "network": false,
    "filesystem": ["read", "write"],
    "shell": false,
    "tools": ["read-file", "write-file"]
  },
  "entry": "main.py",
  "dependencies": {
    "python": ["requests==2.31.0"],
    "skills": ["dependency-skill-id"]
  },
  "risk_tier": "L0",
  "hooks": {
    "pre_install": "pre_install.sh",
    "post_install": "post_install.sh"
  }
}
```

### 常用字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | Skill 名称（可能被用于 typosquatting） |
| `version` | string | 版本号 |
| `description` | string | 功能描述 |
| `author` | object | 作者信息（可能被伪造） |
| `permissions` | object | 权限声明（关键安全字段） |
| `entry` | string | 入口文件路径 |
| `dependencies` | object | 依赖声明 |
| `hooks` | object | 安装钩子（高风险，可执行任意命令） |
| `risk_tier` | string | 自声明的风险等级 |

---

## 四、Chrome Extension 风格的 manifest.json（备选格式）

另一种常见的 Skill 格式参考 Chrome Extension 标准：

```json
{
  "manifest_version": 3,
  "name": "Skill 名称",
  "version": "1.0",
  "description": "功能描述",
  "permissions": ["storage", "activeTab"],
  "host_permissions": ["https://api.example.com/*"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}
```

---

## 五、须重点关注的恶意特征

在检测 Skill 包时，应重点检查以下方面：

### 5.1 manifest.json 层面

| 检查点 | 说明 | 关联 AST |
|--------|------|----------|
| 权限过度声明 | 简单功能却申请 shell/filesystem 权限 | AST03 |
| 名称仿冒 | 名称与知名品牌高度相似（typosquatting） | AST04 |
| hooks 字段 | 含 pre_install/post_install 等可执行钩子 | AST01 |
| 依赖引用异常 | 依赖名称拼写相似（依赖混淆） | AST02 |
| 风险等级不符 | 声明 L0 但含高风险操作 | AST04 |

### 5.2 代码层面

| 检查点 | 说明 | 关联 AST |
|--------|------|----------|
| exec/eval/subprocess 调用 | 执行任意系统命令 | AST01 |
| 网络请求到未知端点 | 数据外传（C2 通信） | AST01 |
| 文件读取敏感路径 | 读取 .env、SSH key、钱包文件 | AST01 / AST03 |
| base64 编码/混淆代码 | 隐藏恶意 Payload | AST01 |
| YAML/JSON 反序列化 | 不安全的反序列化调用 | AST05 |
| 容器/沙箱逃逸尝试 | 尝试突破环境隔离 | AST06 |

### 5.3 自然语言指令层面

| 检查点 | 说明 | 关联 AST |
|--------|------|----------|
| README 中含误导性指令 | 指示用户执行危险操作 | AST01 / AST08 |
| 社会工程提示 | 要求关闭安全防护 | AST01 |
| 行为描述与实际不符 | 说明中声称的功能与代码不符 | AST08 |

---

## 六、各平台 Skill 格式对照

| 平台 | 格式 | 主要风险文件 |
|------|------|-------------|
| OpenClaw | SKILL.md（YAML frontmatter + Markdown） | SKILL.md, SOUL.md, MEMORY.md |
| Claude Code | skill.json / YAML + scripts/ | .claude/settings.json, hooks config |
| Cursor / Codex | manifest.json + handler scripts | manifest.json, tool configs |
| VS Code | package.json + extensions | package.json, extension.ts |
| **本比赛** | **manifest.json + 代码 + 资源** | **manifest.json, 代码文件** |