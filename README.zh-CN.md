<p align="center">
  <img src="assets/icon.svg" width="128" height="128" alt="claw-guard icon">
</p>

<h1 align="center">claw-guard</h1>

<p align="center">
  AI 驱动的 OpenClaw 宿主系统安全审计工具。<br>
  35 条内置检测规则，11 个安全分类，可通过 Skill 扩展，支持 24 个 LLM 提供商的攻击链分析。
</p>

<p align="center">
  不检查 OpenClaw 配置对不对，而是检查：<b>OpenClaw 装在你的系统上之后，你的系统还安全吗？</b>
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

## 快速开始

```sh
# 一键安装（macOS / Linux）
curl -fsSL install9.ai/claw-guard | sh

# Windows (PowerShell)
# irm https://install9.ai/claw-guard-win | iex

# 运行审计（自动上传到 install9，服务端做 AI 分析）
claw-guard

# 使用自己的 API Key 做本地 AI 分析
export CLAW_GUARD_API_KEY=sk-ant-xxx
./claw-guard

# 使用其他 LLM 提供商
./claw-guard --provider openai --model gpt-4o
./claw-guard --provider ollama --model llama3
./claw-guard --provider deepseek --model deepseek-chat

# 完全离线模式（不上传、不远程分析）
./claw-guard --no-upload

# 列出所有支持的 LLM 提供商
./claw-guard --list-providers

# 列出所有规则 + Skill
./claw-guard --list-rules

# 升级到最新版本
./claw-guard --upgrade

# 清除本地数据（~/.claw-guard/）
./claw-guard --purge-data
```

## 示例输出

```
  claw-guard v0.4.0 — my-server  (linux)
  2026-03-10T17:00:00+00:00

  ── Category Breakdown ──
  ✗ Credential Exposure             8 checks   6 fail   0 warn
  ✗ Destructive Action Protection   4 checks   3 fail   1 warn
  ✗ Cost Safety                     3 checks   2 fail   0 warn
  ✓ Gateway Configuration           4 checks   0 fail   0 warn
  ✓ File System Security            6 checks   0 fail   0 warn
  ...

  ── Findings ──
  ✗ [CRITICAL] CG-C001 (Credential directory permissions)
    ~/.aws is world-readable (mode 755)
    evidence: path=~/.aws mode=755 name=aws_credentials
    fix: chmod 700 on credential directories.

  ✗ [CRITICAL] CG-M001 (API cost limit not configured)
    No API cost or rate limits configured.
    fix: Set cost limits in openclaw.json.

  ── AI Analysis ──────────────────────────────────

  Summary:
  你的系统存在凭证窃取攻击链：~/.aws 全局可读，且 shell history
  中出现 API 密钥模式。

  Attack Chains:
  1. [High] 通过凭证泄露接管云账户
     CG-C001 + CG-C003 + CG-S001 → AWS 账户接管
  2. [High] 失控 Agent 造成财务损失
     CG-M001 + CG-M003 + CG-X001 → 不可控 API 消费

  Priority Fixes:
  1. chmod 700 ~/.aws ~/.ssh ~/.docker
     ← 阻断凭证窃取链 (CG-C001)

  ─────────────────────────────────────────────────

╔══════════════════════════════════════════════════╗
║              Audit Result Summary                ║
╚══════════════════════════════════════════════════╝
  Score:    52/100  [██████████░░░░░░░░░░] Poor
  Rules: 35  |  Pass: 24  Fail: 20  Warn: 5  Skip: 0
  !! 9 CRITICAL finding(s) !!
  !  6 HIGH finding(s)
```

退出码：`0` 正常，`1` 存在 HIGH，`2` 存在 CRITICAL。适合 CI/CD 集成。

## AI 分析

claw-guard 使用 LLM 进行深度分析——不只是 pass/fail，而是识别**攻击链**（多个发现组合形成的可利用路径），按影响排序修复优先级，并提供环境相关建议。

### 双模式

| 模式 | 方式 | 适用场景 |
|------|------|----------|
| **本地** (默认) | 使用你自己的 API Key，分析在本地执行 | 隐私优先、离线环境 |
| **远程**（自动降级） | 未配置 API Key — 上传时由 install9 平台分析 | 零配置、持续监控 |

### 支持的提供商（24 个）

使用 `--list-providers` 查看所有提供商及其默认模型和 API 地址。

| 提供商 | 参数 | 默认模型 |
|--------|------|----------|
| Anthropic | `--provider anthropic` | claude-sonnet-4-20250514 |
| OpenAI | `--provider openai` | gpt-4o |
| Ollama（本地） | `--provider ollama` | llama3 |
| vLLM（本地） | `--provider vllm` | default |
| OpenRouter | `--provider openrouter` | anthropic/claude-sonnet-4-20250514 |
| Together AI | `--provider together` | meta-llama/Llama-3-70b-chat-hf |
| Mistral | `--provider mistral` | mistral-large-latest |
| DeepSeek | `--provider deepseek` | deepseek-chat |
| NVIDIA | `--provider nvidia` | meta/llama-3.1-70b-instruct |
| Moonshot（Kimi） | `--provider moonshot` | moonshot-v1-8k |
| GLM（智谱 AI） | `--provider glm` | glm-4 |
| Qwen（阿里通义） | `--provider qwen` | qwen-max |
| MiniMax | `--provider minimax` | abab6.5s-chat |
| Hugging Face | `--provider huggingface` | meta-llama/Llama-3-70b-chat-hf |
| 千帆（百度） | `--provider qianfan` | ernie-4.0-8k |
| Amazon Bedrock | `--provider bedrock` | anthropic.claude-sonnet-4-20250514-v1:0 |
| Cloudflare AI Gateway | `--provider cloudflare` | @cf/meta/llama-3-8b-instruct |
| Vercel AI Gateway | `--provider vercel` | gpt-4o |
| LiteLLM | `--provider litellm` | gpt-4o |
| Venice | `--provider venice` | llama-3.1-405b |
| 小米 | `--provider xiaomi` | xiaomi-ai-large |
| Z.AI | `--provider zai` | default |
| Kilocode | `--provider kilocode` | default |
| OpenCode Zen | `--provider opencode-zen` | default |

支持通过 `--base-url` 使用自定义 OpenAI 兼容端点：

```sh
# 使用 Anthropic API Key（默认提供商）
export CLAW_GUARD_API_KEY=sk-ant-xxx
claw-guard

# 使用 Ollama（完全离线，无需认证）
claw-guard --no-upload --provider ollama --model llama3

# 自定义端点
claw-guard --provider openai --base-url http://my-proxy:8080

# 没有 API Key？直接运行 — 服务端自动分析
claw-guard
```

## 评分模型

claw-guard 使用**加权分类通过率模型**（参考 AWS Security Hub / CIS Benchmarks）：

- 11 个分类，每个分类有重要性权重（总计 = 100）
- 分类内按严重级别加权计算通过率
- 单个分类无法将总分拖至零分
- 警告得 50% 分数，跳过得 80% 分数

| 分类 | 权重 | 说明 |
|------|------|------|
| 沙箱隔离 | 15 | 最关键的安全控制 |
| 凭证暴露 | 12 | 凭证窃取 → 完全沦陷 |
| 网络暴露 | 12 | 网络暴露 → 远程攻击入口 |
| 网关配置 | 10 | 网关认证 → 命令执行 |
| 破坏性操作防护 | 10 | 防止 rm -rf / 数据丢失 |
| 进程安全 | 10 | 进程沦陷 → 宿主接管 |
| 费用安全 | 8 | API 滥用导致的财务风险 |
| 数据泄露 | 8 | 数据外泄 |
| 容器安全 | 5 | 容器逃逸 |
| 插件安全 | 5 | 插件供应链攻击 |
| 文件系统安全 | 5 | 文件权限问题 |

| 分数 | 等级 |
|------|------|
| 90-100 | Excellent |
| 75-89 | Good |
| 60-74 | Fair |
| 40-59 | Poor |
| 0-39 | Critical |

## Skills 扩展

Skill 是社区贡献的安全检查，使用 Markdown 格式编写。每个 Skill 包含一个输出结构化 JSON 的 bash 命令，任何人都可以在不写 Rust 的情况下扩展 claw-guard。

### 使用 Skill

将 `.md` 文件放入 `~/.claw-guard/skills/` 即可，每次运行时自动加载。

```
~/.claw-guard/skills/
├── check-npm-audit.md
├── check-git-secrets.md
└── my-custom-check/
    └── SKILL.md
```

### 编写 Skill

创建一个 `.md` 文件，包含 YAML frontmatter 和 `## Evaluate` 部分：

```markdown
---
name: npm-audit
description: 检查 npm 依赖的已知漏洞
version: 1.0.0
category: plugin
severity: high
id: SK-NPM001
remediation: 运行 'npm audit fix'
timeout: 60
---

# npm Audit Check

## Evaluate

\```bash
if ! command -v npm >/dev/null 2>&1; then
  echo '{"status":"skip","detail":"npm not installed"}'
  exit 0
fi
# ... 检查逻辑 ...
echo '{"status":"pass","detail":"No vulnerabilities found"}'
\```
```

**输出协议** — 每行输出一个 JSON 对象：

```json
{"status": "pass|fail|warn|skip", "detail": "描述", "evidence": "可选证据"}
```

**Frontmatter 字段：**

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | Skill 名称 |
| `description` | 否 | 检查说明 |
| `category` | 否 | 映射到 claw-guard 分类 (credential/network/plugin 等) |
| `severity` | 否 | critical/high/medium/low/info（默认: medium） |
| `id` | 否 | 规则 ID（默认: 自动生成） |
| `remediation` | 否 | 失败时的修复建议 |
| `timeout` | 否 | 最大执行时间，秒（默认: 30） |

**安全性：** Skill 命令执行时会剥离敏感环境变量（AWS 密钥、API Token 等），并强制超时。请只安装你信任的 Skill。


## 检测规则

35 条内置规则，每条有唯一 ID（`CG-XNNN`）、分类、严重级别、修复建议。

### 凭证暴露 (CG-C)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-C001 | 凭证目录权限（~/.ssh, ~/.aws, ~/.kube, ~/.docker 等） | CRITICAL |
| CG-C002 | OpenClaw 配置文件安全（openclaw.json, .env, OAuth 凭证） | HIGH |
| CG-C003 | 敏感环境变量暴露（50+ 已知 API Key 模式） | HIGH |

### 文件系统安全 (CG-F)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-F001 | 系统敏感文件可达性（/etc/shadow, SAM 等） | CRITICAL |
| CG-F002 | SSH 宿主密钥文件权限 | CRITICAL |
| CG-F003 | 历史版本数据残留（~/.clawdbot 等旧目录） | MEDIUM |

### 网络暴露 (CG-N)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-N001 | Gateway 绑定 0.0.0.0（通配监听） | HIGH |
| CG-N002 | 异常外连检测 | HIGH |
| CG-N003 | OpenClaw 端口全面扫描（18789-18899, 9222, 5900, 6080） | MEDIUM |
| CG-N004 | 反弹 Shell / C2 工具检测 | CRITICAL |
| CG-N005 | DNS 隧道数据外泄检测 | MEDIUM |

### 进程安全 (CG-P)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-P001 | 以 root/SYSTEM 权限运行 | HIGH |
| CG-P002 | 子 Agent 危险标志（--yolo, bypassPermissions） | HIGH |
| CG-P003 | 定时任务 / 计划任务审计 | HIGH |
| CG-P004 | 异常子进程检测（矿机、扫描器、代理） | HIGH |
| CG-P005 | 宿主入侵指标检测（SSH 密钥、隐藏文件、CPU 挖矿、登录爆破、二进制完整性） | CRITICAL |

### 网关配置 (CG-G)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-G001 | Gateway 认证模式 = none（未认证 RCE） | CRITICAL |
| CG-G002 | 危险配置标志（allowInsecureAuth, dangerouslyDisable* 等） | CRITICAL |
| CG-G003 | Secret Provider exec 路径安全 | HIGH |
| CG-G004 | Gateway Token 强度 | HIGH |

### 沙箱隔离 (CG-S)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-S001 | Sandbox 模式关闭（所有 exec 直接在宿主运行） | CRITICAL |
| CG-S002 | Sandbox Docker 安全绕过标志 | HIGH |

### 插件安全 (CG-K)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-K001 | 已安装插件清单审计（插件享有完整宿主权限） | HIGH |
| CG-K002 | 插件目录写保护 | HIGH |

### 数据泄露检测 (CG-D)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-D001 | Shell history / 日志中的 API Key 泄露 | HIGH |
| CG-D002 | 日志中的密码、私钥、内网 IP 等敏感信息 | MEDIUM |
| CG-D003 | 配置变更审计日志分析 | MEDIUM |

### 容器安全 (CG-T)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-T001 | Docker Socket 挂载（等效宿主 root） | CRITICAL |

### 费用安全 (CG-M)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-M001 | API 费用限额未配置 | CRITICAL |
| CG-M002 | 多个高价值 API Key 同时暴露 | HIGH |
| CG-M003 | 未配置用量告警 / Webhook | MEDIUM |

### 破坏性操作防护 (CG-X)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-X001 | 无危险命令黑名单 / 白名单 | CRITICAL |
| CG-X002 | 无文件系统写入范围限制 | HIGH |
| CG-X003 | 无备份或回滚机制 | HIGH |
| CG-X004 | 危险操作无人工确认环节 | MEDIUM |

## 架构

```
src/
├── main.rs              # CLI 入口，流程编排
├── platform.rs          # 三平台（macOS/Linux/Windows）路径适配
├── engine/
│   ├── mod.rs           # Rule/StaticRule trait, Finding, Severity, Category 定义
│   ├── registry.rs      # 内置规则注册表（35 条规则）
│   └── skill/
│       ├── mod.rs       # Skill 加载器（目录扫描）
│       ├── parser.rs    # SKILL.md frontmatter + ## Evaluate 解析
│       └── runner.rs    # 沙箱化命令执行 + JSON 输出解析
├── llm/
│   ├── mod.rs           # Analyzer trait, AnalysisReport 类型定义
│   ├── providers.rs     # 提供商注册表（24 个提供商）
│   ├── adapter.rs       # 协议适配器（OpenAI 兼容 + Anthropic 原生）
│   ├── prompt.rs        # Findings → LLM Prompt 构建器
│   └── local.rs         # 本地模式（多提供商 API 调用 + 动画进度条）
├── rules/
│   ├── credential/      # CG-C001 ~ CG-C003
│   ├── filesystem/      # CG-F001 ~ CG-F003
│   ├── network/         # CG-N001 ~ CG-N005
│   ├── process/         # CG-P001 ~ CG-P005
│   ├── gateway/         # CG-G001 ~ CG-G004
│   ├── sandbox/         # CG-S001 ~ CG-S002
│   ├── plugin/          # CG-K001 ~ CG-K002
│   ├── dataleak/        # CG-D001 ~ CG-D003
│   ├── docker/          # CG-T001
│   ├── cost/            # CG-M001 ~ CG-M003
│   └── destructive/     # CG-X001 ~ CG-X004
└── report/
    └── mod.rs           # 报告生成、加权评分、终端输出
```

### 添加内置规则

1. 在对应分类目录下新建 `cg_xxxx.rs`，实现 `StaticRule` trait
2. 在分类 `mod.rs` 中声明
3. 在 `engine/registry.rs` 中注册

### 添加 Skill（无需写 Rust）

1. 创建 `.md` 文件，包含 frontmatter + `## Evaluate` bash 代码块
2. 放入 `~/.claw-guard/skills/`

## 数据安全

claw-guard 仅采集结构化元数据，**绝不上传**文件内容、密钥或凭证：

```json
{
  "rule_id": "CG-C001",
  "status": "fail",
  "severity": "Critical",
  "detail": "~/.aws is world-readable (mode 755)",
  "evidence": "path=~/.aws mode=755 name=aws_credentials"
}
```

- **本地模式**：发现仅发送给你选择的 LLM 提供商，不经过 install9。
- **远程模式**：结构化发现（绝非原始文件）发送到 install9.ai 分析。
- **Skill 沙箱**：敏感环境变量（AWS 密钥、API Token 等）在 Skill 命令执行前被剥离。

## CLI

```
Options:
    --no-upload              完全离线模式（跳过注册、上传、服务端分析）
    --list-rules             列出所有检测规则
    --list-providers         列出所有支持的 LLM 提供商
    --upgrade                检查更新并升级到最新版本
    --purge-data             删除所有 claw-guard 本地数据（~/.claw-guard/）

  AI 分析:
    --api-key <KEY>          LLM 提供商 API Key，用于本地分析（或设置 CLAW_GUARD_API_KEY 环境变量）
    --provider <NAME>        LLM 提供商名称 [默认: anthropic]
    --model <MODEL>          LLM 模型名称（覆盖提供商默认值）
    --base-url <URL>         自定义 OpenAI 兼容端点地址

    -h, --help
    -V, --version
```

## 构建

需要 Rust 1.85+。支持 macOS / Linux / Windows。

```sh
cargo build --release
```

交叉编译：

```sh
# macOS（原生）
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

# Linux（通过 Docker）
docker run --rm --platform linux/arm64 -v "$(pwd)":/app -w /app rust:latest \
  cargo build --release --target aarch64-unknown-linux-gnu
docker run --rm -v "$(pwd)":/app -w /app rust:latest \
  cargo build --release --target x86_64-unknown-linux-gnu

# Windows（通过 Docker）
docker run --rm -v "$(pwd)":/app -w /app rust:latest bash -c \
  "apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null 2>&1 && \
   rustup target add x86_64-pc-windows-gnu && \
   cargo build --release --target x86_64-pc-windows-gnu"
```

## 下载

| 文件 | 平台 |
|------|------|
| claw-guard-v0.4.0-darwin-arm64.tar.gz | macOS Apple Silicon (M1/M2/M3/M4) |
| claw-guard-v0.4.0-darwin-amd64.tar.gz | macOS Intel |
| claw-guard-v0.4.0-linux-amd64.tar.gz | Linux x86_64 |
| claw-guard-v0.4.0-linux-arm64.tar.gz | Linux ARM64 |
| claw-guard-v0.4.0-windows-amd64.zip | Windows x86_64 |

从 [GitHub Releases](https://github.com/akz142857/claw-guard/releases) 下载。

## License

MIT
