# claw-guard

OpenClaw 宿主系统安全审计工具。23 条检测规则，9 个安全分类，覆盖从凭证暴露到容器逃逸的完整攻击面。

不检查 OpenClaw 配置对不对，而是检查：**OpenClaw 装在你的系统上之后，你的系统还安全吗？**

## 快速开始

```sh
cargo build --release

# 完整审计
./target/release/claw-guard --no-upload

# 只检查某个分类
./target/release/claw-guard --no-upload --category gateway

# 列出所有检测规则
./target/release/claw-guard --list-rules

# JSON 输出 / 保存报告
./target/release/claw-guard --no-upload --json
./target/release/claw-guard --no-upload --output report.json
```

## 示例输出

```
╔══════════════════════════════════════════════════╗
║        claw-guard Security Audit Report         ║
╚══════════════════════════════════════════════════╝

  Host:     my-server  (linux)
  Time:     2026-03-09T17:48:00+00:00
  Version:  0.1.0
  Score:    62/100  [████████████░░░░░░░░] Fair

  Rules: 23  |  Pass: 17  Fail: 3  Warn: 1  Skip: 8

  !! 2 CRITICAL finding(s) !!
  !  1 HIGH finding(s)

  ── Category Breakdown ──
  ✗ Credential Exposure             6 checks   2 fail   0 warn
  ✗ Data Leak Detection             4 checks   1 fail   0 warn
  ⚠ Sandbox & Isolation             2 checks   0 fail   1 warn
  ✓ Gateway Configuration           4 checks   0 fail   0 warn
  ✓ Network Exposure                3 checks   0 fail   0 warn
  ...

  ── Findings ──
  ✗ [CRITICAL] CG-C001 (Credential directory permissions)
    ~/.aws is world-readable (mode 755)
    evidence: path=~/.aws mode=755 name=aws_credentials
    fix: chmod 700 on credential directories.

  ✗ [HIGH] CG-D001 (API key leak in history/logs)
    API key patterns in ~/.zsh_history
    evidence: file=~/.zsh_history types=[openai, anthropic]
    fix: Rotate exposed keys. Use secret managers.
```

退出码：`0` 正常，`1` 存在 HIGH，`2` 存在 CRITICAL。适合 CI/CD 集成。

## 检测规则

每条规则有唯一 ID（`CG-XNNN`）、分类、严重级别、修复建议。

### Credential Exposure (CG-C)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-C001 | 凭证目录权限（~/.ssh, ~/.aws, ~/.kube, ~/.docker 等） | CRITICAL |
| CG-C002 | OpenClaw 配置文件安全（openclaw.json, .env, OAuth 凭证） | HIGH |
| CG-C003 | 敏感环境变量暴露（50+ 已知 API Key 模式） | HIGH |

### File System Security (CG-F)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-F001 | 系统敏感文件可达性（/etc/shadow, SAM 等） | CRITICAL |
| CG-F002 | SSH 宿主密钥文件权限 | CRITICAL |
| CG-F003 | 历史版本数据残留（~/.clawdbot 等旧目录） | MEDIUM |

### Network Exposure (CG-N)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-N001 | Gateway 绑定 0.0.0.0（通配监听） | HIGH |
| CG-N002 | 异常外连检测 | HIGH |
| CG-N003 | OpenClaw 端口全面扫描（18789-18899, 9222, 5900, 6080） | MEDIUM |

### Process Security (CG-P)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-P001 | OpenClaw 以 root/SYSTEM 运行 | HIGH |
| CG-P002 | 子 Agent 危险标志（--yolo, bypassPermissions） | HIGH |

### Gateway Configuration (CG-G)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-G001 | Gateway auth mode = none（未认证 RCE） | CRITICAL |
| CG-G002 | 危险配置标志（allowInsecureAuth, dangerouslyDisable* 等） | CRITICAL |
| CG-G003 | Secret Provider exec 路径安全 | HIGH |
| CG-G004 | Gateway Token 强度 | HIGH |

### Sandbox & Isolation (CG-S)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-S001 | Sandbox 模式关闭（所有 exec 直接在宿主运行） | CRITICAL |
| CG-S002 | Sandbox Docker 安全绕过标志 | HIGH |

### Plugin & Extension Security (CG-K)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-K001 | 已安装插件清单审计（插件享有完整宿主权限） | HIGH |
| CG-K002 | 插件目录写保护 | HIGH |

### Data Leak Detection (CG-D)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-D001 | Shell history / 日志中的 API Key 泄露 | HIGH |
| CG-D002 | 日志中的密码、私钥、内网 IP 等敏感信息 | MEDIUM |
| CG-D003 | 配置变更审计日志分析 | MEDIUM |

### Container Security (CG-T)

| ID | 规则 | 严重级别 |
|----|------|----------|
| CG-T001 | Docker Socket 挂载（等效宿主 root） | CRITICAL |

## 架构

```
src/
├── main.rs              # CLI 入口
├── platform.rs          # 三平台（macOS/Linux/Windows）路径适配
├── engine/
│   ├── mod.rs           # Rule trait, Finding, Severity, Category 定义
│   └── registry.rs      # 规则注册表
├── rules/
│   ├── credential/      # CG-C001 ~ CG-C003
│   ├── filesystem/      # CG-F001 ~ CG-F003
│   ├── network/         # CG-N001 ~ CG-N003
│   ├── process/         # CG-P001 ~ CG-P002
│   ├── gateway/         # CG-G001 ~ CG-G004
│   ├── sandbox/         # CG-S001 ~ CG-S002
│   ├── plugin/          # CG-K001 ~ CG-K002
│   ├── dataleak/        # CG-D001 ~ CG-D003
│   └── docker/          # CG-T001
└── report/
    └── mod.rs           # 报告生成、评分、终端/JSON 输出
```

每条规则一个文件，自包含元数据 + 检测逻辑。添加新规则只需三步：

1. 在对应分类目录下新建 `cg_xxxx.rs`，实现 `Rule` trait
2. 在分类 `mod.rs` 中声明
3. 在 `engine/registry.rs` 中注册

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

## CLI

```
Options:
    --platform-id <ID>     平台 ID，用于报告上传
    --json                 JSON 格式输出
    --output <PATH>        保存报告到文件
    --category <NAME>      只运行指定分类的规则
    --list-rules           列出所有检测规则
    --no-upload            跳过上传
    --api-url <URL>        报告上传地址
    -h, --help
    -V, --version
```

## 构建

需要 Rust 1.85+。支持 macOS / Linux / Windows。

```sh
cargo build --release
```

## License

MIT
