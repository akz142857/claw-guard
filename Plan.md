# claw-guard — 产品规划

## 概述

**产品名：** claw-guard
**归属：** install9 旗下产品，网站路径 install9.ai/claw-guard
**仓库：** 独立仓库 `claw-guard`（Rust 项目，与 install9 Shell 脚本分离）
**定位：** AI Agent 宿主系统安全审计工具

```
项目结构：
├── install9          # Shell 安装脚本（现有仓库）
├── claw-guard       # Rust 安全检查 Agent（独立仓库）
└── install9.ai       # 官网（两个产品共用）
```

## 背景

OpenClaw 是增长最快的开源项目之一（250K+ GitHub stars，150 万周下载），但安全事件频发：
- CVE-2025-53773（CVSS 9.6）影响 10 万+ 安装
- CVE-2026-25253 可窃取认证 token
- 80% 的组织报告过 AI agent 越权行为（未授权系统访问、数据暴露）

现有安全工具（官方 `openclaw security audit`、ClawSecure、SecureClaw）都聚焦 **OpenClaw 自身配置** 是否正确。
**没有人关注一个核心问题：OpenClaw 作为一个有系统权限的 AI agent，对宿主机的安全影响是什么？**

install9 解决了安装体验，claw-guard 解决安装之后的系统安全——形成完整的用户生命周期。

## 产品定位

不查 OpenClaw 配置对不对，而是查：**OpenClaw 装在你的系统上之后，你的系统还安全吗？**

| | 现有工具 | claw-guard |
|--|---------|-------------|
| 视角 | OpenClaw 配置是否正确 | OpenClaw 给系统带来了什么风险 |
| 类比 | 检查门锁装没装好 | 检查房子里有没有值钱东西被暴露 |
| 检查对象 | openclaw.json、gateway 设置 | SSH key、云凭证、系统端口、进程权限、文件系统暴露面 |
| 未来扩展 | 仅限 OpenClaw | 任何 AI agent（通用化） |

## 核心设计原则

1. **安装门槛最低化** — 两种安装路径，最简单的只需粘贴一个 URL
2. **持续运行** — 安装后常驻后台定时检查，不依赖用户手动触发
3. **远程可视** — 报告在 Web 平台查看，不需要 SSH 到服务器看终端
4. **开源透明** — 代码开源，让用户审查建立信任
5. **最小权限** — 只读取必要信息，不上传原始文件内容和密钥

## 整体架构

```
安装方式（二选一）
├── 方式 A：粘贴 Skill URL 给 OpenClaw → Skill 自动下载安装 claw-guard
└── 方式 B：手动下载运行（curl 一行命令 / 直接下载二进制）

                          ↓

                claw-guard（常驻后台服务）
              launchd / systemd / Windows Service
                          ↓
                  定时执行系统安全检查
                          ↓
              脱敏结构化数据上传到服务平台
                          ↓
                  AI 分析 → 生成报告
                          ↓
              ┌───────────┴───────────┐
              ↓                       ↓
    Web 平台（平台 ID 登录）    OpenClaw 渠道推送
     install9.ai/claw-guard    Feishu/Telegram/
       查看报告/历史趋势        Slack/Discord
```

## 安装路径

### 方式 A：OpenClaw Skill 自动安装（零门槛）

用户把 Skill URL 粘贴给 OpenClaw：
1. OpenClaw 加载 Skill
2. Skill 下载 claw-guard 二进制
3. Skill 注册为系统服务
4. Skill 使命结束，claw-guard 常驻运行
5. 返回 Web 报告链接

**适合：** 已安装 OpenClaw 的用户，不想碰终端

### 方式 B：手动下载安装（自主可控）

```sh
# 一行命令安装
curl -fsSL https://install9.ai/claw-guard | sh

# 或直接下载二进制
wget https://install9.ai/claw-guard/claw-guard-linux-amd64
chmod +x claw-guard-linux-amd64
./claw-guard-linux-amd64 --install --platform-id <YOUR_ID>
```

**适合：** 独立服务器、想自己掌控的用户、CI/CD 环境

两种方式安装的是同一个 claw-guard，后续行为完全一致。

## claw-guard 核心

**形态：** Rust 编译的单二进制，常驻后台运行

**运行模式：**
- 系统服务（launchd/systemd/Windows Service），开机自启
- 前台模式（`--foreground`），适合 Docker 容器

**核心行为：**
- 启动后立即执行一次全量检查
- 按配置间隔定时检查（默认每日）
- 每次结果上传到服务平台
- CRITICAL 级别问题立即上报

**身份绑定：**
- OpenClaw 平台 ID 标识实例
- Skill 安装自动传入，手动安装通过 `--platform-id` 指定

## 检查项

### 核心检查：AI Agent 对宿主系统的安全影响

| 类别 | 检查内容 | 严重级别 | 技术难度 |
|------|----------|----------|----------|
| **凭证暴露面** | OpenClaw 进程能否访问 ~/.ssh、~/.aws、~/.config/gcloud、数据库凭证等 | CRITICAL | 低 |
| **敏感文件可达性** | /etc/shadow、/etc/passwd、私钥文件等是否在 OpenClaw 可读范围内 | CRITICAL | 低 |
| **网络暴露** | OpenClaw 相关端口是否监听 0.0.0.0、是否有非预期外连 | HIGH | 低 |
| **进程权限** | OpenClaw 是否以 root 运行、子进程链是否异常 | HIGH | 中 |
| **文件系统变更** | 安装后 crontab、systemd service、sudoers、PATH 是否被异常修改 | HIGH | 中 |
| **API Key 泄露** | 系统中的 API key 是否出现在 OpenClaw 日志、shell history、git history 中 | HIGH | 低 |
| **容器安全** | Docker 运行时 volume mount 是否过度暴露宿主机、capability 是否过宽 | HIGH | 中 |
| **环境隔离** | OpenClaw 是否与其他服务共享用户、是否有进程间越权风险 | MEDIUM | 中 |
| **日志泄露** | OpenClaw 日志中是否包含系统敏感信息（其他服务的密码、内网 IP 等） | MEDIUM | 低 |
| **自动更新风险** | OpenClaw 自动更新机制是否可能引入未经审查的代码 | MEDIUM | 低 |

### 辅助检查：OpenClaw 基础配置（与官方互补，不重复）

| 类别 | 检查内容 | 严重级别 |
|------|----------|----------|
| 配置文件权限 | `openclaw.json`、`.env` 权限 | HIGH |
| Gateway 认证 | auth token 强度 | MEDIUM |
| TLS 状态 | Gateway 是否启用 HTTPS | MEDIUM |

### 数据上传原则

- 仅上传结构化元数据（权限值 `644`、端口号 `8080`、检查状态 `pass/fail`）
- **绝不上传**：文件内容、密钥、凭证、用户数据
- 示例：`{"check": "ssh_key_exposure", "status": "fail", "details": "~/.ssh/id_rsa readable by openclaw process (uid 501)"}`

## 服务平台

**URL：** install9.ai/claw-guard

**身份体系：**
- OpenClaw 平台 ID = 报告凭证，无需额外注册

**Web 端功能：**
- 平台 ID 登录
- 检查报告（风险等级、逐项结果、修复建议）
- 历史报告列表
- AI 综合风险评分

**告警推送：**
- CRITICAL 问题通过 OpenClaw 渠道推送（Feishu/Telegram/Slack/Discord）

## 实施路径

### Phase 1：MVP

**目标：** 跑通「安装 → 检查 → Web 查看报告」全链路

**交付物：**
- Rust 编译的 claw-guard（darwin/linux/windows × amd64/arm64）
- 6 个核心检查项（凭证暴露面、敏感文件、网络暴露、进程权限、API Key 泄露、日志泄露）
- 手动安装脚本（方式 B）
- 后端 API（接收数据、存储报告）
- Web 报告页面（基础版）
- GitHub 开源仓库

**不做：**
- Skill 集成（依赖 SDK 调研）
- AI 深度分析
- 定时检查（先做单次手动触发）

### Phase 2：持续监控 + Skill 集成

**目标：** 从单次检查升级为持续安全监控，补齐零门槛安装路径

**交付物：**
- claw-guard 常驻后台 + 定时检查
- OpenClaw Skill（方式 A 安装路径）
- 补齐剩余检查项（文件系统变更、容器安全、环境隔离、自动更新风险）
- 渠道告警推送
- 历史趋势对比

### Phase 3：AI 深度分析 + 商业化

**目标：** AI 驱动的深度分析，开启付费模式

**交付物：**
- AI 综合风险评分（分析配置组合风险，不只是逐项 pass/fail）
- 针对用户环境生成具体修复命令
- Pro 订阅（Web 平台高级功能）

### Phase 4：扩展

**可能方向：**
- 支持更多 AI agent（不只是 OpenClaw，扩展到 AutoGPT、CrewAI 等）
- 企业多实例管理面板
- 合规报告导出（PDF、SOC2、ISO27001）
- 自定义检查规则 + 社区插件
- 运行时行为监控（eBPF，长期方向）

## 技术选型

| 组件 | 选型 | 说明 |
|------|------|------|
| claw-guard | Rust | 内存安全（安全工具的品牌信任）、极低资源占用（常驻 ~2-5MB）、小二进制、为 Phase 4 eBPF 铺路 |
| 架构 | trait Checker | 每个检查项为独立 checker，实现统一 trait |
| 构建发布 | cargo-dist + cross-rs | 覆盖 darwin/linux/windows × amd64/arm64 |
| 后端 API | 待定 | |
| 数据库 | PostgreSQL | 报告存储 |
| Web 前端 | 待定 | 报告展示 |
| AI 分析 | LLM API | Phase 3 |
| OpenClaw Skill | 待调研 SDK | Phase 2 |

## 可行性评估

### 市场机会

- OpenClaw 250K+ stars、150 万周下载，用户基数大
- CVE 频发，系统安全意识在提升
- 「AI agent 对宿主系统的安全影响」这个角度无人覆盖
- AI 安全市场 2026 年约 30 亿美元，年增长 22%

### 竞争格局

| 竞品 | 定位 | 与 claw-guard 的关系 |
|------|------|----------------------|
| `openclaw security audit` | OpenClaw 自身配置检查 | 互补，不竞争 |
| ClawSecure | Skill 审计 + 威胁模式 | 不同方向 |
| SecureClaw | OpenClaw 插件，配置加固 | 不同方向 |
| Lynis | 通用系统审计 | 最接近，但不理解 AI agent 特殊风险 |

### 风险矩阵

| 风险 | 级别 | 应对策略 |
|------|------|----------|
| OpenClaw 官方自己做系统层检查 | 🔴 高 | 保持先发速度，系统层检查不是 OpenClaw 核心方向 |
| 用户信任：安全工具要获取系统权限 | 🔴 高 | 开源代码、最小权限、透明数据上传策略 |
| 杀毒软件误报 | 🟡 中 | 代码签名 + 主流杀软白名单申请 |
| 跨平台维护成本 | 🟡 中 | Rust 条件编译覆盖三平台 |
| 合规/隐私法规 | 🟡 中 | 明确用户协议，不上传原始数据 |
| OpenClaw 架构变更 | 🟢 低 | 系统层检查不依赖 OpenClaw 内部 API |

### 商业模式（Lynis/CISOfy 验证过的 freemium）

| 层级 | 内容 | 定价 |
|------|------|------|
| **Free** | 开源 claw-guard + 本地检查 + Web 基础报告 | 免费 |
| **Pro** | 历史趋势 + AI 分析 + 渠道告警 + 优先支持 | $10/月/实例 |
| **Enterprise** | 多实例管理 + 合规导出 + 自托管 + SLA | 联系销售 |

保守估算：150 万周下载 × 1% 付费 = 1.5 万订阅 × $10/月 = **$150K MRR**

## 待决策

- [ ] 后端技术栈确认
- [ ] 服务平台部署方案（自建 / 云服务）
- [ ] OpenClaw SDK/Skill 能力调研（Phase 2 前置）
- [ ] 是否 Phase 1 就开源，还是 Phase 2 再开源
- [ ] claw-guard 自动更新机制
