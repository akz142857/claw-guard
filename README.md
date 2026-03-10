<p align="center">
  <img src="assets/icon.svg" width="128" height="128" alt="claw-guard icon">
</p>

<h1 align="center">claw-guard</h1>

<p align="center">
  AI-powered host system security audit tool for OpenClaw.<br>
  23 built-in detection rules across 9 categories, extensible via Skills, with LLM-driven attack chain analysis.
</p>

<p align="center">
  Doesn't check if OpenClaw is configured correctly — checks <b>what risks OpenClaw introduces to your host system</b>.
</p>

<p align="center">
  <a href="README.zh-CN.md">中文文档</a>
</p>

## Quick Start

```sh
cargo build --release

# Full audit (classic mode, no LLM)
./target/release/claw-guard --no-upload --no-analyze

# AI-powered audit (Anthropic)
export CLAW_GUARD_API_KEY=sk-ant-xxx
./target/release/claw-guard --no-upload

# AI-powered audit (OpenAI / Ollama)
./target/release/claw-guard --no-upload --provider openai --api-key sk-xxx
./target/release/claw-guard --no-upload --provider ollama --model llama3

# Filter by category
./target/release/claw-guard --no-upload --no-analyze --category gateway

# Load community skills
./target/release/claw-guard --no-upload --no-analyze --skill-dir ./examples/skills

# List all rules + skills
./target/release/claw-guard --list-rules --skill-dir ./examples/skills

# JSON output / save report
./target/release/claw-guard --no-upload --no-analyze --json
./target/release/claw-guard --no-upload --no-analyze --output report.json
```

## Example Output

```
╔══════════════════════════════════════════════════╗
║        claw-guard Security Audit Report         ║
╚══════════════════════════════════════════════════╝

  Host:     my-server  (linux)
  Time:     2026-03-09T17:48:00+00:00
  Version:  0.1.0
  Score:    54/100  [██████████░░░░░░░░░░] Fair

  Rules: 23 + 3 skills  |  Pass: 17  Fail: 6  Warn: 4  Skip: 8

  !! 4 CRITICAL finding(s) !!
  !  2 HIGH finding(s)

  ── Category Breakdown ──
  ✗ Credential Exposure             9 checks   5 fail   2 warn
  ✗ Data Leak Detection             4 checks   1 fail   0 warn
  ⚠ Network Exposure                4 checks   0 fail   1 warn
  ✓ Gateway Configuration           4 checks   0 fail   0 warn
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

  ── AI Analysis ──────────────────────────────────

  Summary:
  Your system has a credential theft attack chain: ~/.aws is
  world-readable AND API keys appear in shell history. An attacker
  with local access could extract AWS credentials in seconds.

  Attack Chains:
  1. [High] Credential Theft via History
     CG-C001 + CG-D001 → AWS account takeover

  Priority Fixes:
  1. chmod 700 ~/.aws ~/.ssh ~/.docker
     ← blocks credential theft chain (CG-C001)
  2. Rotate leaked keys in shell history
     ← damage control (CG-D001)

  ─────────────────────────────────────────────────
```

Exit codes: `0` all clear, `1` HIGH findings, `2` CRITICAL findings. CI/CD friendly.

## AI Analysis

claw-guard uses LLM to go beyond pass/fail — it identifies **attack chains** (combinations of findings that create exploitable paths), prioritizes fixes by impact, and provides environment-specific advice.

### Two Modes

| Mode | How | Best For |
|------|-----|----------|
| **Local** (default) | Your own API key, analysis runs on your machine | Privacy-first, air-gapped environments |
| **Remote** | Sends findings to install9 platform for analysis | Continuous monitoring, historical trends |

### Supported Providers (Local Mode)

| Provider | Flag | Default Model |
|----------|------|---------------|
| Anthropic | `--provider anthropic` | claude-sonnet-4-20250514 |
| OpenAI | `--provider openai` | gpt-4o |
| Ollama | `--provider ollama` | llama3 |

```sh
# Local with Anthropic (default)
export CLAW_GUARD_API_KEY=sk-ant-xxx
claw-guard --no-upload

# Local with Ollama (fully offline)
claw-guard --no-upload --provider ollama --model llama3

# Remote mode (sends to install9 platform)
claw-guard --mode remote --platform-id my-server-id

# Skip AI analysis entirely
claw-guard --no-upload --no-analyze
```

## Skills

Skills are community-contributed security checks in Markdown format. Each skill contains a bash command that outputs structured JSON, letting anyone extend claw-guard without writing Rust.

### Using Skills

```sh
# Load from a directory
claw-guard --no-upload --no-analyze --skill-dir ./my-skills

# Default directory: ~/.claw-guard/skills/
# Skip all skills
claw-guard --no-upload --no-analyze --no-skills
```

### Writing a Skill

Create a `.md` file with YAML frontmatter and an `## Evaluate` section:

```markdown
---
name: npm-audit
description: Check npm packages for known vulnerabilities
version: 1.0.0
category: plugin
severity: high
id: SK-NPM001
remediation: Run 'npm audit fix'
timeout: 60
---

# npm Audit Check

## Evaluate

\```bash
if ! command -v npm >/dev/null 2>&1; then
  echo '{"status":"skip","detail":"npm not installed"}'
  exit 0
fi
# ... check logic ...
echo '{"status":"pass","detail":"No vulnerabilities found"}'
\```
```

**Output protocol** — each line must be a JSON object:

```json
{"status": "pass|fail|warn|skip", "detail": "description", "evidence": "optional data"}
```

**Frontmatter fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Skill name |
| `description` | No | What this skill checks |
| `category` | No | Maps to claw-guard category (credential/network/plugin/etc.) |
| `severity` | No | critical/high/medium/low/info (default: medium) |
| `id` | No | Rule ID (default: auto-generated from name) |
| `remediation` | No | Fix instructions shown on failure |
| `timeout` | No | Max execution time in seconds (default: 30) |

**Security:** Skill commands run with sensitive environment variables stripped (AWS keys, API tokens, etc.) and enforce a timeout. Only install skills you trust.

### Skill Directory Layout

```
~/.claw-guard/skills/
├── check-npm-audit.md          # Flat .md file
├── check-git-secrets.md
└── my-custom-check/
    └── SKILL.md                # Or subdirectory with SKILL.md
```

## Detection Rules

23 built-in rules, each with a unique ID (`CG-XNNN`), category, severity, and remediation advice.

### Credential Exposure (CG-C)

| ID | Rule | Severity |
|----|------|----------|
| CG-C001 | Credential directory permissions (~/.ssh, ~/.aws, ~/.kube, ~/.docker, etc.) | CRITICAL |
| CG-C002 | OpenClaw config file security (openclaw.json, .env, OAuth credentials) | HIGH |
| CG-C003 | Sensitive environment variables (50+ known API key patterns) | HIGH |

### File System Security (CG-F)

| ID | Rule | Severity |
|----|------|----------|
| CG-F001 | Sensitive system file access (/etc/shadow, SAM, etc.) | CRITICAL |
| CG-F002 | SSH host key file permissions | CRITICAL |
| CG-F003 | Legacy config data residue (~/.clawdbot, etc.) | MEDIUM |

### Network Exposure (CG-N)

| ID | Rule | Severity |
|----|------|----------|
| CG-N001 | Wildcard network listeners (gateway bound to 0.0.0.0) | HIGH |
| CG-N002 | Outbound connection audit | HIGH |
| CG-N003 | OpenClaw port surface scan (18789-18899, 9222, 5900, 6080) | MEDIUM |

### Process Security (CG-P)

| ID | Rule | Severity |
|----|------|----------|
| CG-P001 | Elevated privilege execution (root/SYSTEM) | HIGH |
| CG-P002 | Dangerous sub-agent flags (--yolo, bypassPermissions) | HIGH |

### Gateway Configuration (CG-G)

| ID | Rule | Severity |
|----|------|----------|
| CG-G001 | Gateway auth mode = none (unauthenticated RCE) | CRITICAL |
| CG-G002 | Dangerous config flags (allowInsecureAuth, dangerouslyDisable*, etc.) | CRITICAL |
| CG-G003 | Secret provider exec path security | HIGH |
| CG-G004 | Gateway token strength | HIGH |

### Sandbox & Isolation (CG-S)

| ID | Rule | Severity |
|----|------|----------|
| CG-S001 | Sandbox mode disabled (all exec runs directly on host) | CRITICAL |
| CG-S002 | Sandbox Docker security bypasses | HIGH |

### Plugin & Extension Security (CG-K)

| ID | Rule | Severity |
|----|------|----------|
| CG-K001 | Plugin inventory audit (plugins run with full host privileges) | HIGH |
| CG-K002 | Plugin directory write protection | HIGH |

### Data Leak Detection (CG-D)

| ID | Rule | Severity |
|----|------|----------|
| CG-D001 | API key leak in shell history / logs | HIGH |
| CG-D002 | Sensitive data in logs (passwords, private keys, internal IPs) | MEDIUM |
| CG-D003 | Config change audit trail analysis | MEDIUM |

### Container Security (CG-T)

| ID | Rule | Severity |
|----|------|----------|
| CG-T001 | Docker socket exposure (equivalent to host root) | CRITICAL |

## Architecture

```
src/
├── main.rs              # CLI entry point, orchestration
├── platform.rs          # Cross-platform path abstraction (macOS/Linux/Windows)
├── engine/
│   ├── mod.rs           # Rule/StaticRule traits, Finding, Severity, Category
│   ├── registry.rs      # Built-in rule registry
│   └── skill/
│       ├── mod.rs       # Skill loader (directory scanning)
│       ├── parser.rs    # SKILL.md frontmatter + ## Evaluate parser
│       └── runner.rs    # Sandboxed command execution + JSON output parsing
├── llm/
│   ├── mod.rs           # Analyzer trait, AnalysisReport types
│   ├── prompt.rs        # Findings → LLM prompt builder
│   ├── local.rs         # Local mode (Anthropic/OpenAI/Ollama API calls)
│   └── remote.rs        # Remote mode (install9 platform)
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
    └── mod.rs           # Report generation, scoring, terminal/JSON output
```

### Adding a Built-in Rule

1. Create `cg_xxxx.rs` in the appropriate category directory, implement `StaticRule`
2. Declare it in the category `mod.rs`
3. Register it in `engine/registry.rs`

### Adding a Skill (No Rust Required)

1. Create a `.md` file with frontmatter + `## Evaluate` bash block
2. Drop it in `~/.claw-guard/skills/` or pass `--skill-dir`

## Data Privacy

claw-guard collects only structured metadata. It **never uploads** file contents, keys, or credentials:

```json
{
  "rule_id": "CG-C001",
  "status": "fail",
  "severity": "Critical",
  "detail": "~/.aws is world-readable (mode 755)",
  "evidence": "path=~/.aws mode=755 name=aws_credentials"
}
```

- **Local mode**: Findings are sent to the LLM provider you choose. No data goes to install9.
- **Remote mode**: Structured findings (never raw files) are sent to install9.ai for analysis.
- **Skill sandboxing**: Sensitive env vars (AWS keys, API tokens, etc.) are stripped from skill command execution.

## CLI

```
Options:
    --platform-id <ID>       Platform ID for report upload
    --json                   JSON output
    --output <PATH>          Save report to file
    --category <NAME>        Only run rules in this category
    --list-rules             List all detection rules
    --no-upload              Skip upload to platform
    --api-url <URL>          API base URL [default: https://install9.ai/api/claw-guard]

  Skills:
    --skill-dir <PATH>       Skill directory [default: ~/.claw-guard/skills/]
    --no-skills              Skip loading skills

  AI Analysis:
    --mode <local|remote>    Analysis mode [default: local]
    --no-analyze             Skip LLM analysis (classic mode)
    --api-key <KEY>          LLM API key (or set CLAW_GUARD_API_KEY)
    --provider <PROVIDER>    anthropic | openai | ollama [default: anthropic]
    --model <MODEL>          LLM model name
    --ollama-url <URL>       Ollama server URL [default: http://localhost:11434]

    -h, --help
    -V, --version
```

## Building

Requires Rust 1.85+. Supports macOS, Linux, and Windows.

```sh
cargo build --release
```

Cross-compilation (requires [cross](https://github.com/cross-rs/cross)):

```sh
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
cross build --release --target x86_64-apple-darwin
cross build --release --target aarch64-apple-darwin
```

## License

MIT
