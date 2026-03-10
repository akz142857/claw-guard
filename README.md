# claw-guard

Host system security audit tool for OpenClaw. 23 detection rules across 9 categories, covering the full attack surface from credential exposure to container escape.

Doesn't check if OpenClaw is configured correctly — checks **what risks OpenClaw introduces to your host system**.

[中文文档](README.zh-CN.md)

## Quick Start

```sh
cargo build --release

# Full audit
./target/release/claw-guard --no-upload

# Filter by category
./target/release/claw-guard --no-upload --category gateway

# List all rules
./target/release/claw-guard --list-rules

# JSON output / save report
./target/release/claw-guard --no-upload --json
./target/release/claw-guard --no-upload --output report.json
```

## Example Output

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

Exit codes: `0` all clear, `1` HIGH findings, `2` CRITICAL findings. CI/CD friendly.

## Detection Rules

Each rule has a unique ID (`CG-XNNN`), category, severity, and remediation advice.

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
├── main.rs              # CLI entry point
├── platform.rs          # Cross-platform path abstraction (macOS/Linux/Windows)
├── engine/
│   ├── mod.rs           # Rule trait, Finding, Severity, Category definitions
│   └── registry.rs      # Rule registry
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

One file per rule, self-contained metadata + detection logic. Adding a new rule takes three steps:

1. Create `cg_xxxx.rs` in the appropriate category directory, implement the `Rule` trait
2. Declare it in the category `mod.rs`
3. Register it in `engine/registry.rs`

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

## CLI

```
Options:
    --platform-id <ID>     Platform ID for report upload
    --json                 JSON output
    --output <PATH>        Save report to file
    --category <NAME>      Only run rules in this category
    --list-rules           List all detection rules
    --no-upload            Skip upload
    --api-url <URL>        Report upload endpoint
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
