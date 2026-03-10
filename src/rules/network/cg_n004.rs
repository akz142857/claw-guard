use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-N004: Reverse shell detection
pub struct CgN004;

static META: RuleMeta = RuleMeta {
    id: "CG-N004",
    name: "Reverse shell detection",
    description: "Detects processes with reverse shell patterns: bash/sh redirected to \
                  network sockets, netcat listeners, or known reverse shell tools. \
                  Indicates the host may be compromised as a botnet node.",
    category: Category::Network,
    severity: Severity::Critical,
    remediation: "Immediately investigate and terminate the suspicious process. \
                  Check crontab, systemd services, and ~/.bashrc for persistence. \
                  Rotate all credentials on this host. Audit network logs for lateral movement.",
};

/// Command-line patterns indicating reverse shells
const REVSHELL_PATTERNS: &[&str] = &[
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i >",       // bash -i >& /dev/tcp/... (more specific than "bash -i")
    "bash -i>&",
    "sh -i >",         // sh -i >& /dev/tcp/...
    "sh -i>&",
    "nc -e /bin",
    "nc -c /bin",
    "ncat -e /bin",
    "ncat -c /bin",
    "socat exec:",
    "socat tcp:",
    "python -c 'import socket",
    "python3 -c 'import socket",
    "python -c \"import socket",
    "python3 -c \"import socket",
    "perl -e 'use Socket",
    "ruby -rsocket",
    "php -r '$sock",
    "mkfifo /tmp/",
    "mknod /tmp/",
    "openssl s_client -connect",
    "0<&196;exec 196<>/dev/tcp",
];

/// Process names commonly associated with reverse shells or C2.
/// Must NOT match common system processes (findmybeaconingd, etc.)
const SUSPICIOUS_PROCS: &[&str] = &[
    "meterpreter",
    "chisel",
    "frpc",
    "frps",
    "ngrok",
    "rathole",
    "pwncat",
    "sliver-client",
    "sliver-server",
    "cobaltstrike",
];

/// Known-safe system processes that match suspicious keywords.
/// These are excluded from detection to avoid false positives.
const SAFE_PROCESS_ALLOWLIST: &[&str] = &[
    "findmybeaconingd",     // macOS Find My service
    "cloudflared",          // Cloudflare tunnel (legitimate use common)
    "bore",                 // too generic, conflicts with system utils
];

impl StaticRule for CgN004 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check 1: Scan process command lines for reverse shell patterns
        let procs = list_process_cmdlines();
        for (pid, cmdline) in &procs {
            let lower = cmdline.to_lowercase();

            for pattern in REVSHELL_PATTERNS {
                if lower.contains(&pattern.to_lowercase()) {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!(
                            "Reverse shell pattern detected in process (pid {})",
                            pid
                        ),
                        format!(
                            "pid={} pattern='{}' cmd={}",
                            pid,
                            pattern,
                            truncate(cmdline, 200)
                        ),
                    ));
                    break;
                }
            }

            // Check for known C2/tunnel tools (skip safe system processes)
            let is_safe = SAFE_PROCESS_ALLOWLIST
                .iter()
                .any(|safe| lower.contains(safe));
            if !is_safe {
                for suspicious in SUSPICIOUS_PROCS {
                    if lower.contains(suspicious) {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!(
                                "Suspicious C2/tunnel process '{}' detected (pid {})",
                                suspicious, pid
                            ),
                            format!("pid={} cmd={}", pid, truncate(cmdline, 200)),
                        ));
                        break;
                    }
                }
            }
        }

        // Check 2: Look for suspicious established connections (bash/sh with network)
        if let Some(net_findings) = check_shell_network_connections() {
            findings.extend(net_findings);
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No reverse shell or C2 patterns detected",
            ));
        }

        Ok(findings)
    }
}

fn list_process_cmdlines() -> Vec<(String, String)> {
    let mut result = Vec::new();

    if cfg!(target_os = "macos") || cfg!(unix) {
        // Use ps to get all process command lines
        if let Ok(output) = Command::new("ps").args(["aux"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.splitn(11, char::is_whitespace).collect();
                if parts.len() >= 11 {
                    let pid = parts.iter().find(|p| p.parse::<u32>().is_ok())
                        .unwrap_or(&"0").to_string();
                    let cmd = parts[10].to_string();
                    result.push((pid, cmd));
                }
            }
        }
    }

    result
}

fn check_shell_network_connections() -> Option<Vec<Finding>> {
    let output = if cfg!(target_os = "macos") {
        Command::new("lsof")
            .args(["-iTCP", "-sTCP:ESTABLISHED", "-nP"])
            .output()
            .ok()?
    } else if cfg!(unix) {
        Command::new("ss").args(["-tnp"]).output().ok()?
    } else {
        return None;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    let shell_names = ["bash", "sh", "zsh", "dash", "fish", "ksh"];
    for line in stdout.lines() {
        let lower = line.to_lowercase();
        let has_shell = shell_names.iter().any(|s| {
            lower.contains(&format!("/{}", s)) || lower.contains(&format!(" {} ", s))
        });
        if has_shell {
            findings.push(META.finding_with_evidence(
                Status::Fail,
                "Shell process has an established network connection (possible reverse shell)",
                truncate(line.trim(), 300),
            ));
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
