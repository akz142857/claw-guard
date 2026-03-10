use crate::engine::*;
use anyhow::Result;
use std::process::Command;

/// CG-P003: Suspicious cron / scheduled task audit
pub struct CgP003;

static META: RuleMeta = RuleMeta {
    id: "CG-P003",
    name: "Cron job / scheduled task audit",
    description: "Audits crontab entries and scheduled tasks for suspicious patterns: \
                  download-and-execute, encoded payloads, reverse connections, \
                  cryptocurrency miners, or tasks created recently.",
    category: Category::Process,
    severity: Severity::High,
    remediation: "Review and remove suspicious cron entries with 'crontab -e'. \
                  Check /etc/cron.* directories and systemd timers. \
                  Restrict crontab access via /etc/cron.allow.",
};

const SUSPICIOUS_CRON_PATTERNS: &[&str] = &[
    // Download and execute
    "curl.*|.*sh",
    "curl.*|.*bash",
    "wget.*|.*sh",
    "wget.*|.*bash",
    "curl.*-o.*/tmp/",
    "wget.*-O.*/tmp/",
    // Encoded payloads
    "base64 -d",
    "base64 --decode",
    "eval $(echo",
    "echo.*|.*base64",
    "python -c",
    "python3 -c",
    "perl -e",
    // Reverse shells and C2
    "/dev/tcp/",
    "/dev/udp/",
    "nc -e",
    "ncat ",
    // Miners
    "xmrig",
    "minerd",
    "cpuminer",
    "stratum+tcp",
    "nicehash",
    "pool.mining",
    "cryptonight",
    // Suspicious paths
    "/tmp/.",       // hidden files in /tmp
    "/dev/shm/",
    "/var/tmp/.",
];

impl StaticRule for CgP003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check current user's crontab
        match Command::new("crontab").arg("-l").output() {
            Ok(output) => {
                if output.status.success() {
                    let crontab = String::from_utf8_lossy(&output.stdout);
                    check_cron_content(&crontab, "user crontab", &mut findings);
                }
                // Exit code 1 = no crontab, which is fine
            }
            Err(_) => {
                // crontab command not found (Windows, etc.)
            }
        }

        // Check system cron directories
        let cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];

        for dir in &cron_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        let source = format!("{}", entry.path().display());
                        check_cron_content(&content, &source, &mut findings);
                    }
                }
            }
        }

        // Check /etc/crontab
        if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
            check_cron_content(&content, "/etc/crontab", &mut findings);
        }

        // Check systemd timers for suspicious entries
        if cfg!(unix) {
            if let Ok(output) = Command::new("systemctl")
                .args(["list-timers", "--all", "--no-pager"])
                .output()
            {
                if output.status.success() {
                    let timers = String::from_utf8_lossy(&output.stdout);
                    for line in timers.lines() {
                        let lower = line.to_lowercase();
                        for pattern in SUSPICIOUS_CRON_PATTERNS {
                            if lower.contains(&pattern.to_lowercase()) {
                                findings.push(META.finding_with_evidence(
                                    Status::Fail,
                                    "Suspicious systemd timer entry",
                                    truncate(line.trim(), 200),
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No suspicious cron jobs or scheduled tasks detected",
            ));
        }

        Ok(findings)
    }
}

fn check_cron_content(content: &str, source: &str, findings: &mut Vec<Finding>) {
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let lower = trimmed.to_lowercase();
        for pattern in SUSPICIOUS_CRON_PATTERNS {
            if lower.contains(&pattern.to_lowercase()) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Suspicious cron entry in {} matches '{}'", source, pattern),
                    truncate(trimmed, 200),
                ));
                break;
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
