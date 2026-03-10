use crate::engine::*;
use crate::platform;
use anyhow::Result;
use std::io::{BufRead, BufReader};

/// CG-D002: Sensitive information patterns in OpenClaw logs
pub struct CgD002;

static META: RuleMeta = RuleMeta {
    id: "CG-D002",
    name: "Sensitive data in logs",
    description: "Scans OpenClaw log files for passwords, private keys, bearer tokens, \
                  internal IPs, and other sensitive patterns that indicate information leakage.",
    category: Category::DataLeak,
    severity: Severity::Medium,
    remediation: "Configure OpenClaw log level to reduce verbosity. \
                  Implement log scrubbing for sensitive patterns. \
                  Rotate and securely delete old log files.",
};

const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("password", "password"),
    ("secret", "secret"),
    ("private_key", "-----BEGIN"),
    ("internal_ip_192", "192.168."),
    ("internal_ip_10", "10.0."),
    ("connection_string", "connection_string"),
    ("bearer_token", "bearer "),
    ("authorization", "authorization:"),
];

impl Rule for CgD002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut scanned = false;

        for dir in platform::openclaw_log_dirs() {
            if !dir.is_dir() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    scanned = true;

                    let file = match std::fs::File::open(&path) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let reader = BufReader::new(file);
                    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
                    let start = lines.len().saturating_sub(10_000);
                    let mut found = Vec::new();

                    for line in &lines[start..] {
                        let lower = line.to_lowercase();
                        for (leak_type, pattern) in SENSITIVE_PATTERNS {
                            if lower.contains(pattern) && !found.contains(&leak_type.to_string()) {
                                found.push(leak_type.to_string());
                            }
                        }
                    }

                    if !found.is_empty() {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("Sensitive patterns in {}", path.display()),
                            format!("file={} types=[{}]", path.display(), found.join(", ")),
                        ));
                    }
                }
            }
        }

        if !scanned {
            findings.push(META.finding(Status::Pass, "No OpenClaw log directories found"));
        } else if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No sensitive patterns found in logs"));
        }

        Ok(findings)
    }
}
