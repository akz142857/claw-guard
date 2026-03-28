use crate::engine::*;
use crate::platform;
use anyhow::Result;
use std::io::{BufRead, BufReader};

/// CG-D003: Config audit log analysis for unauthorized changes
pub struct CgD003;

static META: RuleMeta = RuleMeta {
    id: "CG-D003",
    name: "Config change audit trail",
    description: "Analyzes OpenClaw config-audit.jsonl for security-relevant configuration \
                  changes: auth mode modifications, sandbox disabling, plugin installs, \
                  secret provider additions.",
    category: Category::DataLeak,
    severity: Severity::Medium,
    remediation: "Review config-audit.jsonl for unauthorized changes. \
                  Implement config file integrity monitoring.",
};

/// Config paths that are security-sensitive.
const SENSITIVE_CONFIG_KEYS: &[&str] = &[
    "gateway.auth",
    "agents.defaults.sandbox",
    "secrets.providers",
    "plugins",
    "hooks",
    "tools.exec",
    "dangerously",
    "allowInsecure",
    "allowUnsafe",
];

impl StaticRule for CgD003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        // config-audit.jsonl lives in the state directory alongside logs
        let home = platform::home_dir();
        let audit_paths = vec![
            home.join(".openclaw/logs/config-audit.jsonl"),
            home.join(".openclaw/config-audit.jsonl"),
        ];

        let mut audit_path = None;
        for p in &audit_paths {
            if p.exists() {
                audit_path = Some(p.clone());
                break;
            }
        }

        let path = match audit_path {
            Some(p) => p,
            None => return Ok(vec![META.finding(Status::Skip, "No config-audit.jsonl found")]),
        };

        let file = std::fs::File::open(&path)?;
        let reader = BufReader::new(file);

        let mut security_changes = 0u32;
        let mut recent_changes = Vec::new();

        // Scan last 1000 lines
        let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
        let start = lines.len().saturating_sub(1000);

        for line in &lines[start..] {
            let lower = line.to_lowercase();
            for key in SENSITIVE_CONFIG_KEYS {
                if lower.contains(key) {
                    security_changes += 1;
                    if recent_changes.len() < 5 {
                        // Keep first 5 as samples
                        recent_changes.push(key.to_string());
                    }
                    break;
                }
            }
        }

        if security_changes == 0 {
            Ok(vec![META.finding(
                Status::Pass,
                "No security-relevant config changes in audit log",
            )])
        } else {
            Ok(vec![META.finding_with_evidence(
                Status::Warn,
                format!(
                    "{} security-relevant config change(s) in audit log, review recommended",
                    security_changes
                ),
                format!(
                    "file={} change_count={} sample_keys=[{}]",
                    path.display(),
                    security_changes,
                    recent_changes.join(", ")
                ),
            )])
        }
    }
}
