use crate::engine::*;
use crate::platform;
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// CG-D001: API key patterns in shell history and OpenClaw logs
pub struct CgD001;

static META: RuleMeta = RuleMeta {
    id: "CG-D001",
    name: "API key leak in history/logs",
    description: "Scans shell history files and OpenClaw logs for known API key patterns \
                  (OpenAI sk-, Anthropic sk-ant-, AWS AKIA, GitHub ghp_, etc). \
                  Never extracts or uploads actual key values.",
    category: Category::DataLeak,
    severity: Severity::High,
    remediation: "Rotate any exposed keys immediately. Use secret managers instead of \
                  pasting keys in terminal. Add HISTIGNORE patterns for sensitive commands.",
};

const KEY_PATTERNS: &[(&str, &str)] = &[
    ("openai", "sk-"),
    ("anthropic", "sk-ant-"),
    ("aws_access_key", "AKIA"),
    ("github_token", "ghp_"),
    ("github_pat", "github_pat_"),
    ("gitlab_token", "glpat-"),
    ("slack_token", "xoxb-"),
    ("stripe_key", "sk_live_"),
    ("sendgrid_key", "SG."),
    ("database_url_pg", "postgres://"),
    ("database_url_mysql", "mysql://"),
    ("database_url_mongo", "mongodb+srv://"),
];

fn scan_file(path: &PathBuf) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    let reader = BufReader::new(file);
    let mut found = Vec::new();

    for line in reader.lines().take(100_000) {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        for (key_type, pattern) in KEY_PATTERNS {
            if line.contains(pattern) && !found.contains(&key_type.to_string()) {
                found.push(key_type.to_string());
            }
        }
    }
    found
}

impl Rule for CgD001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Shell history
        for path in platform::shell_history_files() {
            if !path.exists() {
                continue;
            }
            let found = scan_file(&path);
            if found.is_empty() {
                findings.push(META.finding(
                    Status::Pass,
                    format!("No key patterns in {}", path.display()),
                ));
            } else {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("API key patterns in {}", path.display()),
                    format!("file={} types=[{}]", path.display(), found.join(", ")),
                ));
            }
        }

        // OpenClaw logs
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
                    let found = scan_file(&path);
                    if !found.is_empty() {
                        findings.push(META.finding_with_evidence(
                            Status::Fail,
                            format!("API key patterns in log {}", path.display()),
                            format!("file={} types=[{}]", path.display(), found.join(", ")),
                        ));
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(META.finding(Status::Pass, "No history or log files to scan"));
        }

        Ok(findings)
    }
}
