use crate::engine::{Category, Finding, Severity, Status};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub version: String,
    pub timestamp: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub platform_id: Option<String>,
    pub summary: ReportSummary,
    pub categories: Vec<CategorySummary>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_rules: usize,
    pub total_findings: usize,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
    pub skip: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub score: u8, // 0-100, higher is better
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: Category,
    pub label: String,
    pub total: usize,
    pub fail: usize,
    pub warn: usize,
}

impl AuditReport {
    pub fn new(findings: Vec<Finding>, total_rules: usize, platform_id: Option<String>) -> Self {
        let total_findings = findings.len();
        let pass = findings.iter().filter(|f| f.status == Status::Pass).count();
        let fail = findings.iter().filter(|f| f.status == Status::Fail).count();
        let warn = findings.iter().filter(|f| f.status == Status::Warn).count();
        let error = findings.iter().filter(|f| f.status == Status::Error).count();
        let skip = findings.iter().filter(|f| f.status == Status::Skip).count();
        let critical_findings = findings
            .iter()
            .filter(|f| f.status == Status::Fail && f.severity == Severity::Critical)
            .count();
        let high_findings = findings
            .iter()
            .filter(|f| f.status == Status::Fail && f.severity == Severity::High)
            .count();

        // Score: per-rule dedup — same rule failing multiple times only penalizes once.
        // This prevents e.g. 5 world-readable credential dirs from draining 75 points.
        let mut penalized_rules = std::collections::HashSet::new();
        let mut penalty: usize = 0;
        for f in findings.iter().filter(|f| f.status == Status::Fail) {
            if penalized_rules.insert(f.rule_id.clone()) {
                penalty += match f.severity {
                    Severity::Critical => 15,
                    Severity::High => 8,
                    Severity::Medium => 4,
                    Severity::Low => 2,
                    Severity::Info => 0,
                };
            }
        }
        let score = 100u8.saturating_sub(penalty.min(100) as u8);

        // Category breakdown
        let mut cat_map: HashMap<Category, (usize, usize, usize)> = HashMap::new();
        for f in &findings {
            let entry = cat_map.entry(f.category).or_insert((0, 0, 0));
            entry.0 += 1;
            if f.status == Status::Fail {
                entry.1 += 1;
            }
            if f.status == Status::Warn {
                entry.2 += 1;
            }
        }

        let mut categories: Vec<CategorySummary> = cat_map
            .into_iter()
            .map(|(cat, (total, fail, warn))| CategorySummary {
                label: cat.to_string(),
                category: cat,
                total,
                fail,
                warn,
            })
            .collect();
        categories.sort_by(|a, b| b.fail.cmp(&a.fail).then(b.warn.cmp(&a.warn)));

        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        AuditReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().to_rfc3339(),
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            platform_id,
            summary: ReportSummary {
                total_rules,
                total_findings,
                pass,
                fail,
                warn,
                error,
                skip,
                critical_findings,
                high_findings,
                score,
            },
            categories,
            findings,
        }
    }

    pub fn print_terminal(&self) {
        println!();
        println!("╔══════════════════════════════════════════════════╗");
        println!("║        claw-guard Security Audit Report         ║");
        println!("╚══════════════════════════════════════════════════╝");
        println!();
        println!("  Host:     {}  ({})", self.hostname, self.os);
        println!("  Time:     {}", self.timestamp);
        println!("  Version:  {}", self.version);
        println!(
            "  Score:    {}/100  {}",
            self.summary.score,
            score_bar(self.summary.score)
        );
        println!();

        // Summary bar
        println!(
            "  Rules: {}  |  Pass: {}  Fail: {}  Warn: {}  Skip: {}",
            self.summary.total_rules,
            self.summary.pass,
            self.summary.fail,
            self.summary.warn,
            self.summary.skip,
        );

        if self.summary.critical_findings > 0 {
            println!(
                "\n  !! {} CRITICAL finding(s) !!",
                self.summary.critical_findings
            );
        }
        if self.summary.high_findings > 0 {
            println!(
                "  !  {} HIGH finding(s)",
                self.summary.high_findings
            );
        }

        // Category breakdown
        println!("\n  ── Category Breakdown ──");
        for cat in &self.categories {
            let status_icon = if cat.fail > 0 {
                "✗"
            } else if cat.warn > 0 {
                "⚠"
            } else {
                "✓"
            };
            println!(
                "  {} {:<30} {:>2} checks  {:>2} fail  {:>2} warn",
                status_icon, cat.label, cat.total, cat.fail, cat.warn,
            );
        }

        // Detailed findings — only show non-pass
        let issues: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.status != Status::Pass && f.status != Status::Skip)
            .collect();

        if !issues.is_empty() {
            println!("\n  ── Findings ──");
            for f in &issues {
                let icon = match f.status {
                    Status::Fail => "✗",
                    Status::Warn => "⚠",
                    Status::Error => "?",
                    _ => " ",
                };
                println!(
                    "  {} [{}] {} ({})",
                    icon, f.severity, f.rule_id, f.rule_name,
                );
                println!("    {}", f.detail);
                if let Some(ref ev) = f.evidence {
                    println!("    evidence: {}", ev);
                }
                println!("    fix: {}", f.remediation);
                println!();
            }
        }

        // Pass summary
        let passed: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.status == Status::Pass)
            .collect();
        if !passed.is_empty() {
            println!("  ── Passed ({}) ──", passed.len());
            for f in &passed {
                println!("  ✓ {} {}", f.rule_id, f.detail);
            }
        }

        println!();
    }
}

fn score_bar(score: u8) -> String {
    let filled = (score as usize) / 5;
    let empty = 20 - filled;
    let bar: String = "█".repeat(filled) + &"░".repeat(empty);

    let label = match score {
        90..=100 => "Excellent",
        70..=89 => "Good",
        50..=69 => "Fair",
        30..=49 => "Poor",
        _ => "Critical",
    };

    format!("[{}] {}", bar, label)
}
