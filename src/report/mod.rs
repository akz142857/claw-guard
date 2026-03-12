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
    pub agent_id: Option<String>,
    pub summary: ReportSummary,
    pub categories: Vec<CategorySummary>,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<crate::llm::AnalysisReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_loaded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_url: Option<String>,
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
    pub fn new(findings: Vec<Finding>, total_rules: usize, agent_id: Option<String>) -> Self {
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

        // ── Scoring: Weighted Category Pass-Rate Model ──────────────────
        //
        // Industry-standard approach (AWS Security Hub / CIS Benchmarks style):
        //
        // 1. Each category has an importance weight (total = 100 points).
        //    Weight reflects risk impact: sandbox/credential matter more than plugins.
        //
        // 2. Within each category, each finding has a severity weight:
        //    Critical=5, High=3, Medium=2, Low=1, Info=0.5
        //    Passing a Critical check earns more points than passing an Info check.
        //
        // 3. Per-rule-id dedup: multiple findings from the same rule count once
        //    (worst status wins: Fail > Warn > Error > Pass).
        //
        // 4. Category score = passed_weight / total_weight (0.0 to 1.0)
        //    Final score = Σ(category_score × category_importance)
        //
        // Benefits:
        //  - No single category can drag the score to 0
        //  - Severity matters (passing Critical checks contributes more)
        //  - Encourages balanced security posture across all categories

        let score = compute_weighted_score(&findings);

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
            agent_id,
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
            analysis: None,
            skills_loaded: None,
            web_url: None,
        }
    }

    pub fn print_terminal(&self) {
        // ── Header (lightweight) ────────────────────────────────────────
        println!();
        println!("  claw-guard v{} — {}  ({})", self.version, self.hostname, self.os);
        println!("  {}", self.timestamp);
        println!();

        // ── Category breakdown ──────────────────────────────────────────
        println!("  ── Category Breakdown ──");
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

        // ── Detailed findings (fail/warn/error) ────────────────────────
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

        // ── Passed (compact) ────────────────────────────────────────────
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

        // ── AI Analysis ─────────────────────────────────────────────────
        if let Some(ref analysis) = self.analysis {
            println!();
            println!("  ── AI Analysis ──────────────────────────────────");
            println!();
            println!("  Summary:");
            for line in wrap_text(&analysis.executive_summary, 70) {
                println!("  {}", line);
            }
            println!();

            if !analysis.risk_chains.is_empty() {
                println!("  Attack Chains:");
                for (i, chain) in analysis.risk_chains.iter().enumerate() {
                    println!(
                        "  {}. [{}] {}",
                        i + 1,
                        chain.likelihood,
                        chain.name
                    );
                    println!(
                        "     {} → {}",
                        chain.finding_ids.join(" + "),
                        chain.impact
                    );
                }
                println!();
            }

            if !analysis.priority_actions.is_empty() {
                println!("  Priority Fixes:");
                for action in &analysis.priority_actions {
                    println!(
                        "  {}. {}",
                        action.priority, action.command
                    );
                    println!(
                        "     ← {} ({})",
                        action.reason,
                        action.finding_ids.join(", ")
                    );
                }
                println!();
            }

            if !analysis.context_notes.is_empty() {
                println!("  Notes:");
                for note in &analysis.context_notes {
                    println!("  • {}", note);
                }
                println!();
            }

            println!("  ─────────────────────────────────────────────────");
        }

        // ── Score Summary (LAST — what the user sees when it finishes) ──
        println!();
        println!("╔══════════════════════════════════════════════════╗");
        println!("║              Audit Result Summary                ║");
        println!("╚══════════════════════════════════════════════════╝");
        println!(
            "  Score:    {}/100  {}",
            self.summary.score,
            score_bar(self.summary.score)
        );
        let skills_str = match self.skills_loaded {
            Some(n) if n > 0 => format!(" + {} skills", n),
            _ => String::new(),
        };
        println!(
            "  Rules: {}{}  |  Pass: {}  Fail: {}  Warn: {}  Skip: {}",
            self.summary.total_rules,
            skills_str,
            self.summary.pass,
            self.summary.fail,
            self.summary.warn,
            self.summary.skip,
        );
        if self.summary.critical_findings > 0 {
            println!(
                "  !! {} CRITICAL finding(s) !!",
                self.summary.critical_findings
            );
        }
        if self.summary.high_findings > 0 {
            println!(
                "  !  {} HIGH finding(s)",
                self.summary.high_findings
            );
        }
        if self.summary.critical_findings == 0 && self.summary.high_findings == 0 && self.summary.fail == 0 {
            println!("  All checks passed.");
        }

        // Agent ID & Web URL
        if let Some(ref id) = self.agent_id {
            println!("  Agent ID:   {}", id);
        }
        if let Some(ref url) = self.web_url {
            println!("  Web report: {}", url);
        }

        println!();
    }
}

/// Category importance weights (must sum to 100).
/// Reflects risk impact: sandbox/credential outweigh plugins/filesystem.
fn category_weight(cat: &Category) -> f64 {
    match cat {
        Category::Sandbox => 15.0,       // Single most impactful control
        Category::Credential => 12.0,    // Credential theft → full compromise
        Category::Network => 12.0,       // Network exposure → remote attack
        Category::GatewayConfig => 10.0, // Gateway auth → command execution
        Category::DestructiveAction => 10.0, // Prevents rm -rf / data loss
        Category::Process => 10.0,       // Process security → host compromise
        Category::CostSafety => 8.0,     // Financial risk
        Category::DataLeak => 8.0,       // Data exfiltration
        Category::Docker => 5.0,         // Container escape
        Category::Plugin => 5.0,         // Plugin supply chain
        Category::FileSystem => 5.0,     // File permission issues
        Category::Skill => 0.0,          // Dynamic skills — not scored
    }
}

/// Severity weight for scoring: how much a finding is "worth" when passed.
fn severity_weight(sev: &Severity) -> f64 {
    match sev {
        Severity::Critical => 5.0,
        Severity::High => 3.0,
        Severity::Medium => 2.0,
        Severity::Low => 1.0,
        Severity::Info => 0.5,
    }
}

/// Compute the weighted category pass-rate score (0-100).
fn compute_weighted_score(findings: &[Finding]) -> u8 {
    use std::collections::HashMap;

    // Step 1: Per-rule-id dedup — keep worst status per rule
    // Fail > Warn > Error > Skip > Pass
    let status_rank = |s: &Status| -> u8 {
        match s {
            Status::Fail => 4,
            Status::Warn => 3,
            Status::Error => 2,
            Status::Skip => 1,
            Status::Pass => 0,
        }
    };

    // Map: rule_id → (category, severity, worst_status)
    let mut rule_map: HashMap<String, (Category, Severity, Status)> = HashMap::new();
    for f in findings {
        let entry = rule_map
            .entry(f.rule_id.clone())
            .or_insert((f.category, f.severity, f.status));
        if status_rank(&f.status) > status_rank(&entry.2) {
            entry.2 = f.status;
        }
        // Use the highest severity seen for this rule
        if severity_weight(&f.severity) > severity_weight(&entry.1) {
            entry.1 = f.severity;
        }
    }

    // Step 2: Group by category, compute per-category pass rate
    let mut cat_totals: HashMap<Category, (f64, f64)> = HashMap::new(); // (passed_weight, total_weight)
    for (_rule_id, (cat, sev, status)) in &rule_map {
        let w = severity_weight(sev);
        let entry = cat_totals.entry(*cat).or_insert((0.0, 0.0));
        entry.1 += w; // total
        match status {
            Status::Pass => entry.0 += w,            // full credit
            Status::Warn => entry.0 += w * 0.5,      // partial credit for warnings
            Status::Skip => entry.0 += w * 0.8,      // skipped ≈ not applicable, mostly OK
            _ => {}                                    // Fail/Error = 0 credit
        }
    }

    // Step 3: Weighted sum across categories
    let mut earned = 0.0f64;
    let mut possible = 0.0f64;

    for (cat, (passed_w, total_w)) in &cat_totals {
        let importance = category_weight(cat);
        if importance == 0.0 || *total_w == 0.0 {
            continue;
        }
        let pass_rate = passed_w / total_w; // 0.0 to 1.0
        earned += pass_rate * importance;
        possible += importance;
    }

    // Categories with no findings get full credit (nothing to fail)
    // Add weight for categories that had no findings at all
    let categories_with_findings: std::collections::HashSet<Category> =
        cat_totals.keys().cloned().collect();
    let all_categories = [
        Category::Sandbox, Category::Credential, Category::Network,
        Category::GatewayConfig, Category::DestructiveAction, Category::Process,
        Category::CostSafety, Category::DataLeak, Category::Docker,
        Category::Plugin, Category::FileSystem,
    ];
    for cat in &all_categories {
        if !categories_with_findings.contains(cat) {
            let w = category_weight(cat);
            earned += w;   // full credit — no findings = no problems
            possible += w;
        }
    }

    if possible == 0.0 {
        return 100;
    }

    let score = (earned / possible * 100.0).round() as u8;
    score.min(100)
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn score_bar(score: u8) -> String {
    let filled = (score as usize) / 5;
    let empty = 20 - filled;
    let bar: String = "█".repeat(filled) + &"░".repeat(empty);

    let label = match score {
        90..=100 => "Excellent",  // A
        75..=89 => "Good",        // B
        60..=74 => "Fair",        // C
        40..=59 => "Poor",        // D
        _ => "Critical",          // F
    };

    format!("[{}] {}", bar, label)
}
