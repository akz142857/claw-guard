use crate::engine::Status;
use crate::report::AuditReport;

pub fn build_prompt(report: &AuditReport) -> String {
    // Non-pass findings with full detail for LLM analysis
    let issues_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .filter(|f| f.status != Status::Pass && f.status != Status::Skip)
        .map(|f| {
            serde_json::json!({
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "detail": f.detail,
                "evidence": f.evidence,
                "remediation": f.remediation,
            })
        })
        .collect();

    // Pass summary — compact, just IDs and names to show coverage
    let passed_summary: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Pass)
        .map(|f| format!("{} ({})", f.rule_id, f.rule_name))
        .collect();

    format!(
        r#"You are a senior security analyst specializing in AI agent host system security.
Analyze the following claw-guard security audit report and produce a structured analysis.

## System Context
- Host: {} ({}/{})
- Audit Score: {}/100
- Total Rules: {}, Pass: {}, Fail: {}, Warn: {}, Skip: {}
- Critical Findings: {}, High Findings: {}

## Category Breakdown
{}

## Issues (fail/warn/error findings)
{}

## Passed Checks
{}

## Your Task

Produce a JSON object with exactly this structure:
{{
  "executive_summary": "A concise paragraph summarizing overall security posture, key risks, and urgency level",
  "risk_chains": [
    {{
      "name": "Short name for the attack chain",
      "finding_ids": ["CG-X001", "CG-X002"],
      "impact": "What an attacker could achieve",
      "likelihood": "How likely this is to be exploited"
    }}
  ],
  "priority_actions": [
    {{
      "priority": 1,
      "command": "Specific remediation command (e.g. chmod 700 ~/.aws)",
      "reason": "Why this should be done first",
      "finding_ids": ["CG-X001"]
    }}
  ],
  "context_notes": [
    "Environment-specific observation or recommendation"
  ]
}}

Rules:
1. Identify attack chains — combinations of findings that together create exploitable paths
2. Prioritize actions by impact: what single fix blocks the most attack chains?
3. Consider the OS/arch context (dev machine vs server, platform-specific risks)
4. If there are no failures, still provide positive observations and hardening suggestions
5. NEVER include actual credentials, keys, or sensitive values in your output
6. Output ONLY the JSON object, no markdown fencing, no explanation before/after"#,
        report.hostname,
        report.os,
        report.arch,
        report.summary.score,
        report.summary.total_rules,
        report.summary.pass,
        report.summary.fail,
        report.summary.warn,
        report.summary.skip,
        report.summary.critical_findings,
        report.summary.high_findings,
        report
            .categories
            .iter()
            .map(|c| format!("- {}: {} checks, {} fail, {} warn", c.label, c.total, c.fail, c.warn))
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::to_string_pretty(&issues_json).unwrap_or_default(),
        passed_summary.join(", "),
    )
}
