use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-M001: No API cost / rate limit configured
pub struct CgM001;

static META: RuleMeta = RuleMeta {
    id: "CG-M001",
    name: "API cost limit not configured",
    description: "Checks if OpenClaw config has spending caps (maxMonthlySpend, \
                  maxDailyTokens, rateLimitPerMinute). Without limits, a runaway agent \
                  can exhaust API credits in minutes.",
    category: Category::CostSafety,
    severity: Severity::Critical,
    remediation: "Set cost limits in openclaw.json: \
                  {\"llm\": {\"maxMonthlySpend\": 100, \"maxDailyTokens\": 1000000, \
                  \"rateLimitPerMinute\": 60}}. Also set spending alerts on your \
                  provider dashboard (OpenAI, Anthropic, etc.).",
};

const COST_LIMIT_FIELDS: &[&str] = &[
    "/llm/maxMonthlySpend",
    "/llm/maxDailySpend",
    "/llm/maxDailyTokens",
    "/llm/rateLimitPerMinute",
    "/llm/maxRequestsPerHour",
    "/llm/budgetLimit",
    // Alternative common config paths
    "/cost/limit",
    "/cost/maxMonthly",
    "/limits/maxMonthlySpend",
];

impl StaticRule for CgM001 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Fail,
                "openclaw.json not found — no cost limits can be configured",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let has_any_limit = COST_LIMIT_FIELDS
            .iter()
            .any(|path| json.pointer(path).is_some());

        if has_any_limit {
            Ok(vec![META.finding(
                Status::Pass,
                "Cost/rate limit configuration found",
            )])
        } else {
            Ok(vec![META.finding(
                Status::Fail,
                "No API cost or rate limits configured. A runaway agent loop can \
                 exhaust your API budget within minutes.",
            )])
        }
    }
}
