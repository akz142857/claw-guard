use crate::engine::*;
use crate::platform;
use anyhow::Result;

/// CG-M003: No usage alert / webhook configured
pub struct CgM003;

static META: RuleMeta = RuleMeta {
    id: "CG-M003",
    name: "No usage alert configured",
    description: "Checks if OpenClaw has alert/webhook/notification for cost thresholds. \
                  Without alerts, a billing spike may go unnoticed until the invoice arrives.",
    category: Category::CostSafety,
    severity: Severity::Medium,
    remediation: "Configure usage alerts in openclaw.json: \
                  {\"llm\": {\"alertWebhook\": \"https://...\", \"alertThresholdPercent\": 80}}. \
                  Also enable billing alerts on each provider dashboard.",
};

const ALERT_FIELDS: &[&str] = &[
    "/llm/alertWebhook",
    "/llm/alertEmail",
    "/llm/alertThresholdPercent",
    "/llm/notifications",
    "/cost/alertWebhook",
    "/cost/notifications",
    "/alerts/cost",
];

impl StaticRule for CgM003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let config_path = platform::home_dir().join(".openclaw/openclaw.json");

        if !config_path.exists() {
            return Ok(vec![META.finding(
                Status::Fail,
                "openclaw.json not found — no usage alerts can be configured",
            )]);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let has_alert = ALERT_FIELDS
            .iter()
            .any(|path| json.pointer(path).is_some());

        if has_alert {
            Ok(vec![META.finding(
                Status::Pass,
                "Usage alert/notification configuration found",
            )])
        } else {
            Ok(vec![META.finding(
                Status::Fail,
                "No usage alerts or cost notification webhooks configured. \
                 Billing spikes may go unnoticed.",
            )])
        }
    }
}
