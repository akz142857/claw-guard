use crate::engine::*;
use anyhow::Result;

/// CG-C003: Sensitive API key environment variables exposed in current environment
pub struct CgC003;

static META: RuleMeta = RuleMeta {
    id: "CG-C003",
    name: "Sensitive environment variables",
    description: "Checks if API keys and tokens are set in the environment, which OpenClaw \
                  child processes may inherit. Covers 50+ known provider key patterns.",
    category: Category::Credential,
    severity: Severity::High,
    remediation: "Use OpenClaw secret providers (exec/file) instead of env vars. \
                  If env vars are required, ensure sandbox mode strips them.",
};

/// Env var names known to contain sensitive credentials.
const SENSITIVE_ENV_VARS: &[&str] = &[
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_OAUTH_TOKEN",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY",
    "AI_GATEWAY_API_KEY", "MINIMAX_API_KEY", "ELEVENLABS_API_KEY",
    "DEEPGRAM_API_KEY", "TOGETHER_API_KEY", "MISTRAL_API_KEY",
    "HUGGINGFACE_HUB_TOKEN", "HF_TOKEN",
    "OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GH_TOKEN", "GITHUB_TOKEN",
    "TELEGRAM_BOT_TOKEN", "DISCORD_BOT_TOKEN",
    "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN",
    "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN",
    "AZURE_OPENAI_API_KEY", "COHERE_API_KEY",
    "MATTERMOST_BOT_TOKEN",
    "CLOUDFLARE_AI_GATEWAY_API_KEY", "LITELLM_API_KEY",
    "BRAVE_API_KEY", "PERPLEXITY_API_KEY", "FIRECRAWL_API_KEY",
    "SSLKEYLOGFILE",
];

/// Suffix patterns that indicate sensitive vars.
const SENSITIVE_SUFFIXES: &[&str] = &[
    "_API_KEY", "_SECRET_KEY", "_TOKEN", "_PASSWORD", "_PRIVATE_KEY", "_SECRET",
];

impl Rule for CgC003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut exposed = Vec::new();

        // Check known names
        for var in SENSITIVE_ENV_VARS {
            if std::env::var(var).is_ok() {
                exposed.push(var.to_string());
            }
        }

        // Check suffix patterns
        for (key, _) in std::env::vars() {
            let upper = key.to_uppercase();
            for suffix in SENSITIVE_SUFFIXES {
                if upper.ends_with(suffix) && !exposed.contains(&key) {
                    exposed.push(key.clone());
                }
            }
        }

        if exposed.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No sensitive API keys/tokens found in current environment",
            ));
        } else {
            findings.push(META.finding_with_evidence(
                Status::Fail,
                format!(
                    "{} sensitive env var(s) exposed, child processes will inherit them",
                    exposed.len()
                ),
                format!("vars=[{}]", exposed.join(", ")),
            ));
        }

        Ok(findings)
    }
}
