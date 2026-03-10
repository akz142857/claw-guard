use crate::engine::*;
use anyhow::Result;

/// CG-M002: Multiple high-value API keys present in environment
pub struct CgM002;

static META: RuleMeta = RuleMeta {
    id: "CG-M002",
    name: "Multiple high-value API keys exposed",
    description: "Detects when multiple LLM provider API keys are simultaneously available \
                  in the environment. Each active key multiplies the blast radius of a \
                  credential leak or agent hijack.",
    category: Category::CostSafety,
    severity: Severity::High,
    remediation: "Only export the API key for the provider you are actively using. \
                  Use a secrets manager or .env file scoped to the project instead \
                  of global shell exports. Revoke unused keys.",
};

/// Patterns for high-value API keys (provider, env var prefix)
const API_KEY_PATTERNS: &[(&str, &[&str])] = &[
    ("OpenAI", &["OPENAI_API_KEY", "OPENAI_KEY"]),
    ("Anthropic", &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]),
    ("Google AI", &["GOOGLE_API_KEY", "GEMINI_API_KEY"]),
    ("Azure OpenAI", &["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY"]),
    ("AWS Bedrock", &["AWS_ACCESS_KEY_ID"]),
    ("Mistral", &["MISTRAL_API_KEY"]),
    ("Cohere", &["COHERE_API_KEY", "CO_API_KEY"]),
    ("Together AI", &["TOGETHER_API_KEY", "TOGETHER_AI_KEY"]),
    ("OpenRouter", &["OPENROUTER_API_KEY"]),
    ("DeepSeek", &["DEEPSEEK_API_KEY"]),
    ("Moonshot", &["MOONSHOT_API_KEY"]),
    ("Qwen", &["DASHSCOPE_API_KEY", "QWEN_API_KEY"]),
    ("Qianfan", &["QIANFAN_ACCESS_KEY", "QIANFAN_AK"]),
    ("MiniMax", &["MINIMAX_API_KEY", "MINIMAX_GROUP_ID"]),
    ("Hugging Face", &["HF_TOKEN", "HUGGINGFACE_API_KEY"]),
];

impl StaticRule for CgM002 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut active_providers = Vec::new();

        for (provider, env_vars) in API_KEY_PATTERNS {
            for var in *env_vars {
                if let Ok(val) = std::env::var(var) {
                    if !val.is_empty() {
                        active_providers.push((*provider, *var));
                        break; // one match per provider is enough
                    }
                }
            }
        }

        if active_providers.len() <= 1 {
            Ok(vec![META.finding(
                Status::Pass,
                format!(
                    "{} LLM provider key(s) in environment — acceptable",
                    active_providers.len()
                ),
            )])
        } else {
            let evidence: Vec<String> = active_providers
                .iter()
                .map(|(provider, var)| format!("{} ({})", provider, var))
                .collect();
            Ok(vec![META.finding_with_evidence(
                Status::Fail,
                format!(
                    "{} LLM provider keys active simultaneously — credential leak blast radius is multiplied",
                    active_providers.len()
                ),
                evidence.join(", "),
            )])
        }
    }
}
