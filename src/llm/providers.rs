/// Static provider registry — maps provider names to default configurations.

/// How the API key is passed to the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    /// `Authorization: Bearer {key}`
    BearerToken,
    /// `x-api-key: {key}` (Anthropic)
    XApiKey,
    /// No authentication (local servers)
    None,
}

/// Which HTTP request/response format to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// OpenAI-compatible `/v1/chat/completions`
    OpenAiCompat,
    /// Anthropic Messages API
    Anthropic,
}

/// Configuration for a known provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: &'static str,
    pub display_name: &'static str,
    pub base_url: &'static str,
    pub api_path: &'static str,
    pub auth_type: AuthType,
    pub default_model: &'static str,
    pub protocol: Protocol,
}

/// All known providers.
static PROVIDERS: &[ProviderConfig] = &[
    // ── Direct API providers ────────────────────────────────────────
    ProviderConfig {
        name: "anthropic",
        display_name: "Anthropic",
        base_url: "https://api.anthropic.com",
        api_path: "/v1/messages",
        auth_type: AuthType::XApiKey,
        default_model: "claude-sonnet-4-20250514",
        protocol: Protocol::Anthropic,
    },
    ProviderConfig {
        name: "openai",
        display_name: "OpenAI",
        base_url: "https://api.openai.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "gpt-4o",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "ollama",
        display_name: "Ollama (local)",
        base_url: "http://localhost:11434",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::None,
        default_model: "llama3",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "vllm",
        display_name: "vLLM (local)",
        base_url: "http://localhost:8000",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::None,
        default_model: "default",
        protocol: Protocol::OpenAiCompat,
    },
    // ── Gateway / aggregator providers ──────────────────────────────
    ProviderConfig {
        name: "openrouter",
        display_name: "OpenRouter",
        base_url: "https://openrouter.ai/api",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "anthropic/claude-sonnet-4-20250514",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "together",
        display_name: "Together AI",
        base_url: "https://api.together.xyz",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "meta-llama/Llama-3-70b-chat-hf",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "litellm",
        display_name: "LiteLLM",
        base_url: "http://localhost:4000",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "gpt-4o",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "cloudflare",
        display_name: "Cloudflare AI Gateway",
        base_url: "https://gateway.ai.cloudflare.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "@cf/meta/llama-3-8b-instruct",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "vercel",
        display_name: "Vercel AI Gateway",
        base_url: "https://api.vercel.ai",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "gpt-4o",
        protocol: Protocol::OpenAiCompat,
    },
    // ── Model vendors (OpenAI-compatible) ───────────────────────────
    ProviderConfig {
        name: "mistral",
        display_name: "Mistral",
        base_url: "https://api.mistral.ai",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "mistral-large-latest",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "nvidia",
        display_name: "NVIDIA",
        base_url: "https://integrate.api.nvidia.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "meta/llama-3.1-70b-instruct",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "deepseek",
        display_name: "DeepSeek",
        base_url: "https://api.deepseek.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "deepseek-chat",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "moonshot",
        display_name: "Moonshot (Kimi)",
        base_url: "https://api.moonshot.cn",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "moonshot-v1-8k",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "glm",
        display_name: "GLM (Zhipu AI)",
        base_url: "https://open.bigmodel.cn/api/paas",
        api_path: "/v4/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "glm-4",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "qwen",
        display_name: "Qwen (Alibaba)",
        base_url: "https://dashscope.aliyuncs.com/compatible-mode",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "qwen-max",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "minimax",
        display_name: "MiniMax",
        base_url: "https://api.minimax.chat",
        api_path: "/v1/text/chatcompletion_v2",
        auth_type: AuthType::BearerToken,
        default_model: "abab6.5s-chat",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "huggingface",
        display_name: "Hugging Face",
        base_url: "https://api-inference.huggingface.co",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "meta-llama/Llama-3-70b-chat-hf",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "qianfan",
        display_name: "Qianfan (Baidu)",
        base_url: "https://qianfan.baidubce.com",
        api_path: "/v2/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "ernie-4.0-8k",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "bedrock",
        display_name: "Amazon Bedrock",
        base_url: "https://bedrock-runtime.us-east-1.amazonaws.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "anthropic.claude-sonnet-4-20250514-v1:0",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "venice",
        display_name: "Venice",
        base_url: "https://api.venice.ai",
        api_path: "/api/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "llama-3.1-405b",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "xiaomi",
        display_name: "Xiaomi",
        base_url: "https://api.ai.xiaomi.com",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "xiaomi-ai-large",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "zai",
        display_name: "Z.AI",
        base_url: "https://api.z.ai",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "default",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "kilocode",
        display_name: "Kilocode",
        base_url: "https://api.kilocode.ai",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "default",
        protocol: Protocol::OpenAiCompat,
    },
    ProviderConfig {
        name: "opencode-zen",
        display_name: "OpenCode Zen",
        base_url: "https://api.opencode.ai",
        api_path: "/v1/chat/completions",
        auth_type: AuthType::BearerToken,
        default_model: "default",
        protocol: Protocol::OpenAiCompat,
    },
];

/// Find a provider by name (case-insensitive).
pub fn find_provider(name: &str) -> Option<&'static ProviderConfig> {
    let lower = name.to_lowercase();
    PROVIDERS.iter().find(|p| p.name == lower)
}

/// Return all known providers (for --list-providers).
pub fn all_providers() -> &'static [ProviderConfig] {
    PROVIDERS
}
