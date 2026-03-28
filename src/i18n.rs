use crate::engine::{Category, Severity};

/// Supported languages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    /// All available languages for the UI picker
    pub fn all() -> &'static [Lang] {
        &[Lang::En, Lang::Zh]
    }

    pub fn label(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Zh => "中文",
        }
    }
}

/// Detect system language. Falls back to English.
pub fn detect_system_lang() -> Lang {
    // Check LANG / LC_ALL env vars first
    for var in &["LANG", "LC_ALL", "LC_MESSAGES"] {
        if let Ok(val) = std::env::var(var) {
            let val = val.to_lowercase();
            if val.starts_with("zh") {
                return Lang::Zh;
            }
        }
    }

    // macOS: check AppleLanguages via defaults
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if s.contains("zh") {
                return Lang::Zh;
            }
        }
    }

    Lang::En
}

/// All translatable UI strings
#[allow(dead_code)]
pub struct Tr {
    pub lang: Lang,
}

#[allow(dead_code)]
impl Tr {
    pub fn new(lang: Lang) -> Self {
        Self { lang }
    }

    // ── Welcome / Idle ──

    pub fn app_subtitle(&self) -> &'static str {
        match self.lang {
            Lang::En => "AI Agent Host Security Audit",
            Lang::Zh => "AI 智能体宿主安全审计",
        }
    }

    pub fn cloud_analysis(&self) -> &'static str {
        match self.lang {
            Lang::En => "Cloud Analysis & Fix Recommendations",
            Lang::Zh => "云端分析与修复建议",
        }
    }

    pub fn cloud_analysis_desc(&self) -> &'static str {
        match self.lang {
            Lang::En => "Get AI-powered fix plans and track security trends",
            Lang::Zh => "获取 AI 修复方案，追踪安全趋势",
        }
    }

    pub fn start_scan(&self) -> &'static str {
        match self.lang {
            Lang::En => "Start Scan",
            Lang::Zh => "开始扫描",
        }
    }

    // ── Scanning ──

    pub fn loading_rules(&self) -> &'static str {
        match self.lang {
            Lang::En => "Loading rules...",
            Lang::Zh => "加载规则中...",
        }
    }

    pub fn scanning(&self) -> &'static str {
        match self.lang {
            Lang::En => "Scanning...",
            Lang::Zh => "扫描中...",
        }
    }

    // ── Score labels ──

    pub fn score_label(&self, score: u8) -> &'static str {
        match self.lang {
            Lang::En => match score {
                90..=100 => "Excellent",
                75..=89 => "Good",
                60..=74 => "Fair",
                40..=59 => "Poor",
                _ => "Critical",
            },
            Lang::Zh => match score {
                90..=100 => "优秀",
                75..=89 => "良好",
                60..=74 => "一般",
                40..=59 => "较差",
                _ => "危险",
            },
        }
    }

    // ── Sidebar stats ──

    pub fn pass(&self) -> &'static str {
        match self.lang {
            Lang::En => "pass",
            Lang::Zh => "通过",
        }
    }

    pub fn fail(&self) -> &'static str {
        match self.lang {
            Lang::En => "fail",
            Lang::Zh => "失败",
        }
    }

    pub fn warn(&self) -> &'static str {
        match self.lang {
            Lang::En => "warn",
            Lang::Zh => "警告",
        }
    }

    pub fn categories(&self) -> &'static str {
        match self.lang {
            Lang::En => "Categories",
            Lang::Zh => "分类",
        }
    }

    pub fn all_findings(&self) -> &'static str {
        match self.lang {
            Lang::En => "All Findings",
            Lang::Zh => "所有发现",
        }
    }

    pub fn new_scan(&self) -> &'static str {
        match self.lang {
            Lang::En => "New Scan",
            Lang::Zh => "重新扫描",
        }
    }

    // ── Agent info ──

    pub fn agent_id(&self) -> &'static str {
        match self.lang {
            Lang::En => "AGENT ID",
            Lang::Zh => "智能体 ID",
        }
    }

    pub fn view_web_report(&self) -> &'static str {
        match self.lang {
            Lang::En => "View Web Report \u{2197}",
            Lang::Zh => "查看在线报告 \u{2197}",
        }
    }

    // ── Main panel ──

    pub fn no_issues_in_category(&self) -> &'static str {
        match self.lang {
            Lang::En => "No issues in this category",
            Lang::Zh => "该分类下暂无问题",
        }
    }

    pub fn passed(&self) -> &'static str {
        match self.lang {
            Lang::En => "Passed",
            Lang::Zh => "已通过",
        }
    }

    pub fn fix(&self) -> &'static str {
        match self.lang {
            Lang::En => "Fix:",
            Lang::Zh => "修复:",
        }
    }

    // ── AI Analysis ──

    pub fn ai_analysis(&self) -> &'static str {
        match self.lang {
            Lang::En => "AI Analysis",
            Lang::Zh => "AI 分析",
        }
    }

    pub fn executive_summary(&self) -> &'static str {
        match self.lang {
            Lang::En => "Executive Summary",
            Lang::Zh => "摘要",
        }
    }

    pub fn attack_chains(&self) -> &'static str {
        match self.lang {
            Lang::En => "Attack Chains",
            Lang::Zh => "攻击链",
        }
    }

    pub fn priority_fixes(&self) -> &'static str {
        match self.lang {
            Lang::En => "Priority Fixes",
            Lang::Zh => "优先修复",
        }
    }

    pub fn context_notes(&self) -> &'static str {
        match self.lang {
            Lang::En => "Context Notes",
            Lang::Zh => "备注",
        }
    }

    // ── Error ──

    pub fn scan_error(&self) -> &'static str {
        match self.lang {
            Lang::En => "Scan Error",
            Lang::Zh => "扫描错误",
        }
    }

    pub fn view_fix_plan(&self) -> &'static str {
        match self.lang {
            Lang::En => "View Fix Plan \u{2197}",
            Lang::Zh => "查看修复方案 \u{2197}",
        }
    }

    pub fn back(&self) -> &'static str {
        match self.lang {
            Lang::En => "Back",
            Lang::Zh => "返回",
        }
    }

    // ── Category names ──

    pub fn category_name(&self, cat: Category) -> &'static str {
        match self.lang {
            Lang::En => match cat {
                Category::Credential => "Credential Exposure",
                Category::FileSystem => "File System Security",
                Category::Network => "Network Exposure",
                Category::Process => "Process Security",
                Category::GatewayConfig => "Gateway Configuration",
                Category::Sandbox => "Sandbox & Isolation",
                Category::Plugin => "Plugin & Extension Security",
                Category::DataLeak => "Data Leak Detection",
                Category::Docker => "Container Security",
                Category::CostSafety => "Cost Safety",
                Category::DestructiveAction => "Destructive Action Protection",
                Category::Skill => "Skill",
            },
            Lang::Zh => match cat {
                Category::Credential => "凭证暴露",
                Category::FileSystem => "文件系统安全",
                Category::Network => "网络暴露",
                Category::Process => "进程安全",
                Category::GatewayConfig => "网关配置",
                Category::Sandbox => "沙箱与隔离",
                Category::Plugin => "插件与扩展安全",
                Category::DataLeak => "数据泄漏检测",
                Category::Docker => "容器安全",
                Category::CostSafety => "成本安全",
                Category::DestructiveAction => "破坏性操作防护",
                Category::Skill => "技能",
            },
        }
    }

    // ── Severity names ──

    pub fn severity_name(&self, sev: Severity) -> &'static str {
        match self.lang {
            Lang::En => match sev {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            },
            Lang::Zh => match sev {
                Severity::Critical => "严重",
                Severity::High => "高",
                Severity::Medium => "中",
                Severity::Low => "低",
                Severity::Info => "信息",
            },
        }
    }

}
