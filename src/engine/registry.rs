use super::Rule;
use crate::rules;

/// Central registry: returns all detection rules.
/// Each rule is self-contained with ID, metadata, and evaluation logic.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // ── Credential Exposure (CG-C*) ─────────────────────────────────
        Box::new(rules::credential::cg_c001::CgC001),
        Box::new(rules::credential::cg_c002::CgC002),
        Box::new(rules::credential::cg_c003::CgC003),
        // ── File System Security (CG-F*) ────────────────────────────────
        Box::new(rules::filesystem::cg_f001::CgF001),
        Box::new(rules::filesystem::cg_f002::CgF002),
        Box::new(rules::filesystem::cg_f003::CgF003),
        // ── Network Exposure (CG-N*) ────────────────────────────────────
        Box::new(rules::network::cg_n001::CgN001),
        Box::new(rules::network::cg_n002::CgN002),
        Box::new(rules::network::cg_n003::CgN003),
        // ── Process Security (CG-P*) ────────────────────────────────────
        Box::new(rules::process::cg_p001::CgP001),
        Box::new(rules::process::cg_p002::CgP002),
        // ── Gateway Configuration (CG-G*) ───────────────────────────────
        Box::new(rules::gateway::cg_g001::CgG001),
        Box::new(rules::gateway::cg_g002::CgG002),
        Box::new(rules::gateway::cg_g003::CgG003),
        Box::new(rules::gateway::cg_g004::CgG004),
        // ── Sandbox & Isolation (CG-S*) ─────────────────────────────────
        Box::new(rules::sandbox::cg_s001::CgS001),
        Box::new(rules::sandbox::cg_s002::CgS002),
        // ── Plugin & Extension Security (CG-K*) ─────────────────────────
        Box::new(rules::plugin::cg_k001::CgK001),
        Box::new(rules::plugin::cg_k002::CgK002),
        // ── Data Leak Detection (CG-D*) ─────────────────────────────────
        Box::new(rules::dataleak::cg_d001::CgD001),
        Box::new(rules::dataleak::cg_d002::CgD002),
        Box::new(rules::dataleak::cg_d003::CgD003),
        // ── Container Security (CG-T*) ──────────────────────────────────
        Box::new(rules::docker::cg_t001::CgT001),
    ]
}
