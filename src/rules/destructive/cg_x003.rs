use crate::engine::*;
use anyhow::Result;
use std::path::Path;
use std::process::Command;

/// CG-X003: No backup / rollback mechanism
pub struct CgX003;

static META: RuleMeta = RuleMeta {
    id: "CG-X003",
    name: "No backup or rollback mechanism",
    description: "Checks if the working environment has git auto-commit, filesystem \
                  snapshots, or other rollback mechanisms. Without these, destructive \
                  agent actions are irreversible.",
    category: Category::DestructiveAction,
    severity: Severity::High,
    remediation: "Enable git in the project workspace. Use git auto-commit hooks or \
                  periodic snapshots. Consider btrfs/ZFS snapshots for system-level \
                  protection. Set up pre-exec hooks that auto-commit before dangerous ops.",
};

impl StaticRule for CgX003 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut has_any_backup = false;

        // Check 1: Is current working directory a git repo?
        let cwd = std::env::current_dir().unwrap_or_default();
        let git_dir = cwd.join(".git");
        if git_dir.exists() {
            // Check if there are any commits (not just git init)
            let has_commits = Command::new("git")
                .args(["log", "--oneline", "-1"])
                .current_dir(&cwd)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if has_commits {
                has_any_backup = true;
            } else {
                findings.push(META.finding_with_evidence(
                    Status::Warn,
                    "Git repository exists but has no commits — cannot roll back",
                    format!("git dir: {}", git_dir.display()),
                ));
            }
        } else {
            findings.push(META.finding(
                Status::Fail,
                "Working directory is not a git repository — no file change history",
            ));
        }

        // Check 2: Are there uncommitted changes? (dirty state = no safety net)
        if git_dir.exists() {
            let dirty = Command::new("git")
                .args(["status", "--porcelain"])
                .current_dir(&cwd)
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(false);

            if dirty {
                findings.push(META.finding_with_evidence(
                    Status::Warn,
                    "Working directory has uncommitted changes that cannot be rolled back via git",
                    "Run 'git status' to see uncommitted files",
                ));
            }
        }

        // Check 3: Look for filesystem snapshot tools (btrfs, ZFS, Time Machine)
        let snapshot_indicators: &[&str] = &[
            "/usr/sbin/btrfs",
            "/usr/sbin/zfs",
            "/usr/bin/snapper",
        ];

        for path in snapshot_indicators {
            if Path::new(path).exists() {
                has_any_backup = true;
            }
        }

        // macOS Time Machine check
        if cfg!(target_os = "macos") {
            let tm_enabled = Command::new("tmutil")
                .arg("status")
                .output()
                .map(|o| {
                    let s = String::from_utf8_lossy(&o.stdout);
                    s.contains("Running = 1") || s.contains("Enabled = 1")
                })
                .unwrap_or(false);
            if tm_enabled {
                has_any_backup = true;
            }
        }

        if has_any_backup && findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "Backup/rollback mechanism detected (git or filesystem snapshots)",
            ));
        } else if !has_any_backup && findings.is_empty() {
            findings.push(META.finding(
                Status::Fail,
                "No backup or rollback mechanism found. Destructive agent actions \
                 (file deletion, overwrites) will be irreversible.",
            ));
        }

        Ok(findings)
    }
}
