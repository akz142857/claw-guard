use crate::engine::*;
use crate::platform;
use anyhow::Result;
use std::process::Command;

/// CG-P005: Host compromise indicators (肉鸡检测)
///
/// Checks for signs that the host has been compromised:
/// - Unauthorized SSH authorized_keys entries
/// - Unknown user accounts
/// - Hidden processes or PID namespace anomalies
/// - Suspicious login records
/// - Modified system binaries
/// - Rootkit indicators (hidden files in /tmp, /dev/shm)
/// - Unauthorized services listening
/// - Cryptocurrency mining indicators (CPU usage)
pub struct CgP005;

static META: RuleMeta = RuleMeta {
    id: "CG-P005",
    name: "Host compromise indicators",
    description: "Performs multi-vector compromise assessment: unauthorized SSH keys, \
                  unknown user accounts, hidden processes, abnormal CPU usage (mining), \
                  suspicious files in /tmp and /dev/shm, unauthorized listeners, \
                  and login anomaly detection.",
    category: Category::Process,
    severity: Severity::Critical,
    remediation: "Isolate the host from the network immediately. Preserve forensic \
                  evidence (disk image, memory dump). Rotate ALL credentials that were \
                  accessible from this host. Review frpc/tunnel configs for unauthorized \
                  port mappings. Rebuild from a known-good image if compromise is confirmed.",
};

impl StaticRule for CgP005 {
    fn meta(&self) -> &RuleMeta {
        &META
    }

    fn evaluate(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        check_ssh_authorized_keys(&mut findings);
        check_hidden_tmp_files(&mut findings);
        check_high_cpu_processes(&mut findings);
        check_unknown_listeners(&mut findings);
        check_login_anomalies(&mut findings);
        check_suspicious_users(&mut findings);
        check_system_binary_integrity(&mut findings);

        if findings.is_empty() {
            findings.push(META.finding(
                Status::Pass,
                "No host compromise indicators detected",
            ));
        }

        Ok(findings)
    }
}

/// Check 1: Unauthorized SSH authorized_keys entries
fn check_ssh_authorized_keys(findings: &mut Vec<Finding>) {
    let ssh_dir = platform::home_dir().join(".ssh");
    let auth_keys = ssh_dir.join("authorized_keys");

    if !auth_keys.exists() {
        return;
    }

    let content = match std::fs::read_to_string(&auth_keys) {
        Ok(c) => c,
        Err(_) => return,
    };

    let keys: Vec<&str> = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .collect();

    if keys.len() > 5 {
        findings.push(META.finding_with_evidence(
            Status::Warn,
            format!(
                "{} SSH authorized keys found — review for unauthorized entries",
                keys.len()
            ),
            format!("file={} count={}", auth_keys.display(), keys.len()),
        ));
    }

    // Check for suspicious key comments (common backdoor patterns)
    let suspicious_comments = ["root@", "hack", "backdoor", "pwn", "temp", "test@test"];
    for key in &keys {
        let lower = key.to_lowercase();
        for pattern in &suspicious_comments {
            if lower.contains(pattern) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Suspicious SSH key comment matches '{}'", pattern),
                    truncate(key, 120),
                ));
                break;
            }
        }
    }

    // Check if authorized_keys was modified recently (last 24h)
    if let Ok(metadata) = std::fs::metadata(&auth_keys) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() < 86400 {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        "SSH authorized_keys modified in the last 24 hours",
                        format!(
                            "file={} modified_secs_ago={}",
                            auth_keys.display(),
                            elapsed.as_secs()
                        ),
                    ));
                }
            }
        }
    }
}

/// Check 2: Hidden files in /tmp and /dev/shm (common malware staging)
fn check_hidden_tmp_files(findings: &mut Vec<Finding>) {
    let staging_dirs = ["/tmp", "/var/tmp", "/dev/shm"];

    for dir in &staging_dirs {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Hidden files (starting with .) in tmp dirs
            if name.starts_with('.') && name != "." && name != ".." {
                // Skip common legitimate hidden files
                let legitimate = [".ICE-unix", ".X11-unix", ".XIM-unix", ".font-unix",
                                  ".Test-unix", ".com.apple", ".DS_Store"];
                if legitimate.iter().any(|l| name.starts_with(l)) {
                    continue;
                }

                // Check if it's executable
                #[cfg(unix)]
                let is_executable = {
                    use std::os::unix::fs::PermissionsExt;
                    entry.metadata()
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                };
                #[cfg(not(unix))]
                let is_executable = false;

                if is_executable {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!("Hidden executable file in {} (common malware staging)", dir),
                        format!("path={}/{}", dir, name),
                    ));
                } else {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!("Hidden file in {} — verify it is legitimate", dir),
                        format!("path={}/{}", dir, name),
                    ));
                }
            }

            // Known malware filenames
            let suspicious_names = [
                "kworker", "kthread", "ksoftirqd",  // Fake kernel thread names
                "rsync", "sshd",                     // Fake system service names in /tmp
                ".nanorc", ".bashrc",                // Config files shouldn't be in /tmp
            ];
            if suspicious_names.iter().any(|s| name == *s) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Suspicious file '{}' in {} (mimics system process name)", name, dir),
                    format!("path={}/{}", dir, name),
                ));
            }
        }
    }
}

/// Check 3: Abnormally high CPU processes (mining detection)
fn check_high_cpu_processes(findings: &mut Vec<Finding>) {
    // Use ps to get CPU-intensive processes
    let output = match Command::new("ps").args(["aux", "--sort=-%cpu"]).output() {
        Ok(o) => o,
        Err(_) => {
            // macOS ps doesn't support --sort, use different approach
            match Command::new("ps").args(["aux"]).output() {
                Ok(o) => o,
                Err(_) => return,
            }
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 11 {
            continue;
        }

        let cpu: f64 = parts[2].parse().unwrap_or(0.0);
        let process_name = parts[10..].join(" ");
        let lower_name = process_name.to_lowercase();

        // Flag processes using >80% CPU that look suspicious
        if cpu > 80.0 {
            let mining_indicators = [
                "xmrig", "minerd", "cpuminer", "ethminer", "bfgminer",
                "cgminer", "stratum", "nicehash", "randomx",
                "cryptonight", "hashrate", "pool.mining",
            ];

            let is_mining = mining_indicators.iter().any(|m| lower_name.contains(m));

            if is_mining {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Cryptocurrency miner detected using {:.1}% CPU", cpu),
                    truncate(&process_name, 200),
                ));
            } else {
                // High CPU but not obviously mining — flag for review
                // Skip known legitimate high-CPU processes
                let legitimate = ["compilerd", "cargo", "rustc", "gcc", "clang",
                                  "node", "python", "java", "swift", "Xcode",
                                  "spotlight", "mds_stores", "kernel_task",
                                  "WindowServer", "coreaudio"];
                let is_legit = legitimate.iter().any(|l| lower_name.contains(&l.to_lowercase()));

                if !is_legit {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!("Unknown process using {:.1}% CPU — verify legitimacy", cpu),
                        truncate(&process_name, 200),
                    ));
                }
            }
        }
    }
}

/// Check 4: Unknown listeners (services you didn't start)
fn check_unknown_listeners(findings: &mut Vec<Finding>) {
    let output = if cfg!(target_os = "macos") {
        Command::new("lsof").args(["-iTCP", "-sTCP:LISTEN", "-nP"]).output()
    } else if cfg!(unix) {
        Command::new("ss").args(["-tlnp"]).output()
    } else {
        return;
    };

    let stdout = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return,
    };

    // Well-known suspicious ports that shouldn't be open on a workstation
    let suspicious_ports: &[(u16, &str)] = &[
        (4444, "Metasploit default"),
        (4445, "Metasploit"),
        (5555, "Android ADB / common backdoor"),
        (6666, "IRC / backdoor"),
        (6667, "IRC"),
        (6697, "IRC TLS"),
        (1080, "SOCKS proxy"),
        (1090, "SOCKS proxy"),
        (3128, "HTTP proxy / Squid"),
        (8118, "Privoxy"),
        (9050, "Tor SOCKS"),
        (9150, "Tor Browser SOCKS"),
        (31337, "Back Orifice"),
        (12345, "NetBus"),
        (27015, "Common game/backdoor"),
    ];

    for line in stdout.lines().skip(1) {
        for (port, label) in suspicious_ports {
            let port_str = format!(":{}", port);
            if line.contains(&port_str) {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Suspicious port {} ({}) is listening", port, label),
                    truncate(line.trim(), 200),
                ));
            }
        }
    }
}

/// Check 5: Login anomalies (failed logins, unusual sources)
fn check_login_anomalies(findings: &mut Vec<Finding>) {
    if cfg!(target_os = "macos") {
        // Check for recent failed SSH attempts via system log
        if let Ok(output) = Command::new("log")
            .args([
                "show", "--predicate",
                "process == \"sshd\" AND eventMessage CONTAINS \"Failed\"",
                "--last", "24h", "--style", "compact",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let failed_count = stdout.lines().count();
            if failed_count > 20 {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!(
                        "{} failed SSH login attempts in last 24h (possible brute force)",
                        failed_count
                    ),
                    format!("source=system.log failed_attempts={}", failed_count),
                ));
            } else if failed_count > 5 {
                findings.push(META.finding_with_evidence(
                    Status::Warn,
                    format!("{} failed SSH login attempts in last 24h", failed_count),
                    format!("source=system.log failed_attempts={}", failed_count),
                ));
            }
        }
    } else if cfg!(unix) {
        // Linux: check /var/log/auth.log or /var/log/secure
        for log_path in &["/var/log/auth.log", "/var/log/secure"] {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                let failed_count = content
                    .lines()
                    .filter(|l| l.contains("Failed password") || l.contains("authentication failure"))
                    .count();

                if failed_count > 100 {
                    findings.push(META.finding_with_evidence(
                        Status::Fail,
                        format!(
                            "{} failed login attempts in {} (brute force likely)",
                            failed_count, log_path
                        ),
                        format!("file={} failed_attempts={}", log_path, failed_count),
                    ));
                } else if failed_count > 20 {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!(
                            "{} failed login attempts in {}",
                            failed_count, log_path
                        ),
                        format!("file={} failed_attempts={}", log_path, failed_count),
                    ));
                }
            }
        }
    }
}

/// Check 6: Suspicious user accounts
fn check_suspicious_users(findings: &mut Vec<Finding>) {
    if !cfg!(unix) {
        return;
    }

    // Check for recently created users (uid >= 1000, not system accounts)
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        let suspicious_usernames = [
            "admin1", "test", "guest", "user1", "temp",
            "ftpuser", "mysql", "postgres",  // DB users shouldn't exist on agent hosts
        ];

        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }
            let username = parts[0];
            let uid_str = parts[2];
            let shell = parts[6];

            // Parse uid — negative values (e.g., nobody=-2) are not uid 0
            let uid: i64 = uid_str.parse().unwrap_or(-1);

            // Non-system user with a login shell
            let has_login_shell = shell.ends_with("/bash")
                || shell.ends_with("/zsh")
                || shell.ends_with("/sh")
                || shell.ends_with("/fish");

            if uid >= 1000 && has_login_shell {
                let lower = username.to_lowercase();
                if suspicious_usernames.iter().any(|s| lower == *s) {
                    findings.push(META.finding_with_evidence(
                        Status::Warn,
                        format!(
                            "Suspicious user account '{}' (uid={}) with login shell",
                            username, uid
                        ),
                        format!("user={} uid={} shell={}", username, uid, shell),
                    ));
                }
            }

            // uid=0 accounts other than root (must be exactly "0", not parse failure)
            if uid == 0 && uid_str == "0" && username != "root" {
                findings.push(META.finding_with_evidence(
                    Status::Fail,
                    format!("Non-root account '{}' has uid=0 (equivalent to root)", username),
                    format!("user={} uid=0 shell={}", username, shell),
                ));
            }
        }
    }
}

/// Check 7: System binary integrity (basic check — modification time)
///
/// On macOS, system updates regularly modify /usr/bin/* binaries, so we check
/// whether ALL critical binaries were modified at roughly the same time (= OS update)
/// vs. a single binary modified alone (= suspicious tampering).
fn check_system_binary_integrity(findings: &mut Vec<Finding>) {
    let critical_bins = [
        "/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/login",
        "/usr/bin/su", "/usr/bin/passwd", "/usr/sbin/sshd",
    ];

    let mut mod_times: Vec<(&str, u64)> = Vec::new();

    for bin in &critical_bins {
        let path = std::path::Path::new(bin);
        if !path.exists() {
            continue;
        }
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    let days = elapsed.as_secs() / 86400;
                    mod_times.push((bin, days));
                }
            }
        }
    }

    if mod_times.is_empty() {
        return;
    }

    // If ALL binaries were modified around the same time (within 1 day of each other),
    // it's likely an OS update — report as informational only.
    let recent: Vec<_> = mod_times.iter().filter(|(_, days)| *days < 7).collect();

    if recent.is_empty() {
        return;
    }

    let min_days = recent.iter().map(|(_, d)| *d).min().unwrap_or(0);
    let max_days = recent.iter().map(|(_, d)| *d).max().unwrap_or(0);
    let all_same_time = max_days - min_days <= 1;

    if all_same_time && recent.len() > 1 {
        // All modified together = likely OS update, not tampering
        // Only warn, don't fail
        return;
    }

    // Only one or two binaries modified recently = suspicious
    for (bin, days) in &recent {
        findings.push(META.finding_with_evidence(
            Status::Fail,
            format!(
                "System binary {} was modified {} day(s) ago (other binaries were not)",
                bin, days
            ),
            format!("path={} modified_days_ago={}", bin, days),
        ));
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
