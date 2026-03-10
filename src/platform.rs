use std::path::PathBuf;

/// Returns the user's home directory across all platforms
pub fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                PathBuf::from("C:\\Users\\Default")
            } else {
                PathBuf::from("/")
            }
        })
}

/// Credential directories to check, platform-aware
pub fn credential_paths() -> Vec<(&'static str, PathBuf)> {
    let home = home_dir();

    let mut paths = vec![
        ("ssh_keys", home.join(".ssh")),
        ("aws_credentials", home.join(".aws")),
        ("azure_credentials", home.join(".azure")),
        ("kube_config", home.join(".kube")),
        ("docker_config", home.join(".docker")),
        ("npm_token", home.join(".npmrc")),
        ("pypi_token", home.join(".pypirc")),
    ];

    if cfg!(windows) {
        // Windows-specific credential locations
        let appdata = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("AppData/Roaming"));
        let localappdata = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("AppData/Local"));

        paths.extend(vec![
            ("gcloud_credentials", appdata.join("gcloud")),
            ("gh_credentials", appdata.join("GitHub CLI")),
            ("azure_cli", home.join(".azure")),
            ("docker_desktop", appdata.join("Docker")),
            ("aws_credentials_win", home.join(".aws")),
            ("vscode_credentials", appdata.join("Code/User/globalStorage")),
            ("windows_credential_manager", localappdata.join("Microsoft/Credentials")),
        ]);
    } else {
        // Unix credential locations
        paths.extend(vec![
            ("gcloud_credentials", home.join(".config/gcloud")),
            ("gh_credentials", home.join(".config/gh")),
        ]);
    }

    paths
}

/// Sensitive system files to check, platform-aware
pub fn sensitive_system_paths() -> Vec<(&'static str, PathBuf)> {
    if cfg!(windows) {
        vec![
            ("sam_file", PathBuf::from(r"C:\Windows\System32\config\SAM")),
            ("system_file", PathBuf::from(r"C:\Windows\System32\config\SYSTEM")),
            ("security_file", PathBuf::from(r"C:\Windows\System32\config\SECURITY")),
            ("hosts_file", PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")),
            ("win_ssh_keys", PathBuf::from(r"C:\ProgramData\ssh")),
        ]
    } else {
        vec![
            ("shadow_file", PathBuf::from("/etc/shadow")),
            ("passwd_file", PathBuf::from("/etc/passwd")),
            ("sudoers_file", PathBuf::from("/etc/sudoers")),
            ("ssl_private_keys", PathBuf::from("/etc/ssl/private")),
            ("machine_id", PathBuf::from("/etc/machine-id")),
        ]
    }
}


/// SSH host key directory
pub fn ssh_host_key_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\ssh")
    } else {
        PathBuf::from("/etc/ssh")
    }
}

/// Shell history files, platform-aware
pub fn shell_history_files() -> Vec<PathBuf> {
    let home = home_dir();

    if cfg!(windows) {
        vec![
            home.join("AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
            home.join(".bash_history"),
        ]
    } else {
        vec![
            home.join(".bash_history"),
            home.join(".zsh_history"),
            home.join(".local/share/fish/fish_history"),
        ]
    }
}

/// OpenClaw log directories, platform-aware
pub fn openclaw_log_dirs() -> Vec<PathBuf> {
    let home = home_dir();

    let mut dirs = vec![
        home.join(".openclaw/logs"),
        home.join(".config/openclaw/logs"),
    ];

    if cfg!(windows) {
        let appdata = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("AppData/Roaming"));
        let localappdata = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("AppData/Local"));
        let temp = std::env::var("TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\Temp"));

        dirs.extend(vec![
            appdata.join("OpenClaw/logs"),
            localappdata.join("OpenClaw/logs"),
            temp.join("openclaw"),
        ]);
    } else {
        dirs.extend(vec![
            PathBuf::from("/var/log/openclaw"),
            PathBuf::from("/tmp/openclaw"),
        ]);
    }

    dirs
}
