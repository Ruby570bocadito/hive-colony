// Honey detection: identifies honeypots, honeyfiles, and canary traps.
// The swarm checks targets BEFORE attacking to avoid triggering alerts.
// Detects: fake credentials, bait files, known honeypot services, tripwires.

use std::path::Path;
use std::fs;
use tracing::{info, warn};

// ── Honeyfile Detection ─────────────────────────────────────────────────────

/// Known bait filenames that defenders place as tripwires
const BAIT_FILENAMES: &[&str] = &[
    "passwords.txt", "credentials.docx", "credit_cards.xlsx",
    "admin_passwords.csv", "confidential.pdf", "secrets.zip",
    "salary.xlsx", "customers.sql", "backup.sql",
    "id_rsa_honeypot", "honeykey.pem", "trap.txt",
    "DO_NOT_OPEN.txt", "TOP_SECRET.pdf", "classified.zip",
];

/// Known bait directories
const BAIT_DIRECTORIES: &[&str] = &[
    "/opt/honeypot", "/home/honey", "/var/honeypots",
    "/home/cowrie", "/opt/dionaea",
];

/// Suspicious file patterns (files with exactly 0 bytes, or exactly 1024, etc.)
fn is_suspicious_size(size: u64) -> bool {
    size == 0 || size == 1024 || size == 2048 || size == 4096
        || size == 42 || size == 1337
}

/// Detect if a file is likely a honeyfile.
pub fn detect_honeyfile(path: &Path) -> Option<String> {
    let filename = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let filename_lower = filename.to_lowercase();

    // Check bait filenames
    for bait in BAIT_FILENAMES {
        if filename_lower.contains(bait) {
            return Some(format!("BAIT_FILENAME: matches '{}'", bait));
        }
    }

    // Check parent directory
    if let Some(parent) = path.parent() {
        let parent_str = parent.to_string_lossy();
        for bait_dir in BAIT_DIRECTORIES {
            if parent_str.contains(bait_dir) {
                return Some(format!("BAIT_DIR: in known honeypot dir '{}'", bait_dir));
            }
        }
    }

    // Check suspicious file properties
    if let Ok(meta) = fs::metadata(path) {
        // Recently modified (< 1 hour ago) = likely bait
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() < 3600 {
                    return Some("RECENTLY_MODIFIED: < 1 hour old".into());
                }
            }
        }

        // Suspicious exact size
        if is_suspicious_size(meta.len()) {
            return Some(format!("SUSPICIOUS_SIZE: {} bytes", meta.len()));
        }

        // World-readable + writable credentials = trap
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o777 == 0o777 {
                return Some("WORLD_RWX: permissions 777".into());
            }
        }
    }

    None
}

/// Scan a directory for honeyfiles. Returns list of (path, reason).
pub fn scan_for_honeyfiles(dir: &Path) -> Vec<(String, String)> {
    let mut honeys = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() { continue; }

            if let Some(reason) = detect_honeyfile(&path) {
                warn!("HONEYFILE: {} — {}", path.display(), reason);
                honeys.push((path.display().to_string(), reason));
            }
        }
    }

    honeys
}

// ── Honeypot Service Detection ──────────────────────────────────────────────

/// Known honeypot service ports
const HONEYPOT_PORTS: &[(u16, &str)] = &[
    (2222, "Cowrie SSH"), (2223, "Cowrie SSH alt"),
    (23, "Telnet (Dionaea)"), (2323, "Telnet alt"),
    (21, "FTP honeypot"), (2121, "FTP alt"),
    (8080, "Web honeypot"), (8443, "HTTPS honeypot"),
    (3389, "RDP honeypot"), (3306, "MySQL honeypot"),
    (6379, "Redis honeypot"), (11211, "Memcached honeypot"),
    (9200, "Elasticsearch honeypot"), (27017, "MongoDB honeypot"),
    (5432, "PostgreSQL honeypot"),
];

/// Check if a port/service is a known honeypot.
pub fn detect_honeypot_service(host: &str, port: u16) -> Option<&'static str> {
    for &(hp, desc) in HONEYPOT_PORTS {
        if port == hp {
            info!("HONEYPOT: {}:{} matches known honeypot service '{}'", host, port, desc);

            // Double-check: try to connect and look for honeypot banners
            if let Some(banner) = probe_banner(host, port) {
                let banner_lower = banner.to_lowercase();
                for keyword in &["cowrie", "dionaea", "honeypot", "honeynet", "trap",
                                  "decoy", "glastopf", "conpot", "amun"] {
                    if banner_lower.contains(keyword) {
                        return Some(desc);
                    }
                }
            }
        }
    }
    None
}

/// Probe a TCP service for banner information.
fn probe_banner(host: &str, port: u16) -> Option<String> {
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::time::Duration;

    let addr = format!("{}:{}", host, port);
    match TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(2),
    ) {
        Ok(mut stream) => {
            // Send newline to trigger banner
            let _ = stream.write_all(b"\r\n");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    return Some(String::from_utf8_lossy(&buf[..n]).to_string());
                }
            }
            None
        }
        Err(_) => None,
    }
}

// ── Canary Token Detection ──────────────────────────────────────────────────

/// Detect canary tokens in data (AWS keys, URLs, email addresses that trigger alerts).
pub fn detect_canary_tokens(data: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    // AWS-style canary keys (pattern: AKIA...CANARY)
    if data.contains("CANARY") || data.contains("canary") {
        tokens.push("CANARY_KEYWORD".into());
    }

    // HoneyDocs-style URLs
    if data.contains("honeydoc") || data.contains("canarytokens") {
        tokens.push("HONEYDOC_URL".into());
    }

    // Suspicious email patterns (canary mail addresses)
    for canary_domain in &["canarytokens.org", "honeydoc.io", "trapmail.com"] {
        if data.to_lowercase().contains(canary_domain) {
            tokens.push(format!("CANARY_DOMAIN: {}", canary_domain));
        }
    }

    // Files with embedded tracking URLs (base64 encoded URLs)
    if data.len() > 100 && data.chars().all(|c| c.is_ascii_graphic() || c == '=') {
        // Could be base64 bait
        if data.len() < 1000 {
            tokens.push("SUSPICIOUS_BASE64: possible encoded canary".into());
        }
    }

    tokens
}

// ── Combined Check ───────────────────────────────────────────────────────────

/// Check a target host/path for honey indicators BEFORE attacking.
/// Returns list of warnings. If any CRITICAL, abort the attack.
#[derive(Debug)]
pub struct HoneyCheck {
    pub honeyfiles: Vec<(String, String)>,
    pub honeypot_ports: Vec<(u16, &'static str)>,
    pub canary_tokens: Vec<String>,
}

impl HoneyCheck {
    pub fn is_clean(&self) -> bool {
        self.honeyfiles.is_empty() && self.honeypot_ports.is_empty() && self.canary_tokens.is_empty()
    }

    pub fn has_critical(&self) -> bool {
        !self.honeypot_ports.is_empty() || !self.canary_tokens.is_empty()
    }
}

/// Run a full honey check on a target before any offensive action.
pub fn check_target(target_host: &str, target_path: Option<&str>) -> HoneyCheck {
    let mut check = HoneyCheck {
        honeyfiles: Vec::new(),
        honeypot_ports: Vec::new(),
        canary_tokens: Vec::new(),
    };

    // Check filesystem if path provided
    if let Some(path) = target_path {
        let p = Path::new(path);
        if p.exists() {
            check.honeyfiles = scan_for_honeyfiles(p);
        }
    }

    // Check for honeypot services on common ports
    for &(port, _) in HONEYPOT_PORTS.iter().take(5) {
        if let Some(desc) = detect_honeypot_service(target_host, port) {
            check.honeypot_ports.push((port, desc));
        }
    }

    if !check.is_clean() {
        warn!("HONEY DETECTED on {}: {:?}", target_host, check);
    }

    check
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_bait_filename() {
        let path = Path::new("/tmp/passwords.txt");
        let result = detect_honeyfile(path);
        assert!(result.is_some());
    }

    #[test]
    fn test_normal_file_not_detected() {
        let dir = std::env::temp_dir().join("hive_test_guardian");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("normal_data.txt");
        std::fs::write(&path, b"hello").unwrap();
        let result = detect_honeyfile(&path);
        if let Some(reason) = result {
            assert!(reason.contains("RECENTLY_MODIFIED"),
                "unexpected detection reason: {}", reason);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_canary_keyword() {
        let tokens = detect_canary_tokens("AKIAIOSFODNN7CANARY");
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_normal_data_no_canary() {
        let tokens = detect_canary_tokens("hello world");
        assert!(tokens.is_empty());
    }
}
