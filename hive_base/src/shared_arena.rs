// Shared memory arena for inter-agent communication.
// Replaces the TCP bus (127.0.0.1:4242) with an anonymous file-backed
// memory-mapped ring buffer. No sockets, no ports, no listen() footprint.
//
// Cross-process: uses shm_open with random name on Linux.
// All agents mmap the same region and communicate via lock-free atomics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::mem;
use std::ptr;

// ── constants ────────────────────────────────────────────────────────────────

pub const MAX_AGENTS: usize = 16;
pub const MAX_MESSAGES: usize = 2048;
pub const MAX_MSG_SIZE: usize = 8192;
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 30;

const ARENA_MAGIC: [u8; 8] = [0x53, 0x57, 0x52, 0x4D, 0x01, 0x00, 0x00, 0x00]; // "SWRM\1\0\0\0"

// ── arena header (first cache line) ──────────────────────────────────────────

#[repr(C, align(64))]
pub struct ArenaHeader {
    pub magic: [u8; 8],
    pub arena_size: u64,
    pub write_cursor: AtomicU64,
    pub agent_registry_seq: AtomicU64,
    pub _pad: [u8; 40],
}

// ── agent registry slot ──────────────────────────────────────────────────────

#[repr(C)]
pub struct AgentSlot {
    pub agent_id: [u8; 16],
    pub last_heartbeat: AtomicU64,
    pub verifying_key: [u8; 32],
    pub role: u8,
    pub flags: u8,
    pub _pad: [u8; 6],
}

// ── message slot ─────────────────────────────────────────────────────────────

#[repr(C, align(64))]
pub struct MessageSlot {
    pub seq: AtomicU64,
    pub timestamp: u64,
    pub agent_id: [u8; 16],
    pub verifying_key: [u8; 32],
    pub signature: [u8; 64],
    pub role: u8,
    pub payload_len: u32,
    pub _pad: [u8; 3],
    pub payload: [u8; MAX_MSG_SIZE],
}

// ── sizes ────────────────────────────────────────────────────────────────────

const HEADER_SIZE: usize = mem::size_of::<ArenaHeader>();
const AGENT_SLOT_SIZE: usize = mem::size_of::<AgentSlot>();
const MESSAGE_SLOT_SIZE: usize = mem::size_of::<MessageSlot>();

pub const fn arena_layout_size() -> usize {
    HEADER_SIZE + (MAX_AGENTS * AGENT_SLOT_SIZE) + (MAX_MESSAGES * MESSAGE_SLOT_SIZE)
}

// ── operations ───────────────────────────────────────────────────────────────

pub fn verify_arena(ptr: *const u8) -> bool {
    unsafe {
        let header: *const ArenaHeader = ptr as *const ArenaHeader;
        (*header).magic == ARENA_MAGIC
    }
}

pub fn init_arena(ptr: *mut u8) {
    unsafe {
        let header = ptr as *mut ArenaHeader;
        ptr::write_bytes(ptr, 0, arena_layout_size());
        (*header).magic = ARENA_MAGIC;
        (*header).arena_size = arena_layout_size() as u64;
        (*header).write_cursor = AtomicU64::new(0);
        (*header).agent_registry_seq = AtomicU64::new(0);
    }
}

pub fn write_cursor_ref(ptr: *const u8) -> &'static AtomicU64 {
    unsafe {
        let header = ptr as *const ArenaHeader;
        &(*header).write_cursor
    }
}

pub fn claim_slot(ptr: *mut u8) -> (u64, usize) {
    let cursor_ref = write_cursor_ref(ptr);
    let seq = cursor_ref.fetch_add(1, Ordering::AcqRel);
    let slot_idx = (seq as usize) % MAX_MESSAGES;
    (seq, slot_idx)
}

pub fn message_slot_mut(ptr: *mut u8, slot_idx: usize) -> *mut MessageSlot {
    unsafe {
        let offset = HEADER_SIZE + (MAX_AGENTS * AGENT_SLOT_SIZE) + (slot_idx * MESSAGE_SLOT_SIZE);
        (ptr.add(offset)) as *mut MessageSlot
    }
}

pub fn message_slot_ptr(ptr: *const u8, slot_idx: usize) -> *const MessageSlot {
    unsafe {
        let offset = HEADER_SIZE + (MAX_AGENTS * AGENT_SLOT_SIZE) + (slot_idx * MESSAGE_SLOT_SIZE);
        (ptr.add(offset)) as *const MessageSlot
    }
}

pub fn read_slot_seq(slot: *const MessageSlot) -> u64 {
    unsafe { (*slot).seq.load(Ordering::Acquire) }
}

pub fn write_message_slot(
    slot: *mut MessageSlot,
    seq: u64,
    timestamp: u64,
    agent_id: [u8; 16],
    verifying_key: [u8; 32],
    signature: [u8; 64],
    role: u8,
    data: &[u8],
) {
    unsafe {
        let len = data.len().min(MAX_MSG_SIZE);
        (*slot).timestamp = timestamp;
        (*slot).agent_id = agent_id;
        (*slot).verifying_key = verifying_key;
        (*slot).signature = signature;
        (*slot).role = role;
        (*slot).payload_len = len as u32;
        ptr::copy_nonoverlapping(data.as_ptr(), (*slot).payload.as_mut_ptr(), len);
        (*slot).seq.store(seq, Ordering::Release);
    }
}

// ── agent registry ───────────────────────────────────────────────────────────

pub fn agent_slot_mut(ptr: *mut u8, idx: usize) -> *mut AgentSlot {
    unsafe {
        let offset = HEADER_SIZE + (idx * AGENT_SLOT_SIZE);
        (ptr.add(offset)) as *mut AgentSlot
    }
}

pub fn agent_slot_ptr(ptr: *const u8, idx: usize) -> *const AgentSlot {
    unsafe {
        let offset = HEADER_SIZE + (idx * AGENT_SLOT_SIZE);
        (ptr.add(offset)) as *const AgentSlot
    }
}

pub fn find_or_claim_agent_slot(ptr: *mut u8, agent_id: [u8; 16]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_AGENTS {
            let slot = agent_slot_ptr(ptr, i);
            if ((*slot).flags & 1) != 0 && (*slot).agent_id == agent_id {
                return Some(i);
            }
        }
        for i in 0..MAX_AGENTS {
            let slot = agent_slot_mut(ptr, i);
            if (*slot).flags & 1 == 0 {
                (*slot).agent_id = agent_id;
                (*slot).last_heartbeat = AtomicU64::new(0);
                (*slot).role = 0;
                (*slot).flags = 1;
                return Some(i);
            }
        }
        None
    }
}

pub fn update_heartbeat(ptr: *mut u8, idx: usize, ts: u64) {
    unsafe {
        let slot = agent_slot_mut(ptr, idx);
        (*slot).last_heartbeat.store(ts, Ordering::Release);
    }
}

pub fn set_agent_role(ptr: *mut u8, idx: usize, role: u8) {
    unsafe {
        let slot = agent_slot_mut(ptr, idx);
        (*slot).role = role;
    }
}

pub fn set_verifying_key(ptr: *mut u8, idx: usize, key: [u8; 32]) {
    unsafe {
        let slot = agent_slot_mut(ptr, idx);
        (*slot).verifying_key = key;
    }
}

pub fn enumerate_agents<F>(ptr: *const u8, mut f: F)
where
    F: FnMut([u8; 16], u8, u64, [u8; 32]),
{
    for i in 0..MAX_AGENTS {
        unsafe {
            let slot = agent_slot_ptr(ptr, i);
            let flags = (*slot).flags;
            if (flags & 1) != 0 && (flags & 2) == 0 {
                let hb = (*slot).last_heartbeat.load(Ordering::Acquire);
                f((*slot).agent_id, (*slot).role, hb, (*slot).verifying_key);
            }
        }
    }
}

pub fn mark_agent_dead(ptr: *mut u8, idx: usize) {
    unsafe {
        let slot = agent_slot_mut(ptr, idx);
        (*slot).flags |= 2;
    }
}

pub fn last_heartbeat_val(ptr: *const u8, idx: usize) -> u64 {
    unsafe {
        let slot = agent_slot_ptr(ptr, idx);
        (*slot).last_heartbeat.load(Ordering::Acquire)
    }
}

pub fn agent_role_val(ptr: *const u8, idx: usize) -> u8 {
    unsafe {
        let slot = agent_slot_ptr(ptr, idx);
        (*slot).role
    }
}

pub fn agent_id_val(ptr: *const u8, idx: usize) -> [u8; 16] {
    unsafe {
        let slot = agent_slot_ptr(ptr, idx);
        (*slot).agent_id
    }
}

pub fn agent_flags_val(ptr: *const u8, idx: usize) -> u8 {
    unsafe {
        let slot = agent_slot_ptr(ptr, idx);
        (*slot).flags
    }
}

pub fn generate_arena_name() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let suffix: String = (0..16)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect();
    format!("/swarm_{}", suffix)
}

pub fn arena_size() -> usize {
    let sz = arena_layout_size();
    (sz + 4095) & !4095
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_arena_constants() {
        assert!(MAX_AGENTS >= 8);
        assert!(MAX_MESSAGES >= 512);
        assert!(MAX_MSG_SIZE >= 4096);
        assert!(HEARTBEAT_TIMEOUT_SECS >= 10);
    }

    #[test]
    fn test_arena_magic() {
        assert_eq!(&ARENA_MAGIC, b"SWRM\x01\x00\x00\x00");
    }

    #[test]
    fn test_header_size_alignment() {
        assert_eq!(mem::size_of::<ArenaHeader>() % 64, 0, "Header must be cache-line aligned");
    }

    #[test]
    fn test_agent_slot_size() {
        let sz = mem::size_of::<AgentSlot>();
        assert!(sz >= 64, "Agent slot too small: {}", sz);
    }

    #[test]
    fn test_message_slot_size() {
        let sz = mem::size_of::<MessageSlot>();
        assert!(sz >= MAX_MSG_SIZE, "Message slot too small for max message");
    }
}
