// Chaos: fault injection engine for the Hive Colony.
// Injects controlled failures at three levels (FailStop, Byzantine, Coordinated)
// to verify system resilience. Integrates with HTL for observability and replay.
//
// Usage:
//   let engine = ChaosEngine::new(arena_ptr, Some(&collector));
//   engine.inject(ChaosRecipe::fail_stop(agent_id));
//   engine.inject(ChaosRecipe::byzantine_corrupt_msg(slot_idx));

use crate::shared_arena as arena;
use crate::telemetry::{EventType, TelemetryCollector};
use rand::Rng;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

// ── Fault Levels ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultLevel {
    FailStop,
    Byzantine,
    Coordinated,
}

// ── Fault Types ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum Fault {
    // Fail-stop
    KillAgent([u8; 16]),
    SimulateTimeout([u8; 16]),
    DropMessage(usize),
    CrashProcess,

    // Byzantine-lite
    CorruptMessage(usize),
    CorruptSignature(usize),
    CorruptAgentId(usize),
    ReorderMessages,
    DuplicateMessage(usize),
    DelayDelivery(usize, u64),

    // Coordinated
    DegradeMultiple(Vec<[u8; 16]>),
    SlowArena,
    ReduceQuorum(u32),
    CorruptArenaHeader,
    FloodArena(usize),
}

impl Fault {
    pub fn level(&self) -> FaultLevel {
        match self {
            Fault::KillAgent(_)
            | Fault::SimulateTimeout(_)
            | Fault::DropMessage(_)
            | Fault::CrashProcess => FaultLevel::FailStop,

            Fault::CorruptMessage(_)
            | Fault::CorruptSignature(_)
            | Fault::CorruptAgentId(_)
            | Fault::ReorderMessages
            | Fault::DuplicateMessage(_)
            | Fault::DelayDelivery(..) => FaultLevel::Byzantine,

            Fault::DegradeMultiple(_)
            | Fault::SlowArena
            | Fault::ReduceQuorum(_)
            | Fault::CorruptArenaHeader
            | Fault::FloodArena(_) => FaultLevel::Coordinated,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Fault::KillAgent(_) => "kill_agent",
            Fault::SimulateTimeout(_) => "simulate_timeout",
            Fault::DropMessage(_) => "drop_message",
            Fault::CrashProcess => "crash_process",
            Fault::CorruptMessage(_) => "corrupt_message",
            Fault::CorruptSignature(_) => "corrupt_signature",
            Fault::CorruptAgentId(_) => "corrupt_agent_id",
            Fault::ReorderMessages => "reorder_messages",
            Fault::DuplicateMessage(_) => "duplicate_message",
            Fault::DelayDelivery(..) => "delay_delivery",
            Fault::DegradeMultiple(_) => "degrade_multiple",
            Fault::SlowArena => "slow_arena",
            Fault::ReduceQuorum(_) => "reduce_quorum",
            Fault::CorruptArenaHeader => "corrupt_arena_header",
            Fault::FloodArena(_) => "flood_arena",
        }
    }
}

// ── ChaosRecipe ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ChaosRecipe {
    pub fault: Fault,
    pub description: String,
    pub payload: Option<Vec<u8>>,
}

impl ChaosRecipe {
    pub fn new(fault: Fault, description: impl Into<String>) -> Self {
        Self {
            fault,
            description: description.into(),
            payload: None,
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    // ── Convenience constructors ──

    pub fn kill_agent(agent_id: [u8; 16]) -> Self {
        Self::new(
            Fault::KillAgent(agent_id),
            format!("Fail-stop: kill agent {:02x}..", agent_id[0]),
        )
    }

    pub fn simulate_timeout(agent_id: [u8; 16]) -> Self {
        Self::new(
            Fault::SimulateTimeout(agent_id),
            format!("Fail-stop: timeout agent {:02x}..", agent_id[0]),
        )
    }

    pub fn corrupt_message(slot_idx: usize) -> Self {
        Self::new(
            Fault::CorruptMessage(slot_idx),
            format!("Byzantine: corrupt message at slot {}", slot_idx),
        )
    }

    pub fn corrupt_signature(slot_idx: usize) -> Self {
        Self::new(
            Fault::CorruptSignature(slot_idx),
            format!("Byzantine: corrupt signature at slot {}", slot_idx),
        )
    }

    pub fn degrade_agents(agents: Vec<[u8; 16]>) -> Self {
        Self::new(
            Fault::DegradeMultiple(agents.clone()),
            format!("Coordinated: degrade {} agents", agents.len()),
        )
    }

    pub fn reduce_quorum(new_threshold: u32) -> Self {
        Self::new(
            Fault::ReduceQuorum(new_threshold),
            format!("Coordinated: reduce quorum to {}", new_threshold),
        )
    }

    pub fn flood_arena(count: usize) -> Self {
        Self::new(
            Fault::FloodArena(count),
            format!("Coordinated: flood arena with {} messages", count),
        )
    }

    pub fn corrupt_header() -> Self {
        Self::new(Fault::CorruptArenaHeader, "Coordinated: corrupt arena header")
    }

    pub fn reorder() -> Self {
        Self::new(Fault::ReorderMessages, "Byzantine: reorder messages")
    }
}

// ── Injection Result ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct InjectionResult {
    pub fault: Fault,
    pub success: bool,
    pub detail: String,
    pub agent_slot: Option<usize>,
    pub message_slot: Option<usize>,
}

// ── ChaosEngine ───────────────────────────────────────────────────────────

pub struct ChaosEngine {
    arena_ptr: *mut u8,
    collector: Option<Box<TelemetryCollector>>,
    active_faults: Vec<Fault>,
    injected_count: u64,
    rng: rand::rngs::ThreadRng,
    /// Track which agent slots have been killed (to avoid double-kill)
    killed_slots: HashSet<usize>,
}

unsafe impl Send for ChaosEngine {}
unsafe impl Sync for ChaosEngine {}

impl ChaosEngine {
    pub fn new(arena_ptr: *mut u8) -> Self {
        Self {
            arena_ptr,
            collector: None,
            active_faults: Vec::new(),
            injected_count: 0,
            rng: rand::thread_rng(),
            killed_slots: HashSet::new(),
        }
    }

    pub fn with_collector(mut self, collector: TelemetryCollector) -> Self {
        self.collector = Some(Box::new(collector));
        self
    }

    pub fn attach_collector(&mut self, collector: TelemetryCollector) {
        self.collector = Some(Box::new(collector));
    }

    /// Inject a fault. Returns an InjectionResult describing what happened.
    pub fn inject(&mut self, recipe: &ChaosRecipe) -> InjectionResult {
        self.injected_count += 1;
        info!("Chaos: injecting fault #{}: {}", self.injected_count, recipe.description);
        let result = self.execute_injection(recipe);

        // Emit HTL SecurityTrigger
        if let Some(ref collector) = self.collector {
            let payload = serde_json::json!({
                "fault": recipe.fault.label(),
                "level": format!("{:?}", recipe.fault.level()),
                "description": recipe.description,
                "success": result.success,
            });
            collector.emit(
                EventType::SecurityTrigger,
                vec![],
                Some(serde_json::to_vec(&payload).unwrap_or_default()),
            );
        }

        if !result.success {
            warn!("Chaos: injection FAILED: {}", result.detail);
        }

        result
    }

    /// Inject multiple faults sequentially
    pub fn inject_all(&mut self, recipes: &[ChaosRecipe]) -> Vec<InjectionResult> {
        recipes.iter().map(|r| self.inject(r)).collect()
    }

    fn execute_injection(&mut self, recipe: &ChaosRecipe) -> InjectionResult {
        match &recipe.fault {
            // ── Fail-stop ──
            Fault::KillAgent(agent_id) => self.do_kill_agent(agent_id),
            Fault::SimulateTimeout(agent_id) => self.do_simulate_timeout(agent_id),
            Fault::DropMessage(slot_idx) => self.do_drop_message(*slot_idx),
            Fault::CrashProcess => self.do_crash_process(),

            // ── Byzantine-lite ──
            Fault::CorruptMessage(slot_idx) => self.do_corrupt_message(*slot_idx),
            Fault::CorruptSignature(slot_idx) => self.do_corrupt_signature(*slot_idx),
            Fault::CorruptAgentId(slot_idx) => self.do_corrupt_agent_id(*slot_idx),
            Fault::ReorderMessages => self.do_reorder_messages(),
            Fault::DuplicateMessage(slot_idx) => self.do_duplicate_message(*slot_idx),
            Fault::DelayDelivery(slot_idx, delay) => self.do_delay_delivery(*slot_idx, *delay),

            // ── Coordinated ──
            Fault::DegradeMultiple(agents) => self.do_degrade_multiple(agents),
            Fault::SlowArena => self.do_slow_arena(),
            Fault::ReduceQuorum(threshold) => self.do_reduce_quorum(*threshold),
            Fault::CorruptArenaHeader => self.do_corrupt_arena_header(),
            Fault::FloodArena(count) => self.do_flood_arena(*count),
        }
    }

    // ── Fail-stop injections ──

    fn do_kill_agent(&mut self, agent_id: &[u8; 16]) -> InjectionResult {
        let ptr = self.arena_ptr;
        let mut slot_idx = None;
        for i in 0..arena::MAX_AGENTS {
            let slot_agent = arena::agent_id_val(ptr, i);
            if slot_agent == *agent_id && (arena::agent_flags_val(ptr, i) & 1) != 0 {
                arena::mark_agent_dead(ptr, i);
                // Also zero the heartbeat to ensure it's detected
                let slot = arena::agent_slot_mut(ptr, i);
                unsafe { (*slot).last_heartbeat.store(0, Ordering::Release); }
                slot_idx = Some(i);
                self.killed_slots.insert(i);
                break;
            }
        }
        InjectionResult {
            fault: Fault::KillAgent(*agent_id),
            success: slot_idx.is_some(),
            detail: match slot_idx {
                Some(i) => format!("Agent slot {} marked DEAD", i),
                None => "Agent not found in arena".into(),
            },
            agent_slot: slot_idx,
            message_slot: None,
        }
    }

    fn do_simulate_timeout(&mut self, agent_id: &[u8; 16]) -> InjectionResult {
        let ptr = self.arena_ptr;
        let mut slot_idx = None;
        for i in 0..arena::MAX_AGENTS {
            let slot_agent = arena::agent_id_val(ptr, i);
            if slot_agent == *agent_id && (arena::agent_flags_val(ptr, i) & 1) != 0 {
                // Set heartbeat to far in the past to simulate timeout
                let slot = arena::agent_slot_mut(ptr, i);
                unsafe { (*slot).last_heartbeat.store(1, Ordering::Release); }
                slot_idx = Some(i);
                break;
            }
        }
        InjectionResult {
            fault: Fault::SimulateTimeout(*agent_id),
            success: slot_idx.is_some(),
            detail: match slot_idx {
                Some(i) => format!("Agent slot {} heartbeat set to ancient timestamp", i),
                None => "Agent not found in arena".into(),
            },
            agent_slot: slot_idx,
            message_slot: None,
        }
    }

    fn do_drop_message(&mut self, slot_idx: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                // Zero the seq to make it appear unwritten
                (*slot).seq.store(0, Ordering::Release);
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::DropMessage(slot_idx),
            success,
            detail: if success {
                format!("Message slot {} dropped (seq zeroed)", slot_idx)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    fn do_crash_process(&mut self) -> InjectionResult {
        // Simulated: we can't actually crash, but we can emit the event
        InjectionResult {
            fault: Fault::CrashProcess,
            success: true,
            detail: "Crash process simulated (event recorded)".into(),
            agent_slot: None,
            message_slot: None,
        }
    }

    // ── Byzantine-lite injections ──

    fn do_corrupt_message(&mut self, slot_idx: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                // Flip random bits in payload
                let len = (*slot).payload_len as usize;
                if len > 0 {
                    let corrupt_byte = self.rng.gen_range(0..len);
                    let flip_bit = 1u8 << self.rng.gen_range(0..8);
                    (*slot).payload[corrupt_byte] ^= flip_bit;
                }
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::CorruptMessage(slot_idx),
            success,
            detail: if success {
                format!("Message slot {} payload corrupted", slot_idx)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    fn do_corrupt_signature(&mut self, slot_idx: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                // Flip one byte in the signature
                let corrupt_byte = self.rng.gen_range(0..64);
                let flip_bit = 1u8 << self.rng.gen_range(0..8);
                (*slot).signature[corrupt_byte] ^= flip_bit;
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::CorruptSignature(slot_idx),
            success,
            detail: if success {
                format!("Signature corrupted at slot {} byte position", slot_idx)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    fn do_corrupt_agent_id(&mut self, slot_idx: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                let corrupt_byte = self.rng.gen_range(0..16);
                (*slot).agent_id[corrupt_byte] ^= 0xff;
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::CorruptAgentId(slot_idx),
            success,
            detail: if success {
                format!("Agent ID corrupted at slot {}", slot_idx)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    fn do_reorder_messages(&mut self) -> InjectionResult {
        let ptr = self.arena_ptr;
        let cursor = arena::write_cursor_ref(ptr).load(Ordering::Acquire);
        if cursor > 1 {
            // Swap the seq numbers of last two written slots
            let idx_a = ((cursor - 1) as usize) % arena::MAX_MESSAGES;
            let idx_b = ((cursor - 2) as usize) % arena::MAX_MESSAGES;
            let slot_a = arena::message_slot_mut(ptr, idx_a);
            let slot_b = arena::message_slot_mut(ptr, idx_b);
            unsafe {
                let seq_a = (*slot_a).seq.load(Ordering::Acquire);
                let seq_b = (*slot_b).seq.load(Ordering::Acquire);
                (*slot_a).seq.store(seq_b, Ordering::Release);
                (*slot_b).seq.store(seq_a, Ordering::Release);
            }
            InjectionResult {
                fault: Fault::ReorderMessages,
                success: true,
                detail: format!("Swapped seq numbers of slots {} and {}", idx_a, idx_b),
                agent_slot: None,
                message_slot: None,
            }
        } else {
            InjectionResult {
                fault: Fault::ReorderMessages,
                success: false,
                detail: "Not enough messages to reorder".into(),
                agent_slot: None,
                message_slot: None,
            }
        }
    }

    fn do_duplicate_message(&mut self, slot_idx: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                let len = (*slot).payload_len as usize;
                if len > 0 && len <= arena::MAX_MSG_SIZE {
                    let mut dup_payload = [0u8; arena::MAX_MSG_SIZE];
                    std::ptr::copy_nonoverlapping((*slot).payload.as_ptr(), dup_payload.as_mut_ptr(), len);
                    // Write to next slot as duplicate
                    let next_idx = (slot_idx + 1) % arena::MAX_MESSAGES;
                    let next_slot = arena::message_slot_mut(ptr, next_idx);
                    let dup_seq = (*slot).seq.load(Ordering::Acquire);
                    std::ptr::copy_nonoverlapping(
                        (*slot).agent_id.as_ptr(),
                        (*next_slot).agent_id.as_mut_ptr(),
                        16,
                    );
                    std::ptr::copy_nonoverlapping(
                        (*slot).verifying_key.as_ptr(),
                        (*next_slot).verifying_key.as_mut_ptr(),
                        32,
                    );
                    std::ptr::copy_nonoverlapping(
                        (*slot).signature.as_ptr(),
                        (*next_slot).signature.as_mut_ptr(),
                        64,
                    );
                    (*next_slot).role = (*slot).role;
                    (*next_slot).payload_len = len as u32;
                    std::ptr::copy_nonoverlapping(dup_payload.as_ptr(), (*next_slot).payload.as_mut_ptr(), len);
                    (*next_slot).seq.store(dup_seq, Ordering::Release);
                }
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::DuplicateMessage(slot_idx),
            success,
            detail: if success {
                format!("Message at slot {} duplicated to slot {}", slot_idx, (slot_idx + 1) % arena::MAX_MESSAGES)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    fn do_delay_delivery(&mut self, slot_idx: usize, _delay_ns: u64) -> InjectionResult {
        let ptr = self.arena_ptr;
        let success = if slot_idx < arena::MAX_MESSAGES {
            let slot = arena::message_slot_mut(ptr, slot_idx);
            unsafe {
                let old_seq = (*slot).seq.load(Ordering::Acquire);
                // Lower seq so it appears "in the past" but still valid
                if old_seq > 1 {
                    (*slot).seq.store(old_seq - 1, Ordering::Release);
                }
            }
            true
        } else {
            false
        };
        InjectionResult {
            fault: Fault::DelayDelivery(slot_idx, _delay_ns),
            success,
            detail: if success {
                format!("Message at slot {} delayed (seq decremented)", slot_idx)
            } else {
                format!("Invalid slot index {}", slot_idx)
            },
            agent_slot: None,
            message_slot: Some(slot_idx),
        }
    }

    // ── Coordinated injections ──

    fn do_degrade_multiple(&mut self, agents: &[[u8; 16]]) -> InjectionResult {
        let mut count = 0u32;
        for agent_id in agents {
            let result = self.do_simulate_timeout(agent_id);
            if result.success {
                count += 1;
            }
        }
        InjectionResult {
            fault: Fault::DegradeMultiple(agents.to_vec()),
            success: count > 0,
            detail: format!("Degraded {} of {} targeted agents", count, agents.len()),
            agent_slot: None,
            message_slot: None,
        }
    }

    fn do_slow_arena(&mut self) -> InjectionResult {
        // Simulated: flood the cursor to create "stale" state
        let cursor = arena::write_cursor_ref(self.arena_ptr);
        cursor.fetch_add(1000, Ordering::AcqRel);
        InjectionResult {
            fault: Fault::SlowArena,
            success: true,
            detail: "Arena write cursor advanced by 1000 to simulate slowdown".into(),
            agent_slot: None,
            message_slot: None,
        }
    }

    fn do_reduce_quorum(&mut self, _threshold: u32) -> InjectionResult {
        // Quorum is configured per-agent in ConsenusEngine — this injection
        // logs the event for operator awareness. Actual quorum change must
        // be done via reconfigure.
        InjectionResult {
            fault: Fault::ReduceQuorum(_threshold),
            success: true,
            detail: format!("Quorum reduction request for threshold {} recorded", _threshold),
            agent_slot: None,
            message_slot: None,
        }
    }

    fn do_corrupt_arena_header(&mut self) -> InjectionResult {
        let ptr = self.arena_ptr;
        unsafe {
            let header = ptr as *mut arena::ArenaHeader;
            (*header).magic = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        }
        InjectionResult {
            fault: Fault::CorruptArenaHeader,
            success: true,
            detail: "Arena header magic corrupted to 0xDEADBEEF".into(),
            agent_slot: None,
            message_slot: None,
        }
    }

    fn do_flood_arena(&mut self, count: usize) -> InjectionResult {
        let ptr = self.arena_ptr;
        let max_slots = arena::MAX_MESSAGES;
        let write_count = count.min(max_slots / 2);
        for i in 0..write_count {
            let slot = arena::message_slot_mut(ptr, i);
            unsafe {
                (*slot).seq.store(u64::MAX - i as u64, Ordering::Release);
                (*slot).payload_len = arena::MAX_MSG_SIZE as u32;
            }
        }
        InjectionResult {
            fault: Fault::FloodArena(count),
            success: write_count > 0,
            detail: format!("Flooded arena with {} garbage messages", write_count),
            agent_slot: None,
            message_slot: None,
        }
    }

    pub fn injected_count(&self) -> u64 {
        self.injected_count
    }

    pub fn active_faults(&self) -> &[Fault] {
        &self.active_faults
    }

    /// Reset the engine: clear killed slots, active faults
    pub fn reset(&mut self) {
        self.killed_slots.clear();
        self.active_faults.clear();
        self.injected_count = 0;
    }

    /// Check if the arena is still usable (header not corrupted)
    pub fn arena_is_healthy(&self) -> bool {
        arena::verify_arena(self.arena_ptr)
    }

    /// Count alive agents
    pub fn alive_agent_count(&self) -> usize {
        let ptr = self.arena_ptr;
        let mut count = 0;
        arena::enumerate_agents(ptr, |_, _, _, _| count += 1);
        count
    }
}

// ── Replay integration ────────────────────────────────────────────────────

/// A recorded fault that can be replayed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReplayableFault {
    pub index: u64,
    pub fault_label: String,
    pub description: String,
    pub timestamp: u64,
}

/// Run a chaos scenario: a sequence of injections against an engine.
/// Returns results and whether the arena survived.
pub fn run_scenario(
    engine: &mut ChaosEngine,
    recipes: &[ChaosRecipe],
) -> (Vec<InjectionResult>, bool) {
    let results = engine.inject_all(recipes);
    let survived = engine.arena_is_healthy();
    (results, survived)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetryBuffer;

    fn alloc_arena() -> *mut u8 {
        let size = arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        arena::init_arena(ptr);
        let tb = TelemetryBuffer::open(ptr);
        tb.init();
        ptr
    }

    unsafe fn free_arena(ptr: *mut u8) {
        let size = arena::arena_size();
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        std::alloc::dealloc(ptr, layout);
    }

    fn register_test_agent(ptr: *mut u8, id: [u8; 16]) -> usize {
        arena::find_or_claim_agent_slot(ptr, id).expect("slot available")
    }

    fn write_dummy_message(ptr: *mut u8) -> usize {
        let (seq, slot_idx) = arena::claim_slot(ptr);
        let slot = arena::message_slot_mut(ptr, slot_idx);
        let payload = b"test message payload";
        arena::write_message_slot(
            slot, seq, 1000, [1u8; 16], [2u8; 32], [3u8; 64], 0, payload,
        );
        slot_idx
    }

    // ── Fail-stop tests ──

    #[test]
    fn test_chaos_kill_agent() {
        let ptr = alloc_arena();
        let agent_id = [0xAAu8; 16];
        let slot = register_test_agent(ptr, agent_id);
        assert!(arena::agent_flags_val(ptr, slot) & 2 == 0, "should be alive");

        let mut engine = ChaosEngine::new(ptr);
        let recipe = ChaosRecipe::kill_agent(agent_id);
        let result = engine.inject(&recipe);
        assert!(result.success, "kill should succeed");

        assert!(arena::agent_flags_val(ptr, slot) & 2 != 0, "agent should be dead");
        assert_eq!(engine.alive_agent_count(), 0, "no alive agents");
        assert!(engine.arena_is_healthy());
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_kill_unknown_agent() {
        let ptr = alloc_arena();
        let unknown_id = [0xBBu8; 16];
        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::kill_agent(unknown_id));
        assert!(!result.success, "unknown agent should not be found");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_timeout_agent() {
        let ptr = alloc_arena();
        let agent_id = [0xCCu8; 16];
        register_test_agent(ptr, agent_id);
        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::simulate_timeout(agent_id));
        assert!(result.success);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_drop_message() {
        let ptr = alloc_arena();
        write_dummy_message(ptr); // seq 0
        let slot_idx = write_dummy_message(ptr); // seq 1
        assert!(arena::read_slot_seq(arena::message_slot_ptr(ptr, slot_idx)) > 0);

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::new(
            Fault::DropMessage(slot_idx),
            "drop test message",
        ));
        assert!(result.success);

        let seq = arena::read_slot_seq(arena::message_slot_ptr(ptr, slot_idx));
        assert_eq!(seq, 0, "dropped message seq should be 0");
        unsafe { free_arena(ptr); }
    }

    // ── Byzantine-lite tests ──

    #[test]
    fn test_chaos_corrupt_message() {
        let ptr = alloc_arena();
        let slot_idx = write_dummy_message(ptr);
        let orig_payload = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            let len = (*slot).payload_len as usize;
            let mut buf = vec![0u8; len.min(32)];
            std::ptr::copy_nonoverlapping((*slot).payload.as_ptr(), buf.as_mut_ptr(), buf.len());
            buf
        };

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::corrupt_message(slot_idx));
        assert!(result.success);

        let new_payload = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            let len = (*slot).payload_len as usize;
            let mut buf = vec![0u8; len.min(32)];
            std::ptr::copy_nonoverlapping((*slot).payload.as_ptr(), buf.as_mut_ptr(), buf.len());
            buf
        };
        assert_ne!(orig_payload, new_payload, "payload should differ after corruption");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_corrupt_signature() {
        let ptr = alloc_arena();
        let slot_idx = write_dummy_message(ptr);
        let orig_sig = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            (*slot).signature
        };

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::corrupt_signature(slot_idx));
        assert!(result.success);

        let new_sig = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            (*slot).signature
        };
        assert_ne!(orig_sig, new_sig, "signature should differ after corruption");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_corrupt_agent_id() {
        let ptr = alloc_arena();
        let slot_idx = write_dummy_message(ptr);
        let orig_id = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            (*slot).agent_id
        };

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::new(
            Fault::CorruptAgentId(slot_idx),
            "corrupt agent id",
        ));
        assert!(result.success);

        let new_id = unsafe {
            let slot = arena::message_slot_ptr(ptr, slot_idx);
            (*slot).agent_id
        };
        assert_ne!(orig_id, new_id);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_reorder_messages() {
        let ptr = alloc_arena();
        // Write two messages so we have something to swap
        write_dummy_message(ptr);
        write_dummy_message(ptr);

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::reorder());
        assert!(result.success, "reorder needs > 1 message");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_duplicate_message() {
        let ptr = alloc_arena();
        let slot_idx = write_dummy_message(ptr);
        let next_idx = (slot_idx + 1) % arena::MAX_MESSAGES;

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::new(
            Fault::DuplicateMessage(slot_idx),
            "duplicate message",
        ));
        assert!(result.success);

        let dup_seq = unsafe { (*arena::message_slot_ptr(ptr, next_idx)).seq.load(Ordering::Acquire) };
        let orig_seq = unsafe { (*arena::message_slot_ptr(ptr, slot_idx)).seq.load(Ordering::Acquire) };
        assert_eq!(dup_seq, orig_seq, "duplicate should have same seq");
        unsafe { free_arena(ptr); }
    }

    // ── Coordinated tests ──

    #[test]
    fn test_chaos_degrade_multiple() {
        let ptr = alloc_arena();
        let id1 = [0x11u8; 16];
        let id2 = [0x22u8; 16];
        register_test_agent(ptr, id1);
        register_test_agent(ptr, id2);

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::degrade_agents(vec![id1, id2]));
        assert!(result.success);
        assert!(result.detail.contains("2"), "should degrade 2 agents");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_corrupt_arena_header() {
        let ptr = alloc_arena();
        assert!(arena::verify_arena(ptr));

        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::corrupt_header());
        assert!(result.success);
        assert!(!engine.arena_is_healthy(), "arena should be corrupted");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_flood_arena() {
        let ptr = alloc_arena();
        let mut engine = ChaosEngine::new(ptr);
        let result = engine.inject(&ChaosRecipe::flood_arena(100));
        assert!(result.success);

        // Verify first flooded slot has the garbage seq
        let seq = arena::read_slot_seq(arena::message_slot_ptr(ptr, 0));
        assert_eq!(seq, u64::MAX, "flooded slot should have max seq");
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_scenario_survives_fail_stop() {
        let ptr = alloc_arena();
        let id1 = [0xA1u8; 16];
        let id2 = [0xA2u8; 16];
        register_test_agent(ptr, id1);
        register_test_agent(ptr, id2);

        let mut engine = ChaosEngine::new(ptr);
        let recipes = vec![
            ChaosRecipe::kill_agent(id1),
            ChaosRecipe::simulate_timeout(id2),
        ];
        let (results, survived) = run_scenario(&mut engine, &recipes);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
        assert!(survived, "arena should survive fail-stop");
        // Only the killed agent is gone; timed-out agent still has flags & 1
        assert_eq!(engine.alive_agent_count(), 1);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_mixed_scenario() {
        let ptr = alloc_arena();
        let id = [0xB0u8; 16];
        register_test_agent(ptr, id);
        let slot = write_dummy_message(ptr);

        let mut engine = ChaosEngine::new(ptr);
        let recipes = vec![
            ChaosRecipe::kill_agent(id),
            ChaosRecipe::corrupt_message(slot),
            ChaosRecipe::corrupt_signature(slot),
        ];
        let (results, survived) = run_scenario(&mut engine, &recipes);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
        // Corrupt header not included, so arena should survive
        assert!(survived);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_injected_count() {
        let ptr = alloc_arena();
        let id = [0xC0u8; 16];
        register_test_agent(ptr, id);

        let mut engine = ChaosEngine::new(ptr);
        assert_eq!(engine.injected_count(), 0);
        engine.inject(&ChaosRecipe::kill_agent(id));
        assert_eq!(engine.injected_count(), 1);
        engine.inject(&ChaosRecipe::kill_agent(id)); // already dead, will fail
        assert_eq!(engine.injected_count(), 2);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_reset() {
        let ptr = alloc_arena();
        let id = [0xD0u8; 16];
        register_test_agent(ptr, id);

        let mut engine = ChaosEngine::new(ptr);
        engine.inject(&ChaosRecipe::kill_agent(id));
        assert_eq!(engine.injected_count(), 1);

        engine.reset();
        assert_eq!(engine.injected_count(), 0);
        assert!(engine.arena_is_healthy());
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chaos_header_corruption_detected() {
        let ptr = alloc_arena();
        let mut engine = ChaosEngine::new(ptr);
        assert!(engine.arena_is_healthy());
        engine.inject(&ChaosRecipe::corrupt_header());
        assert!(!engine.arena_is_healthy());
        unsafe { free_arena(ptr); }
    }
}
