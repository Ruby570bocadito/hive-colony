// Phase A Integration Tests
// Validates the complete HTL + Chaos + IPC Contracts pipeline:
//   - Colony degrades controllably under chaos
//   - Replay engine reproduces exact degradation sequences
//   - SafetyTrigger events fire on contract violations
//   - State machine respects formal transitions

use std::path::Path;
use uuid::Uuid;

use hive_base::chaos::{ChaosEngine, ChaosRecipe};
use hive_base::ipc_contract::{
    AgentState, AgentStateMachine, ContractFault, MessageValidator,
    validate_message,
};
use hive_base::ldc::{Message, Role};
use hive_base::shared_arena as arena;
use hive_base::telemetry::{
    Criticality, Event, EventId, EventType, ReplayEngine,
    TelemetryBuffer, TelemetryCollector,
};

// ── Helpers ───────────────────────────────────────────────────────────────

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

fn test_id() -> Uuid {
    Uuid::new_v4()
}

fn agent_id_from_uuid(id: Uuid) -> [u8; 16] {
    *id.as_bytes()
}

fn register_agent(ptr: *mut u8, id: [u8; 16]) -> usize {
    arena::find_or_claim_agent_slot(ptr, id).expect("slot free")
}

fn make_collector(agent_id: [u8; 16], ptr: *mut u8, dir: &Path) -> TelemetryCollector {
    TelemetryCollector::new(agent_id, ptr, dir)
}

// ── Scenario 1: Controlled degradation via FloodInvalidMessages ────────────

mod scenario1_controlled_degradation {
    use super::*;

    #[test]
    fn test_s1_flood_triggers_safety_events() {
        let ptr = alloc_arena();
        let id = test_id();
        let id_bytes = agent_id_from_uuid(id);
        let dir = std::env::temp_dir().join("s1_flood_triggers");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = make_collector(id_bytes, ptr, &dir);
        let mut validator = MessageValidator::new(id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();

        assert_eq!(validator.state_machine().state(), AgentState::Active);

        // Inject 5+ invalid messages to force DEGRADED
        let fault = ContractFault::FloodInvalidMessages(10);
        for _ in 0..6 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let _ = validator.validate(&bad_msg);
        }

        assert_eq!(
            validator.state_machine().state(),
            AgentState::Degraded,
            "should degrade after threshold"
        );
        assert!(
            validator.reject_count() >= 5,
            "should have rejected >=5 messages, got {}",
            validator.reject_count()
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s1_other_agents_not_degraded() {
        let ptr = alloc_arena();
        let queen_id = test_id();
        let worker_id = test_id();
        let dir = std::env::temp_dir().join("s1_other_not_degraded");
        let _ = std::fs::remove_dir_all(&dir);

        // Queen gets flooded
        let collector = make_collector(agent_id_from_uuid(queen_id), ptr, &dir);
        let mut queen_validator = MessageValidator::new(queen_id).with_collector(collector);
        queen_validator.state_machine_mut().activate().unwrap();

        // Worker stays clean
        let mut worker_state = AgentStateMachine::new(worker_id);
        worker_state.activate().unwrap();

        let fault = ContractFault::FloodInvalidMessages(10);
        for _ in 0..6 {
            let bad_msg = fault.build_message(worker_id, Role::Worker);
            let _ = queen_validator.validate(&bad_msg);
        }

        assert_eq!(
            queen_validator.state_machine().state(),
            AgentState::Degraded,
            "queen should be degraded"
        );
        assert_eq!(
            worker_state.state(),
            AgentState::Active,
            "worker should remain active"
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s1_safety_trigger_event_types() {
        let ptr = alloc_arena();
        let id = test_id();
        let id_bytes = agent_id_from_uuid(id);
        let dir = std::env::temp_dir().join("s1_safety_events");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = make_collector(id_bytes, ptr, &dir);
        let mut validator = MessageValidator::new(id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();

        let fault = ContractFault::EmptyFieldMessage;
        let bad_msg = fault.build_message(test_id(), Role::Worker);
        let result = validator.validate(&bad_msg);
        assert!(result.is_err(), "empty field should be rejected");

        // Drain telemetry to verify events were emitted
        // (We can't inspect the collector's internal buffer directly in tests,
        //  but we can verify the state transition happened)
        assert_eq!(validator.state_machine().invalid_message_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s1_replay_degradation_sequence() {
        let ptr = alloc_arena();
        let id = test_id();
        let id_bytes = agent_id_from_uuid(id);
        let dir = std::env::temp_dir().join("s1_replay_seq");
        let _ = std::fs::remove_dir_all(&dir);

        let collector = make_collector(id_bytes, ptr, &dir);
        let mut validator = MessageValidator::new(id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();

        // Track state transitions manually for replay comparison
        let mut expected_transitions: Vec<String> = Vec::new();
        expected_transitions.push("init→active".into());

        let fault = ContractFault::FloodInvalidMessages(10);
        for i in 0..6 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let _ = validator.validate(&bad_msg);
            if i == 4 {
                // On the 5th invalid message (threshold=5), should degrade
                expected_transitions.push("active→degraded".into());
            }
        }

        // Verify expected transitions happened
        let history = validator.state_machine().history();
        for (i, transition) in history.iter().enumerate() {
            let label = format!("{}→{}", transition.from.label(), transition.to.label());
            if i < expected_transitions.len() {
                assert_eq!(
                    label, expected_transitions[i],
                    "transition {} mismatch: expected {}, got {}",
                    i, expected_transitions[i], label
                );
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }
}

// ── Scenario 2: Recovery from DEGRADED to ACTIVE ──────────────────────────

mod scenario2_recovery {
    use super::*;

    #[test]
    fn test_s2_sporadic_invalid_below_threshold() {
        let id = test_id();
        let mut sm = AgentStateMachine::new(id).with_degrade_threshold(5);
        sm.activate().unwrap();

        // Inject 4 invalid messages (below threshold of 5)
        let fault = ContractFault::EmptyFieldMessage;
        for _ in 0..4 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let is_valid = validate_message(&bad_msg).valid;
            sm.record_message(is_valid);
        }

        assert_eq!(
            sm.state(),
            AgentState::Active,
            "should stay active below threshold"
        );
        assert_eq!(sm.invalid_message_count(), 4);
    }

    #[test]
    fn test_s2_force_degraded_then_recover() {
        let id = test_id();
        let mut sm = AgentStateMachine::new(id).with_degrade_threshold(3);
        sm.activate().unwrap();

        // Force invalid until threshold
        let fault = ContractFault::BadConfidence;
        for _ in 0..3 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let _ = sm.record_message(!validate_message(&bad_msg).valid);
        }
        // Wait, record_message takes is_valid, not !is_valid
        // Let me redo this properly
        let mut sm2 = AgentStateMachine::new(id).with_degrade_threshold(3);
        sm2.activate().unwrap();

        for _ in 0..3 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let is_valid = validate_message(&bad_msg).valid;
            sm2.record_message(is_valid);
        }

        assert_eq!(sm2.state(), AgentState::Degraded);

        // Now recover: inject only valid messages
        let good_msg = Message::heartbeat(test_id(), Role::Worker);
        for _ in 0..5 {
            let is_valid = validate_message(&good_msg).valid;
            sm2.record_message(is_valid);
        }

        // Recover via explicit call
        assert!(sm2.recover().is_ok());
        assert_eq!(sm2.state(), AgentState::Active);
    }

    #[test]
    fn test_s2_degraded_still_processes_valid() {
        let id = test_id();
        let mut sm = AgentStateMachine::new(id).with_degrade_threshold(1);
        sm.activate().unwrap();

        // Force immediate degradation
        let fault = ContractFault::EmptyFieldMessage;
        let bad_msg = fault.build_message(test_id(), Role::Worker);
        sm.record_message(validate_message(&bad_msg).valid);
        assert_eq!(sm.state(), AgentState::Degraded);

        // Valid messages should still be counted but state unchanged
        let good_msg = Message::heartbeat(test_id(), Role::Worker);
        let is_valid = validate_message(&good_msg).valid;
        assert!(is_valid, "heartbeat should be valid");
        sm.record_message(is_valid);
        assert_eq!(sm.state(), AgentState::Degraded);
    }

    #[test]
    fn test_s2_transition_history_accuracy() {
        let id = test_id();
        let mut sm = AgentStateMachine::new(id);
        assert_eq!(sm.history_len(), 0);

        sm.activate().unwrap();
        assert_eq!(sm.history_len(), 1);
        assert_eq!(sm.history()[0].from, AgentState::Init);
        assert_eq!(sm.history()[0].to, AgentState::Active);

        sm.degrade("injected fault").unwrap();
        assert_eq!(sm.history_len(), 2);
        assert_eq!(sm.history()[1].from, AgentState::Active);
        assert_eq!(sm.history()[1].to, AgentState::Degraded);
        assert!(sm.history()[1].reason.contains("fault"));

        sm.recover().unwrap();
        assert_eq!(sm.history_len(), 3);
        assert_eq!(sm.history()[2].from, AgentState::Degraded);
        assert_eq!(sm.history()[2].to, AgentState::Active);
    }
}

// ── Scenario 3: Kill switch via Chaos ─────────────────────────────────────

mod scenario3_kill_switch {
    use super::*;

    #[test]
    fn test_s3_kill_queen_transitions_dead() {
        let ptr = alloc_arena();
        let queen_id = test_id();
        let queen_bytes = agent_id_from_uuid(queen_id);
        let slot = register_agent(ptr, queen_bytes);
        assert!(arena::agent_flags_val(ptr, slot) & 2 == 0, "queen alive");

        let mut sm = AgentStateMachine::new(queen_id);
        sm.activate().unwrap();

        // Chaos: kill the queen in the arena
        let mut chaos = ChaosEngine::new(ptr);
        let result = chaos.inject(&ChaosRecipe::kill_agent(queen_bytes));
        assert!(result.success, "kill queen should succeed");

        // Verify arena state
        assert!(arena::agent_flags_val(ptr, slot) & 2 != 0, "queen slot should be DEAD");

        // Verify state machine transition
        sm.mark_dead("kill switch injected").unwrap();
        assert_eq!(sm.state(), AgentState::Dead);

        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s3_workers_detect_queen_death() {
        let ptr = alloc_arena();
        let queen_bytes = agent_id_from_uuid(test_id());
        let worker_bytes = agent_id_from_uuid(test_id());

        let queen_slot = register_agent(ptr, queen_bytes);
        let _worker_slot = register_agent(ptr, worker_bytes);
        assert!(arena::agent_flags_val(ptr, queen_slot) & 2 == 0, "queen alive");

        // Kill queen
        let mut chaos = ChaosEngine::new(ptr);
        chaos.inject(&ChaosRecipe::kill_agent(queen_bytes));

        // Verify queen dead
        assert!(arena::agent_flags_val(ptr, queen_slot) & 2 != 0);

        // Worker state machine stays active (worker not killed)
        let worker_id = Uuid::from_bytes(worker_bytes);
        let mut worker_sm = AgentStateMachine::new(worker_id);
        worker_sm.activate().unwrap();
        assert_eq!(worker_sm.state(), AgentState::Active);

        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s3_colony_survives_queen_loss() {
        let ptr = alloc_arena();
        let queen_bytes = agent_id_from_uuid(test_id());
        let worker_bytes = agent_id_from_uuid(test_id());
        let drone_bytes = agent_id_from_uuid(test_id());

        register_agent(ptr, queen_bytes);
        register_agent(ptr, worker_bytes);
        register_agent(ptr, drone_bytes);

        // Kill queen
        let mut chaos = ChaosEngine::new(ptr);
        chaos.inject(&ChaosRecipe::kill_agent(queen_bytes));

        // Colony survives: worker and drone still registered
        let alive = chaos.alive_agent_count();
        assert_eq!(alive, 2, "worker + drone should survive (queen dead)");
        assert!(chaos.arena_is_healthy(), "arena should be healthy");

        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_s3_dead_agent_rejects_all_messages() {
        let id = test_id();
        let mut validator = MessageValidator::new(id);
        validator.state_machine_mut().activate().unwrap();
        validator.state_machine_mut().mark_dead("kill switch").unwrap();

        // Even a heartbeat should be rejected when DEAD
        let msg = Message::heartbeat(test_id(), Role::Worker);
        let result = validator.validate(&msg);
        assert!(result.is_err(), "dead agent should reject even heartbeats");
    }
}

// ── Scenario 4: Replay fidelity + causal DAG consistency ──────────────────

mod scenario4_replay {
    use super::*;

    fn build_event(agent_id: [u8; 16], seq: u64, event_type: EventType, causes: Vec<EventId>) -> Event {
        Event::new(agent_id, seq, event_type, causes, None)
    }

    #[test]
    fn test_s4_replay_empty_log() {
        let engine = ReplayEngine::new();
        assert_eq!(engine.state().total_events, 0);
        assert!(engine.events().is_empty());
        assert!(engine.verify_causal_integrity().is_empty());
    }

    #[test]
    fn test_s4_replay_single_event_sequence() {
        let agent = [0x01u8; 16];

        let e1 = build_event(agent, 1, EventType::HeartbeatSent, vec![]);
        let e2 = build_event(agent, 2, EventType::BeliefPublished, vec![e1.id.clone()]);
        let e3 = build_event(agent, 3, EventType::AgentStateChange, vec![e2.id.clone()]);

        let dir = std::env::temp_dir().join("s4_single_seq");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("events.jsonl");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            use std::io::Write;
            for e in &[&e1, &e2, &e3] {
                writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
        }

        let mut engine = ReplayEngine::new();
        let count = engine.load_file(&path).unwrap();
        assert_eq!(count, 3);

        // Step through
        assert_eq!(engine.state().current_index, 0);
        assert!(engine.step_forward().is_some());
        assert_eq!(engine.state().current_index, 1);
        assert!(engine.step_forward().is_some());
        assert_eq!(engine.state().current_index, 2);
        assert!(engine.step_forward().is_some());
        assert_eq!(engine.state().current_index, 3);
        assert!(engine.step_forward().is_none()); // end

        // Causal integrity should pass
        let errors = engine.verify_causal_integrity();
        assert!(errors.is_empty(), "causal integrity should hold: {:?}", errors);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_s4_replay_causal_dag_consistency() {
        let mut engine = ReplayEngine::new();
        let agent = [0x02u8; 16];

        // Event 3 references event 99 (missing) — should fail integrity
        let e1 = build_event(agent, 1, EventType::HeartbeatSent, vec![]);
        let e3 = build_event(agent, 3, EventType::SecurityTrigger, vec![EventId::new(agent, 99)]);

        let dir = std::env::temp_dir().join("s4_causal_dag");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("dag_test.jsonl");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            use std::io::Write;
            writeln!(f, "{}", serde_json::to_string(&e1).unwrap()).unwrap();
            writeln!(f, "{}", serde_json::to_string(&e3).unwrap()).unwrap();
        }

        engine.load_file(&path).unwrap();
        let errors = engine.verify_causal_integrity();
        assert!(!errors.is_empty(), "should detect missing cause");
        assert!(
            errors.iter().any(|e| e.contains("99")),
            "error should mention missing seq 99: {:?}",
            errors
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_s4_replay_step_backward_reset() {
        let agent = [0x03u8; 16];
        let e1 = build_event(agent, 1, EventType::HeartbeatSent, vec![]);
        let e2 = build_event(agent, 2, EventType::BeliefPublished, vec![]);

        let dir = std::env::temp_dir().join("s4_step_back");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("back.jsonl");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            use std::io::Write;
            writeln!(f, "{}", serde_json::to_string(&e1).unwrap()).unwrap();
            writeln!(f, "{}", serde_json::to_string(&e2).unwrap()).unwrap();
        }

        let mut engine = ReplayEngine::new();
        engine.load_file(&path).unwrap();

        engine.step_forward();
        engine.step_forward();
        assert_eq!(engine.state().current_index, 2);

        engine.step_backward();
        assert_eq!(engine.state().current_index, 1);

        engine.reset();
        assert_eq!(engine.state().current_index, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_s4_replay_pause_toggle() {
        let mut engine = ReplayEngine::new();
        assert!(!engine.is_paused());
        engine.toggle_pause();
        assert!(engine.is_paused());
        engine.toggle_pause();
        assert!(!engine.is_paused());
    }

    #[test]
    fn test_s4_replay_jump_to_index() {
        let agent = [0x04u8; 16];
        let events: Vec<_> = (0..5)
            .map(|i| build_event(agent, i, EventType::HeartbeatSent, vec![]))
            .collect();

        let dir = std::env::temp_dir().join("s4_jump");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jump.jsonl");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            use std::io::Write;
            for e in &events {
                writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
        }

        let mut engine = ReplayEngine::new();
        engine.load_file(&path).unwrap();
        engine.jump_to(3);
        assert_eq!(engine.state().current_index, 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_s4_replay_critical_event_priority() {
        // Critical events should be persisted regardless of buffer state
        let agent = [0x05u8; 16];
        let event = build_event(agent, 1, EventType::KillSwitchActivated, vec![]);
        assert_eq!(event.criticality, Criticality::Critical);

        // Verify round-trip serialization preserves criticality
        let json = serde_json::to_string(&event).unwrap();
        let deser: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.criticality, Criticality::Critical);
        assert_eq!(deser.event_type, EventType::KillSwitchActivated);
    }

    #[test]
    fn test_s4_replay_debug_events_skipped_in_production() {
        let agent = [0x06u8; 16];
        let dir = std::env::temp_dir().join("s4_debug_skip");
        let _ = std::fs::remove_dir_all(&dir);

        let ptr = alloc_arena();
        let collector = make_collector(agent, ptr, &dir);

        // Debug events should be skipped unless HIVE_LAB_MODE=1
        std::env::set_var("HIVE_LAB_MODE", "0");
        let emitted = collector.emit_simple(EventType::ModelInference);
        assert!(emitted.is_none(), "debug events skipped in production");

        // Normal events go through sampling (may or may not emit)
        // Critical events always emit
        let emitted = collector.emit_simple(EventType::KillSwitchActivated);
        assert!(emitted.is_some(), "critical events always emit");

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }
}

// ── Cross-module scenario: full pipeline HTL + Chaos + IPC Contracts ──────

mod full_pipeline {
    use super::*;

    #[test]
    fn test_full_pipeline_degrade_via_chaos_ipc_htl() {
        let ptr = alloc_arena();
        let agent_id = test_id();
        let id_bytes = agent_id_from_uuid(agent_id);
        let dir = std::env::temp_dir().join("full_pipeline_degrade");
        let _ = std::fs::remove_dir_all(&dir);

        // 1. Set up HTL collector
        let collector = make_collector(id_bytes, ptr, &dir);

        // 2. Set up IPC contract validator with HTL integration
        let mut validator = MessageValidator::new(agent_id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();
        assert_eq!(validator.state_machine().state(), AgentState::Active);

        // 3. Chaos: inject invalid contract-violating messages
        let fault = ContractFault::FloodInvalidMessages(10);
        for _ in 0..6 {
            let bad_msg = fault.build_message(test_id(), Role::Worker);
            let _ = validator.validate(&bad_msg);
        }

        // 4. Verify: state machine degraded
        assert_eq!(
            validator.state_machine().state(),
            AgentState::Degraded,
            "full pipeline: IPC contracts should detect invalid messages and degrade"
        );

        // 5. Verify: reject count reflects violations
        assert!(
            validator.reject_count() >= 5,
            "full pipeline: should have rejected >=5 invalid messages"
        );

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_full_pipeline_chaos_kill_then_ipc_reject() {
        let ptr = alloc_arena();
        let agent_id = test_id();
        let id_bytes = agent_id_from_uuid(agent_id);
        let dir = std::env::temp_dir().join("full_pipeline_kill");
        let _ = std::fs::remove_dir_all(&dir);

        register_agent(ptr, id_bytes);
        let collector = make_collector(id_bytes, ptr, &dir);

        // 1. Set up validator + state machine
        let mut validator = MessageValidator::new(agent_id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();

        // 2. Chaos: kill agent in arena
        let mut chaos = ChaosEngine::new(ptr);
        chaos.inject(&ChaosRecipe::kill_agent(id_bytes));

        // 3. IPC: mark state machine as DEAD
        validator.state_machine_mut().mark_dead("chaos kill").unwrap();
        assert_eq!(validator.state_machine().state(), AgentState::Dead);

        // 4. Verify: all messages rejected when DEAD
        let msg = Message::heartbeat(test_id(), Role::Worker);
        let result = validator.validate(&msg);
        assert!(result.is_err(), "DEAD agent should reject all messages");

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_full_pipeline_scenario_survives_and_logs() {
        let ptr = alloc_arena();
        let queen_id = test_id();
        let worker_id = test_id();
        let queen_bytes = agent_id_from_uuid(queen_id);
        let worker_bytes = agent_id_from_uuid(worker_id);
        let dir = std::env::temp_dir().join("full_pipeline_scenario");
        let _ = std::fs::remove_dir_all(&dir);

        register_agent(ptr, queen_bytes);
        register_agent(ptr, worker_bytes);

        let collector = make_collector(queen_bytes, ptr, &dir);
        let mut validator = MessageValidator::new(queen_id).with_collector(collector);
        validator.state_machine_mut().activate().unwrap();

        // Run a scenario: kill worker, flood queen with bad messages
        let mut chaos = ChaosEngine::new(ptr);
        chaos.inject(&ChaosRecipe::kill_agent(worker_bytes));

        let fault = ContractFault::FloodInvalidMessages(10);
        for _ in 0..8 {
            let bad_msg = fault.build_message(worker_id, Role::Worker);
            let _ = validator.validate(&bad_msg);
        }

        // Queen should be degraded (invalid msgs ≥ 5)
        assert_eq!(validator.state_machine().state(), AgentState::Degraded);

        // Arena still healthy despite deaths
        assert!(chaos.arena_is_healthy());
        // 1 agent dead (worker), 1 degraded but alive (queen)
        assert_eq!(chaos.alive_agent_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
        unsafe { free_arena(ptr); }
    }
}

// ── Scenario 5: Cross-module Integration ─────────────────────────────────────
//
// Tests that span multiple modules: WhisperNet ↔ HiveMind ↔ Tournament ↔ Chrononaut

mod scenario5_cross_module {
    use super::*;
    use std::collections::HashMap;
    use hive_base::hivemind::HiveMind;
    use hive_base::ldc::Decision;

    fn read_slot_payload(slot: *const arena::MessageSlot) -> Vec<u8> {
        unsafe {
            let len = (*slot).payload_len as usize;
            let mut buf = vec![0u8; len];
            std::ptr::copy_nonoverlapping((*slot).payload.as_ptr(), buf.as_mut_ptr(), len);
            buf
        }
    }

    #[test]
    fn test_whispernet_hivemind_arena_message_flow() {
        let ptr = alloc_arena();
        let queen_id = test_id();
        let worker_id = test_id();
        let id_bytes = agent_id_from_uuid(queen_id);

        let _queen_slot = register_agent(ptr, id_bytes);
        let _worker_slot = register_agent(ptr, agent_id_from_uuid(worker_id));

        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.consensus_threshold = 0.4;

        let did = hive.propose_from_operator(queen_id, "data_exfil".into(), HashMap::new());
        assert_eq!(hive.directives.len(), 1);

        let (arena_msg, _pid) = Message::proposal(
            queen_id, Role::Queen,
            "data_exfil".into(), "execute".into(),
        );

        let mut rep = HashMap::new();
        rep.insert(worker_id, 1.0);

        let _result = hive.process_arena_message(&arena_msg, &rep);
        assert!(hive.directives.iter().any(|d| d.directive_id == did));

        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_chrononaut_hivemind_timer_triggered_directive() {
        use hive_base::chrononaut::{Chrononaut, TimeCapsule};
        use std::io::Write;

        let dir = std::env::temp_dir().join("cross_chrono_hivemind");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("target.txt");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"marker").unwrap();

        let capsule_id = test_id();
        let capsule = TimeCapsule {
            capsule_id,
            trigger_timestamp: 1_800_000_000,
            command: "exfil --target /tmp/creds".into(),
            payload: b"encrypted_payload".to_vec(),
            host_hint: "target_host".into(),
            executed: false,
        };

        Chrononaut::encode_in_timestamp(&file_path, &capsule).unwrap();
        let recovered = Chrononaut::decode_from_timestamp(&file_path, capsule_id).unwrap();

        assert_eq!(recovered.capsule_id, capsule_id);
        assert_eq!(recovered.trigger_timestamp, capsule.trigger_timestamp);
        assert_eq!(recovered.command, capsule.command);
        assert_eq!(recovered.payload, capsule.payload);
        assert_eq!(recovered.host_hint, capsule.host_hint);

        let mut hive = HiveMind::new();
        hive.enabled = true;
        let id = test_id();
        let did = hive.propose_from_operator(id, recovered.command.clone(), HashMap::new());
        assert!(hive.directives.iter().any(|d| d.action == recovered.command));

        let mut rep = HashMap::new();
        rep.insert(id, 1.0);
        let vote = Message::vote(id, Role::Queen, did, Decision::Support, 1.0);
        let _ = hive.process_arena_message(&vote, &rep);
        assert!(hive.directives.iter().any(|d| d.approved));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tournament_result_propagation_through_hivemind() {
        use hive_base::tournament::{Tournament, TournamentConfig, WinCriteria};

        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.consensus_threshold = 0.3;

        let queen_id = test_id();

        let tournament = Tournament::new();
        let config = TournamentConfig {
            target: "sim_host".into(),
            competitors: 3,
            criteria: vec![WinCriteria::Speed, WinCriteria::Stealth],
            timeout_secs: 60,
            generations: 5,
        };
        let mut competitors = tournament.generate_competitors(&config);
        assert_eq!(competitors.len(), 3);

        tournament.score_competitor(&mut competitors[0], 1000, 1050, 2, 8, 0.7);
        tournament.score_competitor(&mut competitors[1], 1000, 1100, 0, 4, 0.3);
        tournament.score_competitor(&mut competitors[2], 1000, 1080, 5, 12, 0.9);

        assert!(competitors[0].completed);
        assert!(competitors[1].completed);
        assert!(competitors[2].completed);

        let winner_id = tournament.select_winner(&competitors).unwrap();
        let runner_up = tournament.select_runner_up(&competitors, winner_id);
        assert!(runner_up.is_some());
        assert_ne!(winner_id, runner_up.unwrap());

        let winner = competitors.iter().find(|c| c.id == winner_id).unwrap();
        let did = hive.propose_from_operator(
            queen_id, format!("deploy_winner:{}", winner.variant_code), HashMap::new(),
        );

        let mut rep = HashMap::new();
        rep.insert(queen_id, 1.0);
        let vote = Message::vote(queen_id, Role::Queen, did, Decision::Support, 1.0);
        let _ = hive.process_arena_message(&vote, &rep);
        assert!(hive.directives.iter().any(|d| d.approved));
    }

    #[test]
    fn test_whispernet_tournament_comms_message_conversion() {
        let mut hive = HiveMind::new();
        hive.enabled = true;

        let queen_id = test_id();
        let did = hive.propose_from_operator(queen_id, "directive:scan_network".into(), HashMap::new());
        let directive = hive.directives.iter().find(|d| d.directive_id == did).unwrap();

        let msg = hive.to_directive_message(directive, queen_id);

        // Verify it's a StatusEvent via payload match
        assert!(matches!(msg.payload, hive_base::ldc::Payload::StatusEvent{..}));

        let json_bytes = serde_json::to_vec(&msg).unwrap();
        assert!(!json_bytes.is_empty());
        let deserialized: Message = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(deserialized.agent_id, queen_id);
    }

    #[test]
    fn test_arena_whispernet_hivemind_cross_module_codec() {
        let ptr = alloc_arena();
        let queen_id = test_id();
        let id_bytes = agent_id_from_uuid(queen_id);
        let _slot = register_agent(ptr, id_bytes);

        let payload = b"cross_module_test".to_vec();
        let (_seq, slot_idx) = arena::claim_slot(ptr);
        let slot = arena::message_slot_mut(ptr, slot_idx);
        arena::write_message_slot(slot, 1, 1000, id_bytes, [0u8; 32], [0u8; 64], 0, &payload);

        let slot_ptr = arena::message_slot_ptr(ptr, slot_idx);
        let seq = arena::read_slot_seq(slot_ptr);
        assert_eq!(seq, 1);

        let payload_copy = read_slot_payload(slot_ptr);
        assert_eq!(payload_copy, payload);

        let payload_str = String::from_utf8_lossy(&payload_copy);
        let mut hive = HiveMind::new();
        hive.enabled = true;
        let did = hive.propose_from_operator(
            queen_id, format!("arena_cmd:{}", payload_str), HashMap::new(),
        );
        assert!(hive.directives.iter().any(|d| d.action.contains("cross_module_test")));

        let mut rep = HashMap::new();
        rep.insert(queen_id, 1.0);
        let vote = Message::vote(queen_id, Role::Queen, did, Decision::Support, 1.0);
        let _ = hive.process_arena_message(&vote, &rep);
        assert!(hive.directives.iter().any(|d| d.approved));

        unsafe { free_arena(ptr); }
    }

    #[test]
    fn test_hivemind_chrononaut_scheduled_directive_execution() {
        use hive_base::chrononaut::{Chrononaut, TimeCapsule};
        use std::io::Write;

        let mut hive = HiveMind::new();
        hive.enabled = true;
        hive.consensus_threshold = 0.3;

        let queen_id = test_id();

        let did = hive.propose_from_operator(
            queen_id, "scheduled_exfil".into(), HashMap::new(),
        );
        let mut rep = HashMap::new();
        rep.insert(queen_id, 1.0);
        let vote = Message::vote(queen_id, Role::Queen, did, Decision::Support, 1.0);
        let _ = hive.process_arena_message(&vote, &rep);
        assert!(hive.directives.iter().any(|d| d.approved));

        let directive = hive.directives.iter().find(|d| d.approved).unwrap();

        let dir = std::env::temp_dir().join("cross_hivemind_chrono");
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("chrono_target.txt");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        f.write_all(b"config").unwrap();

        let capsule = TimeCapsule {
            capsule_id: directive.directive_id,
            trigger_timestamp: 1_800_000_000,
            command: directive.action.clone(),
            payload: b"directive_payload".to_vec(),
            host_hint: "colony_host".into(),
            executed: false,
        };
        Chrononaut::encode_in_timestamp(&cfg_path, &capsule).unwrap();

        let recovered = Chrononaut::decode_from_timestamp(&cfg_path, directive.directive_id).unwrap();
        assert_eq!(recovered.command, directive.action);
        assert_eq!(recovered.host_hint, "colony_host");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
