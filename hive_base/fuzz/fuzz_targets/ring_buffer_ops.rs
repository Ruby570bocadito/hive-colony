#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }
    use hive_base::shared_arena as arena;
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(arena::arena_size(), 64).unwrap();
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() { return; }
    arena::init_arena(ptr);
    let (_seq, _slot_idx) = arena::claim_slot(ptr);
    let slot = arena::message_slot_mut(ptr, 0);
    let agent_id = [0x01u8; 16];
    let now = 1000u64;
    let payload = &data[..std::cmp::min(data.len(), arena::MAX_MSG_SIZE)];
    arena::write_message_slot(slot, 1, now, agent_id, [0u8; 32], [0u8; 64], 0, payload);
    // Read back
    let slot_ptr = arena::message_slot_ptr(ptr, 0);
    let seq_read = arena::read_slot_seq(slot_ptr);
    assert!(seq_read > 0 || seq_read == 1);
    unsafe {
        let _ = std::alloc::dealloc(ptr, layout);
    }
});
