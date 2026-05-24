use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hive_base::telemetry::{Event, EventType, TelemetryBuffer};

fn bench_telemetry_buffer_write(c: &mut Criterion) {
    // Must use the full arena size — TelemetryBuffer relies on shared_arena
    // offsets for its header and data region (well beyond the 4 MB buffer).
    let arena_size = hive_base::shared_arena::arena_size();
    let layout = std::alloc::Layout::from_size_align(arena_size, 64).unwrap();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

    c.bench_function("telemetry_buffer_write_1000_events", |b| {
        b.iter(|| {
            let tb = TelemetryBuffer::open(black_box(ptr));
            tb.init();
            let agent = [0x01u8; 16];
            for i in 0..1000 {
                let event = Event::new(agent, i, EventType::HeartbeatSent, vec![], None);
                tb.write_event(&event);
            }
            black_box(tb.occupancy_ratio());
        })
    });

    // Read benchmark reuses the buffer filled by the write benchmark's last iteration.
    // Memory is intentionally leaked — OS reclaims on process exit.
    // Criterion runs benchmarks lazily, so the allocation must outlive this function.
    c.bench_function("telemetry_buffer_read_all", |b| {
        b.iter(|| {
            let tb = TelemetryBuffer::open(black_box(ptr));
            let events = tb.peek(4096);
            black_box(events.len());
        })
    });
}

fn bench_arena_claim_write_read(c: &mut Criterion) {
    let layout = std::alloc::Layout::from_size_align(
        hive_base::shared_arena::arena_size(), 64).unwrap();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    hive_base::shared_arena::init_arena(ptr);

    let agent_id = [0x42u8; 16];
    let payload = vec![0xABu8; 1024];
    let now = 1000u64;

    c.bench_function("arena_claim_write_1000_messages", |b| {
        b.iter(|| {
            for i in 0..1000 {
                let (_seq, slot_idx) = hive_base::shared_arena::claim_slot(black_box(ptr));
                let slot = hive_base::shared_arena::message_slot_mut(ptr, slot_idx);
                hive_base::shared_arena::write_message_slot(
                    black_box(slot), i, now, agent_id, [0u8; 32], [0u8; 64], 0, &payload);
            }
            black_box(())
        })
    });
}

criterion_group!(benches, bench_telemetry_buffer_write, bench_arena_claim_write_read);
criterion_main!(benches);
