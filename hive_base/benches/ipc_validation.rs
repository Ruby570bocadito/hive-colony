use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hive_base::ipc_contract::validate_message;
use hive_base::ldc::{Message, Role, Value};
use uuid::Uuid;

fn bench_ipc_validation(c: &mut Criterion) {
    let id = Uuid::new_v4();
    let valid_msg = Message::belief(id, Role::Worker, "test_asset".into(), Value::Bool(true), 0.95);

    c.bench_function("ipc_validate_valid_message", |b| {
        b.iter(|| {
            let result = validate_message(black_box(&valid_msg));
            black_box(result.valid);
        })
    });

    // Invalid: NaN confidence
    let invalid_msg = Message::belief(id, Role::Worker, "test".into(), Value::Float(1.0), f32::NAN);
    c.bench_function("ipc_validate_invalid_message", |b| {
        b.iter(|| {
            let result = validate_message(black_box(&invalid_msg));
            black_box(result.errors.len());
        })
    });
}

criterion_group!(ipc_benches, bench_ipc_validation);
criterion_main!(ipc_benches);
