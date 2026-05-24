#![no_main]
use libfuzzer_sys::fuzz_target;
use hive_base::ipc_contract::validate_message;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = serde_json::from_slice::<hive_base::ldc::Message>(data) {
        let result = validate_message(&msg);
        // Should not panic, should always return a valid result
        assert!(result.valid || !result.errors.is_empty());
    }
    if let Ok(msg) = rmp_serde::from_slice::<hive_base::ldc::Message>(data) {
        let result = validate_message(&msg);
        assert!(result.valid || !result.errors.is_empty());
    }
});
