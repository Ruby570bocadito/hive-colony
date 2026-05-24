use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter("swarm_run=info")
        .init();

    let cfg = hive_base::config::HiveConfig::load();

    if cfg.colony.aggressive {
        info!("=== SWARM COLONY MODE (AGGRESSIVE) ===");
        info!("Scan subnets: {:?}", cfg.colony.scan_subnets);
        info!("Safe IPs: {:?}", cfg.brain.safe_ips);
    } else {
        info!("=== SWARM INTEGRATION TEST ===");
    }

    let arena_name = hive_base::shared_arena::generate_arena_name();
    info!("Arena: {}", arena_name);

    info!("Launching agents...");
    let mut scout = spawn_agent("worker", &arena_name);
    thread::sleep(Duration::from_secs(2));
    let mut shaper = spawn_agent("drone", &arena_name);
    thread::sleep(Duration::from_millis(500));
    let mut hoarder = spawn_agent("honeybee", &arena_name);
    thread::sleep(Duration::from_millis(500));
    let mut weaver = spawn_agent("weaver", &arena_name);
    thread::sleep(Duration::from_millis(500));
    let mut overmind = spawn_agent("queen", &arena_name);

    // Colony mode: also launch Worm
    let worm = if cfg.colony.aggressive {
        thread::sleep(Duration::from_millis(500));
        info!("  worm agent starting (autonomous spread)...");
        Some(spawn_agent("swarm", &arena_name))
    } else {
        info!("  worm agent SKIPPED (colony.aggressive=false)");
        None
    };

    let duration = if cfg.colony.aggressive { 120 } else { 30 };
    info!("All agents launched. Running {}s...", duration);
    thread::sleep(Duration::from_secs(duration));

    info!("Shutting down...");
    let _ = scout.kill();
    let _ = scout.wait();
    let _ = shaper.kill();
    let _ = shaper.wait();
    let _ = hoarder.kill();
    let _ = hoarder.wait();
    let _ = weaver.kill();
    let _ = weaver.wait();
    let _ = overmind.kill();
    let _ = overmind.wait();
    if let Some(mut w) = worm {
        let _ = w.kill();
        let _ = w.wait();
    }
    info!("Done.");
}

fn spawn_agent(name: &str, arena_name: &str) -> Child {
    info!("  {} agent starting...", name);
    Command::new("cargo")
        .args(["run", "-p", name, "--quiet"])
        .env("__HIVE_ARENA", arena_name)
        .env("RUST_LOG", format!("{}=info", name))
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn {}: {}", name, e))
}
