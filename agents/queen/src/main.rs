use hive_base::{AgentIdentity, ConsensusEngine, HiveChamber, Message, Payload, Role};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};
use uuid::Uuid;

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
    last_tournament_gen: usize,
}

impl OvermindAgent {
    async fn new() -> Self {
        let identity = AgentIdentity::new();
        let comms = HiveChamber::connect(&identity, Role::Queen)
            .await
            .expect("Failed to connect to colmena arena");

        info!("Queen connected to shared-memory arena");

        Self {
            comms, identity,
            consensus: ConsensusEngine::new(0.66),
            ollama_url: "http://localhost:11434".to_string(),
            model: "tinyllama".to_string(),
            heartbeat_interval: Duration::from_secs(10),
            tournament: hive_base::tournament::Tournament::new(),
            hivemind: hive_base::hivemind::HiveMind::new(),
            last_tournament_gen: 0,
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
                Payload::Belief { asset, value: _value, confidence: _confidence } => {
                    // Check for HiveMind proposals in beliefs
                    if asset.starts_with("hivemind:") {
                        info!("HiveMind: received proposal belief: {}", asset);
                    }
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
                let msg = self.hivemind.to_belief(
                    &self.hivemind.directives.iter()
                        .find(|d| d.directive_id == executed_id).unwrap(),
                    self.identity.id(),
                );
                self.publish_msg(msg).await;
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

    async fn run(&mut self) {
        info!("Hive Queen starting | ID: {}", self.identity.id());
        info!("Ollama: {} | Model: {}", self.ollama_url, self.model);
        self.send_heartbeat().await;

        let mut heartbeat_timer = time::interval(self.heartbeat_interval);
        let mut tournament_timer = time::interval(Duration::from_secs(600));
        let mut hivemind_timer = time::interval(Duration::from_secs(120));

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
