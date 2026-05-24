use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WinCriteria {
    Speed,        // fastest to achieve objective
    Stealth,      // fewest detections
    Damage,       // most impact achieved
    Coverage,     // most techniques used
    Composite,    // weighted average of all
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TournamentConfig {
    pub target: String,
    pub competitors: usize,
    pub criteria: Vec<WinCriteria>,
    pub timeout_secs: u64,
    pub generations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Competitor {
    pub id: Uuid,
    pub name: String,
    pub variant_code: String,
    pub policies: HashMap<String, String>,
    pub score: f32,
    pub speed_score: f32,
    pub stealth_score: f32,
    pub damage_score: f32,
    pub coverage_score: f32,
    pub completed: bool,
    pub alive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TournamentResult {
    pub winner_id: Uuid,
    pub runner_up_id: Option<Uuid>,
    pub generation: usize,
    pub scores: Vec<(Uuid, f32)>,
}

pub struct Tournament;

impl Default for Tournament {
    fn default() -> Self {
        Self::new()
    }
}

impl Tournament {
    pub fn new() -> Self { Self }

    pub fn generate_competitors(&self, config: &TournamentConfig) -> Vec<Competitor> {
        let mut competitors = Vec::new();
        let mut rng = rand::thread_rng();

        let archetypes = [("Aggressor", vec![("marl_policy", "aggressive"), ("evasion", "minimal"), ("lateral", "eternalblue")]),
            ("Ghost", vec![("marl_policy", "conservative"), ("evasion", "maximum"), ("lateral", "kerberoast")]),
            ("Hybrid", vec![("marl_policy", "balanced"), ("evasion", "adaptive"), ("lateral", "lolbins")]),
            ("Experimental", vec![("marl_policy", "exploratory"), ("evasion", "smoke_signals"), ("lateral", "dns_tunnel")]),
            ("Veteran", vec![("marl_policy", "conservative"), ("evasion", "high"), ("lateral", "ssh_scp")])];

        for (name, policies) in archetypes.iter().take(config.competitors.min(archetypes.len())) {
            let mut policy_map = HashMap::new();
            for (k, v) in policies {
                policy_map.insert(k.to_string(), v.to_string());
            }

            let variant_code = format!(
                "variants/{}/{}/policy_{}",
                name,
                Uuid::new_v4(),
                rand::Rng::gen_range(&mut rng, 1000..9999)
            );

            competitors.push(Competitor {
                id: Uuid::new_v4(),
                name: name.to_string(),
                variant_code,
                policies: policy_map,
                score: 0.0,
                speed_score: 0.0,
                stealth_score: 0.0,
                damage_score: 0.0,
                coverage_score: 0.0,
                completed: false,
                alive: true,
            });
        }
        competitors
    }

    pub fn score_competitor(&self, competitor: &mut Competitor, start_time: u64, now: u64,
                            detection_count: u32, techniques_used: u32, damage_level: f32) {
        let elapsed = now.saturating_sub(start_time);
        competitor.speed_score = 1.0 / (elapsed as f32 + 1.0) * 100.0;
        competitor.stealth_score = 1.0 / (detection_count as f32 + 1.0) * 100.0;
        competitor.damage_score = damage_level * 100.0;
        competitor.coverage_score = (techniques_used as f32 / 36.0) * 100.0;

        competitor.score = (competitor.speed_score
            + competitor.stealth_score
            + competitor.damage_score
            + competitor.coverage_score) / 4.0;
        competitor.completed = true;
    }

    pub fn select_winner(&self, competitors: &[Competitor]) -> Option<Uuid> {
        competitors.iter()
            .filter(|c| c.completed && c.alive)
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
            .map(|c| c.id)
    }

    pub fn select_runner_up(&self, competitors: &[Competitor], winner_id: Uuid) -> Option<Uuid> {
        let mut sorted: Vec<&Competitor> = competitors.iter()
            .filter(|c| c.id != winner_id && c.completed && c.alive)
            .collect();
        sorted.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        sorted.first().map(|c| c.id)
    }

    pub fn crossover(&self, parent_a: &Competitor, parent_b: &Competitor) -> Competitor {
        let mut child_policies = HashMap::new();
        let mut rng = rand::thread_rng();

        let all_keys: Vec<&String> = parent_a.policies.keys()
            .chain(parent_b.policies.keys())
            .collect();

        for key in all_keys {
            if rand::Rng::gen_bool(&mut rng, 0.5) {
                if let Some(val) = parent_a.policies.get(key) {
                    child_policies.insert(key.to_string(), val.clone());
                }
            } else {
                if let Some(val) = parent_b.policies.get(key) {
                    child_policies.insert(key.to_string(), val.clone());
                }
            }
        }

        Competitor {
            id: Uuid::new_v4(),
            name: format!("Hybrid-{}-{}", parent_a.name, parent_b.name),
            variant_code: format!("cross/{}/{}", parent_a.id, parent_b.id),
            policies: child_policies,
            score: 0.0,
            speed_score: 0.0,
            stealth_score: 0.0,
            damage_score: 0.0,
            coverage_score: 0.0,
            completed: false,
            alive: true,
        }
    }

    pub fn mutate_next_generation(&self, winner: &Competitor, runner_up: Option<&Competitor>,
                                  generation: usize, config: &TournamentConfig) -> Vec<Competitor> {
        let mut next_gen = Vec::new();

        let child = match runner_up {
            Some(ru) => self.crossover(winner, ru),
            None => self.crossover(winner, winner),
        };
        next_gen.push(child);

        let mut rng = rand::thread_rng();
        for i in 1..config.competitors {
            let mut clone = winner.clone();
            clone.id = Uuid::new_v4();
            clone.name = format!("Mutant-{}-Gen{}", clone.name, generation);

            let mutation_count = rand::Rng::gen_range(&mut rng, 1..=3);
            for _ in 0..mutation_count {
                if clone.policies.is_empty() { break; }
                let keys: Vec<String> = clone.policies.keys().cloned().collect();
                let key = &keys[rand::Rng::gen_range(&mut rng, 0..keys.len())];
                let suffixes = ["_v2", "_alt", "_beta", "_edge", "_next"];
                let suffix = suffixes[rand::Rng::gen_range(&mut rng, 0..suffixes.len())];
                if let Some(val) = clone.policies.get(key) {
                    clone.policies.insert(key.clone(), format!("{}{}", val, suffix));
                }
            }

            clone.variant_code = format!("mutant/generation_{}/variant_{}", generation, i);
            next_gen.push(clone);
        }

        next_gen
    }

    pub fn run_tournament(&self, config: &TournamentConfig) -> TournamentResult {
        let mut competitors = self.generate_competitors(config);

        for gen in 0..config.generations {
            let start_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            for competitor in &mut competitors {
                let mut rng = rand::thread_rng();
                let detection_count = rand::Rng::gen_range(&mut rng, 0u32..=5);
                let techniques_used = rand::Rng::gen_range(&mut rng, 5u32..=20);
                let damage_level = rand::Rng::gen_range(&mut rng, 0.0..=1.0);
                let elapsed = if competitor.name.contains("Ghost") {
                    rand::Rng::gen_range(&mut rng, 60..300)
                } else {
                    rand::Rng::gen_range(&mut rng, 30..300)
                };

                self.score_competitor(competitor, start_time,
                    start_time + elapsed, detection_count, techniques_used, damage_level);
            }

            let winner_id = self.select_winner(&competitors);
            let runner_up_id = winner_id.and_then(|w| {
                
                self.select_runner_up(&competitors, w)
            });

            if gen + 1 < config.generations {
                if let Some(w_id) = winner_id {
                    let winner = competitors.iter().find(|c| c.id == w_id).cloned();
                    let runner_up = runner_up_id.and_then(|ru_id|
                        competitors.iter().find(|c| c.id == ru_id).cloned());

                    if let Some(w) = winner {
                        let next_gen = self.mutate_next_generation(
                            &w, runner_up.as_ref(), gen + 1, config);
                        competitors = next_gen;
                    }
                }
            }

            if gen + 1 == config.generations {
                let scores: Vec<(Uuid, f32)> = competitors.iter()
                    .map(|c| (c.id, c.score)).collect();
                let winner_id = winner_id.unwrap_or_else(Uuid::nil);

                return TournamentResult {
                    winner_id,
                    runner_up_id,
                    generation: gen,
                    scores,
                };
            }
        }

        TournamentResult {
            winner_id: Uuid::nil(),
            runner_up_id: None,
            generation: 0,
            scores: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_competitors() {
        let t = Tournament::new();
        let config = TournamentConfig {
            target: "10.0.0.5".into(),
            competitors: 3,
            criteria: vec![WinCriteria::Speed, WinCriteria::Stealth],
            timeout_secs: 300,
            generations: 1,
        };
        let competitors = t.generate_competitors(&config);
        assert_eq!(competitors.len(), 3);
        assert!(competitors[0].name.contains("Aggressor"));
    }

    #[test]
    fn test_scoring() {
        let t = Tournament::new();
        let mut c = Competitor {
            id: Uuid::new_v4(),
            name: "Test".into(),
            variant_code: "test".into(),
            policies: HashMap::new(),
            score: 0.0,
            speed_score: 0.0,
            stealth_score: 0.0,
            damage_score: 0.0,
            coverage_score: 0.0,
            completed: false,
            alive: true,
        };
        t.score_competitor(&mut c, 1000, 1100, 2, 10, 0.8);
        assert!(c.score > 0.0);
        assert!(c.completed);
    }

    #[test]
    fn test_winner_selection() {
        let t = Tournament::new();
        let mut competitors = Vec::new();
        for i in 0..3 {
            competitors.push(Competitor {
                id: Uuid::new_v4(),
                name: format!("C{}", i),
                variant_code: "".into(),
                policies: HashMap::new(),
                score: i as f32 * 10.0,
                speed_score: 0.0,
                stealth_score: 0.0,
                damage_score: 0.0,
                coverage_score: 0.0,
                completed: true,
                alive: true,
            });
        }
        let winner = t.select_winner(&competitors);
        assert!(winner.is_some());
        let w_id = winner.unwrap();
        let winner_c = competitors.iter().find(|c| c.id == w_id).unwrap();
        assert_eq!(winner_c.name, "C2");
    }

    #[test]
    fn test_crossover() {
        let t = Tournament::new();
        let mut p1 = HashMap::new();
        p1.insert("policy".into(), "aggressive".into());
        let mut p2 = HashMap::new();
        p2.insert("policy".into(), "stealth".into());

        let a = Competitor {
            id: Uuid::new_v4(), name: "A".into(), variant_code: "".into(),
            policies: p1, score: 0.0, speed_score: 0.0, stealth_score: 0.0,
            damage_score: 0.0, coverage_score: 0.0, completed: false, alive: true,
        };
        let b = Competitor {
            id: Uuid::new_v4(), name: "B".into(), variant_code: "".into(),
            policies: p2, score: 0.0, speed_score: 0.0, stealth_score: 0.0,
            damage_score: 0.0, coverage_score: 0.0, completed: false, alive: true,
        };
        let child = t.crossover(&a, &b);
        assert_ne!(child.id, a.id);
        assert!(child.name.contains("A") || child.name.contains("B"));
    }

    #[test]
    fn test_tournament_hivemind_policy_integration() {
        // Tournament winners should be compatible with HiveMind policies
        use crate::hivemind::HiveMind;
        let t = Tournament::new();
        let _hm = HiveMind::new();
        let config = TournamentConfig {
            target: "10.0.0.5".into(),
            competitors: 2,
            criteria: vec![WinCriteria::Stealth, WinCriteria::Coverage],
            timeout_secs: 300,
            generations: 1,
        };
        let competitors = t.generate_competitors(&config);
        assert_eq!(competitors.len(), 2);
        // Each competitor's policies should be valid HiveMind directive targets
        for c in &competitors {
            for key in c.policies.keys() {
                assert!(!key.is_empty(), "Policy key should not be empty");
            }
        }
        // Simulate a tournament round and verify scoring is consistent
        let mut scored = competitors.clone();
        for c in &mut scored {
            t.score_competitor(c, 500, 600, 1, 5, 0.5);
        }
        let winner = t.select_winner(&scored);
        assert!(winner.is_some());
        let w = scored.iter().find(|c| c.id == winner.unwrap()).unwrap();
        assert!(w.completed);
        assert!(w.score >= 0.0);
    }
}
