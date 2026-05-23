use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub edr_process_count: u32,
    pub total_processes: u32,
    pub uptime_hours: u64,
    pub firewall_rules: u32,
    pub logged_in_users: u32,
    pub listening_ports: u32,
    pub has_defender: bool,
    pub has_sentinelone: bool,
    pub has_crowdstrike: bool,
    pub has_carbonblack: bool,
    pub has_symantec: bool,
    pub is_vm: bool,
    pub is_domain_controller: bool,
    pub is_server_os: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionPrediction {
    pub probability: f32,              // 0.0-1.0
    pub estimated_soc_response_secs: u64,
    pub most_likely_vector: String,    // "network" | "endpoint" | "behavioral" | "log"
    pub confidence: f32,               // 0.0-1.0
}

pub struct Seer {
    model: SimplePredictor,
}

struct SimplePredictor {
    weights: HashMap<String, f32>,
}

impl Seer {
    pub fn new() -> Self {
        Self {
            model: SimplePredictor::default(),
        }
    }

    pub fn predict_detection(&self, telemetry: &TelemetrySample, action: &str) -> DetectionPrediction {
        let base_risk = self.model.base_risk_for_action(action);
        let edr_risk = self.model.edr_risk_score(telemetry);
        let env_risk = self.model.env_risk_score(telemetry);

        let raw_probability = (base_risk + edr_risk + env_risk) / 3.0;
        let probability = raw_probability.clamp(0.0, 1.0);

        let response_time = match telemetry {
            t if t.has_crowdstrike || t.has_sentinelone => {
                if t.is_domain_controller { 120 } else { 300 }
            }
            t if t.has_defender => {
                if t.is_domain_controller { 300 } else { 600 }
            }
            _ => 900,
        };

        let vector = self.predict_vector(telemetry, action);

        DetectionPrediction {
            probability,
            estimated_soc_response_secs: response_time,
            most_likely_vector: vector,
            confidence: if telemetry.total_processes > 50 { 0.85 } else { 0.65 },
        }
    }

    pub fn should_proceed(&self, prediction: &DetectionPrediction, threshold: f32) -> bool {
        prediction.probability < threshold
    }

    fn predict_vector(&self, telemetry: &TelemetrySample, action: &str) -> String {
        let has_edr = telemetry.has_crowdstrike || telemetry.has_sentinelone
            || telemetry.has_defender || telemetry.has_carbonblack;

        if action.contains("scan") || action.contains("port") {
            if telemetry.firewall_rules > 10 {
                return "network".into();
            }
        }
        if action.contains("exfil") || action.contains("upload") {
            if telemetry.listening_ports > 5 {
                return "network".into();
            }
        }
        if action.contains("exec") || action.contains("run") || action.contains("process") {
            if has_edr {
                return "endpoint".into();
            }
        }
        if action.contains("ssh") || action.contains("scp") {
            if telemetry.logged_in_users > 2 {
                return "log".into();
            }
        }
        if action.contains("persist") || action.contains("boot") {
            if telemetry.is_vm {
                return "behavioral".into();
            }
        }
        "behavioral".into()
    }

    pub fn ingest_telemetry(&self, _samples: Vec<TelemetrySample>) {
        // Future: online learning to refine weights
    }
}

impl SimplePredictor {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert("scan".into(), 0.3);
        weights.insert("exec".into(), 0.6);
        weights.insert("exfil".into(), 0.8);
        weights.insert("persist".into(), 0.5);
        weights.insert("ssh".into(), 0.4);
        weights.insert("exploit".into(), 0.9);
        weights.insert("mutate".into(), 0.2);
        weights.insert("default".into(), 0.5);
        Self { weights }
    }

    fn base_risk_for_action(&self, action: &str) -> f32 {
        let action_lower = action.to_lowercase();
        for (key, val) in &self.weights {
            if action_lower.contains(key) {
                return *val;
            }
        }
        self.weights.get("default").copied().unwrap_or(0.5)
    }

    fn edr_risk_score(&self, telemetry: &TelemetrySample) -> f32 {
        let mut score = 0.0;
        let mut count = 0;

        if telemetry.has_crowdstrike { score += 0.9; count += 1; }
        if telemetry.has_sentinelone { score += 0.85; count += 1; }
        if telemetry.has_defender { score += 0.6; count += 1; }
        if telemetry.has_carbonblack { score += 0.8; count += 1; }
        if telemetry.has_symantec { score += 0.5; count += 1; }

        if count > 0 { score / count as f32 } else { 0.2 }
    }

    fn env_risk_score(&self, telemetry: &TelemetrySample) -> f32 {
        let mut score = 0.3;

        if telemetry.is_domain_controller { score += 0.3; }
        if telemetry.is_server_os { score += 0.2; }
        if telemetry.is_vm { score += 0.1; }
        if telemetry.logged_in_users > 5 { score += 0.1; }
        if telemetry.firewall_rules > 20 { score += 0.1; }
        if telemetry.edr_process_count > 0 {
            score += (telemetry.edr_process_count as f32) * 0.1;
        }

        score.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_telemetry() -> TelemetrySample {
        TelemetrySample {
            edr_process_count: 2,
            total_processes: 120,
            uptime_hours: 720,
            firewall_rules: 15,
            logged_in_users: 3,
            listening_ports: 8,
            has_defender: true,
            has_sentinelone: false,
            has_crowdstrike: true,
            has_carbonblack: false,
            has_symantec: false,
            is_vm: false,
            is_domain_controller: true,
            is_server_os: true,
        }
    }

    #[test]
    fn test_prediction_high_risk() {
        let seer = Seer::new();
        let telemetry = sample_telemetry();
        let prediction = seer.predict_detection(&telemetry, "exploit eternalblue");
        assert!(prediction.probability > 0.5, "High risk action should have >0.5 probability");
        assert!(prediction.estimated_soc_response_secs > 0);
    }

    #[test]
    fn test_prediction_low_risk() {
        let seer = Seer::new();
        let telemetry = sample_telemetry();
        let prediction = seer.predict_detection(&telemetry, "scan localhost");
        assert!(prediction.probability < 0.8, "Scan should be lower risk");
    }

    #[test]
    fn test_should_proceed() {
        let seer = Seer::new();
        let pred = DetectionPrediction {
            probability: 0.3,
            estimated_soc_response_secs: 600,
            most_likely_vector: "endpoint".into(),
            confidence: 0.8,
        };
        assert!(seer.should_proceed(&pred, 0.5));
        assert!(!seer.should_proceed(&pred, 0.2));
    }
}
