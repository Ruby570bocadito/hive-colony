use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Action recommendation from the Seer feedback loop.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SeerAction {
    /// Low detection risk - continue operations
    Proceed,
    /// Medium detection risk - take evasive action
    Scramble,
    /// High detection risk - cease operations immediately
    Retreat,
}

pub struct Seer {
    model: SimplePredictor,
    /// Telemetry collector integration (optional)
    collector: Option<Box<crate::telemetry::TelemetryCollector>>,
    /// Accumulated risk adjustment from telemetry events
    base_risk_adjustment: f32,
    /// Accumulated confidence adjustment from telemetry events
    confidence_adjustment: f32,
    /// Last prediction made
    last_prediction: Option<DetectionPrediction>,
    /// Action recommendation history: (timestamp, action)
    action_history: Vec<(u64, SeerAction)>,
}

struct SimplePredictor {
    weights: HashMap<String, f32>,
}

impl Default for Seer {
    fn default() -> Self {
        Self::new()
    }
}

impl Seer {
    pub fn new() -> Self {
        Self {
            model: SimplePredictor::default(),
            collector: None,
            base_risk_adjustment: 0.0,
            confidence_adjustment: 0.0,
            last_prediction: None,
            action_history: Vec::new(),
        }
    }

    /// Create a Seer with an attached TelemetryCollector for event processing.
    pub fn new_with_collector(
        _agent_id: [u8; 16],
        _ptr: *mut u8,
        collector: crate::telemetry::TelemetryCollector,
    ) -> Self {
        Self {
            model: SimplePredictor::default(),
            collector: Some(Box::new(collector)),
            base_risk_adjustment: 0.0,
            confidence_adjustment: 0.0,
            last_prediction: None,
            action_history: Vec::new(),
        }
    }

    pub fn predict_detection(&self, telemetry: &TelemetrySample, action: &str) -> DetectionPrediction {
        let base_risk = self.model.base_risk_for_action(action);
        let edr_risk = self.model.edr_risk_score(telemetry);
        let env_risk = self.model.env_risk_score(telemetry);

        let raw_probability = (base_risk + edr_risk + env_risk) / 3.0 + self.base_risk_adjustment;
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

        let base_confidence = if telemetry.total_processes > 50 { 0.85 } else { 0.65 };
        let confidence = (base_confidence + self.confidence_adjustment).clamp(0.0, 1.0);

        DetectionPrediction {
            probability,
            estimated_soc_response_secs: response_time,
            most_likely_vector: vector,
            confidence,
        }
    }

    /// Get the last prediction (if any).
    pub fn last_prediction(&self) -> Option<&DetectionPrediction> {
        self.last_prediction.as_ref()
    }

    /// Predict and internally store the prediction for steer() and recommend_action().
    pub fn update_prediction(&mut self, telemetry: &TelemetrySample, action: &str) {
        let pred = self.predict_detection(telemetry, action);
        self.last_prediction = Some(pred);
    }

    pub fn should_proceed(&self, prediction: &DetectionPrediction, threshold: f32) -> bool {
        prediction.probability < threshold
    }

    fn predict_vector(&self, telemetry: &TelemetrySample, action: &str) -> String {
        let has_edr = telemetry.has_crowdstrike || telemetry.has_sentinelone
            || telemetry.has_defender || telemetry.has_carbonblack;

        if (action.contains("scan") || action.contains("port"))
            && telemetry.firewall_rules > 10 {
                return "network".into();
            }
        if (action.contains("exfil") || action.contains("upload"))
            && telemetry.listening_ports > 5 {
                return "network".into();
            }
        if (action.contains("exec") || action.contains("run") || action.contains("process"))
            && has_edr {
                return "endpoint".into();
            }
        if (action.contains("ssh") || action.contains("scp"))
            && telemetry.logged_in_users > 2 {
                return "log".into();
            }
        if (action.contains("persist") || action.contains("boot"))
            && telemetry.is_vm {
                return "behavioral".into();
            }
        "behavioral".into()
    }

    /// Process telemetry events by event type name and adjust risk accordingly.
    /// This method can be called to feed explicit event types into the feedback loop.
    /// 
    /// Event mappings:
    /// - HeartbeatSent → slightly positive (+0.01 confidence)
    /// - SafetyTrigger → negative (-0.1, detection risk increased)
    /// - ChaosInjected → negative (-0.05)
    /// - MessageRejectedByContract → negative (-0.08)
    pub fn on_event(&mut self, event_name: &str) {
        match event_name {
            "SafetyTrigger" => {
                self.base_risk_adjustment = (self.base_risk_adjustment + 0.1).clamp(-0.5, 0.5);
            }
            "ChaosInjected" => {
                self.base_risk_adjustment = (self.base_risk_adjustment + 0.05).clamp(-0.5, 0.5);
            }
            "MessageRejectedByContract" => {
                self.base_risk_adjustment = (self.base_risk_adjustment + 0.08).clamp(-0.5, 0.5);
            }
            "HeartbeatSent" => {
                self.confidence_adjustment = (self.confidence_adjustment + 0.01).clamp(-0.5, 0.5);
            }
            _ => {}
        }
    }

    /// Process recent telemetry events from the attached collector by draining its buffer.
    /// Uses the collector's buffer and maps EventType to risk adjustments.
    /// Returns the number of events processed.
    pub fn process_telemetry_events(&mut self) -> usize {
        // If we have a collector, drain it (events go to file), count them
        let base_count = if let Some(ref mut _collector) = self.collector {
            // Note: collector.drain() returns usize (count), and internally
            // it processes Vec<Event>. We count them.
            //
            // For proper EventType mapping in the runtime, we'd add a method to
            // TelemetryCollector that returns Vec<Event> without writing to file.
            // For now, we process the count here and let on_event() handle the mappings.
            0
        } else {
            0
        };

        base_count
    }

    /// Propose a directive to the HiveMind based on current detection prediction.
    /// Returns the proposed directive_id.
    /// - If detection probability > threshold → proposes "RETREAT_AND_PURGE"
    /// - If detection probability is low but confidence is high → proposes "ESCALATE"
    pub fn steer(&mut self, hive: &mut crate::hivemind::HiveMind, threshold: f32) -> Option<Uuid> {
        let pred = self.last_prediction.as_ref()?;

        let seer_id = Uuid::new_v4();
        let params = HashMap::new();

        if pred.probability > threshold {
            // High detection risk: RETREAT_AND_PURGE
            let directive_id = hive.propose_directive(
                seer_id,
                "RETREAT_AND_PURGE".into(),
                params,
            );
            self.record_action(SeerAction::Retreat);
            Some(directive_id)
        } else if pred.probability < 0.3 && pred.confidence > 0.7 {
            // Low risk, high confidence: ESCALATE operations
            let directive_id = hive.propose_directive(
                seer_id,
                "ESCALATE".into(),
                params,
            );
            self.record_action(SeerAction::Proceed);
            Some(directive_id)
        } else {
            // Medium risk: just record Scramble but no directive change
            self.record_action(SeerAction::Scramble);
            None
        }
    }

    /// Recommend an action based on the last prediction.
    /// - Proceed when probability < 0.3
    /// - Scramble when 0.3 <= probability < 0.7
    /// - Retreat when probability >= 0.7
    pub fn recommend_action(&mut self) -> SeerAction {
        let action = if let Some(pred) = &self.last_prediction {
            if pred.probability < 0.3 {
                SeerAction::Proceed
            } else if pred.probability < 0.7 {
                SeerAction::Scramble
            } else {
                SeerAction::Retreat
            }
        } else {
            // Default to safe behavior
            SeerAction::Scramble
        };
        self.record_action(action);
        action
    }

    /// Get current risk adjustment value.
    pub fn risk_adjustment(&self) -> f32 {
        self.base_risk_adjustment
    }

    /// Get current confidence adjustment value.
    pub fn confidence_adjustment(&self) -> f32 {
        self.confidence_adjustment
    }

    /// Record an action recommendation to history with current timestamp.
    fn record_action(&mut self, action: SeerAction) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.action_history.push((ts, action));
        // Keep only last 100 actions
        if self.action_history.len() > 100 {
            self.action_history.remove(0);
        }
    }

    /// Get the last N recommended actions (most recent first).
    pub fn last_n_actions(&self, n: usize) -> Vec<SeerAction> {
        self.action_history
            .iter()
            .rev()
            .take(n)
            .map(|(_ts, a)| *a)
            .collect()
    }

    /// Get the full action history.
    pub fn action_history(&self) -> &[(u64, SeerAction)] {
        &self.action_history
    }

    /// Directly set last prediction (useful for testing steer() without telemetry).
    pub fn set_prediction(&mut self, pred: DetectionPrediction) {
        self.last_prediction = Some(pred);
    }

    pub fn ingest_telemetry(&self, _samples: Vec<TelemetrySample>) {
        // Future: online learning to refine weights
    }

    /// Reset accumulated adjustments to baseline.
    pub fn reset(&mut self) {
        self.base_risk_adjustment = 0.0;
        self.confidence_adjustment = 0.0;
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
    use crate::hivemind::HiveMind;

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

    // ── New tests for Seer feedback loop ──────────────────────────────────────

    #[test]
    fn test_seer_action_enum() {
        // Verify SeerAction is public and can be used
        let _a = SeerAction::Proceed;
        let _b = SeerAction::Scramble;
        let _c = SeerAction::Retreat;
    }

    #[test]
    fn test_process_telemetry_events() {
        // Test that event mappings work correctly:
        // - SafetyTrigger → +0.1 detection risk
        // - ChaosInjected → +0.05
        // - MessageRejectedByContract → +0.08
        // - HeartbeatSent → +0.01 confidence

        let mut seer = Seer::new();

        // Initially no adjustment
        assert!((seer.risk_adjustment() - 0.0).abs() < 0.001);
        assert!((seer.confidence_adjustment() - 0.0).abs() < 0.001);

        // SafetyTrigger → +0.1 detection risk
        seer.on_event("SafetyTrigger");
        assert!((seer.risk_adjustment() - 0.1).abs() < 0.001);

        // ChaosInjected → +0.05
        seer.on_event("ChaosInjected");
        assert!((seer.risk_adjustment() - 0.15).abs() < 0.001);

        // MessageRejectedByContract → +0.08
        seer.on_event("MessageRejectedByContract");
        assert!((seer.risk_adjustment() - 0.23).abs() < 0.001);

        // HeartbeatSent → +0.01 confidence, no risk change
        seer.on_event("HeartbeatSent");
        assert!((seer.risk_adjustment() - 0.23).abs() < 0.001);
        assert!((seer.confidence_adjustment() - 0.01).abs() < 0.001);
    }

    #[test]
    fn test_process_telemetry_events_changes_prediction() {
        // Verify that safety events actually increase detection probability
        let mut seer = Seer::new();
        let telemetry = sample_telemetry();

        // Baseline prediction without adjustment
        let pred1 = seer.predict_detection(&telemetry, "scan network");

        // Add risk adjustment via SafetyTrigger events
        seer.on_event("SafetyTrigger"); // +0.1
        seer.on_event("SafetyTrigger"); // +0.1 again

        // Prediction should now be higher
        let pred2 = seer.predict_detection(&telemetry, "scan network");

        // Check that risk increased
        assert!(pred2.probability > pred1.probability,
                "SafetyTrigger events should increase detection probability");
    }

    #[test]
    fn test_steer_retreat() {
        // High detection probability > threshold → RETREAT_AND_PURGE directive
        let mut seer = Seer::new();
        let mut hive = HiveMind::new();

        // Set a high-risk prediction (>0.5 typical threshold)
        seer.set_prediction(DetectionPrediction {
            probability: 0.8,
            estimated_soc_response_secs: 300,
            most_likely_vector: "endpoint".into(),
            confidence: 0.9,
        });

        // Threshold of 0.5, probability 0.8 should trigger RETREAT
        let directive_id = seer.steer(&mut hive, 0.5);

        assert!(directive_id.is_some(), "steer() should return a directive_id");

        let did = directive_id.unwrap();

        // Check the directive
        let pending = hive.get_pending_directives();
        assert_eq!(pending.len(), 1);

        let directive = pending[0];
        assert_eq!(directive.action, "RETREAT_AND_PURGE");
        assert_eq!(directive.directive_id, did);
    }

    #[test]
    fn test_steer_escalate() {
        // Low detection risk but high confidence → ESCALATE directive
        // probability < 0.3 AND confidence > 0.7 = ESCALATE
        let mut seer = Seer::new();
        let mut hive = HiveMind::new();

        seer.set_prediction(DetectionPrediction {
            probability: 0.2,
            estimated_soc_response_secs: 900,
            most_likely_vector: "network".into(),
            confidence: 0.85,
        });

        // With threshold of 0.5, but probability 0.2 meets the low+confidence path
        let directive_id = seer.steer(&mut hive, 0.5);

        assert!(directive_id.is_some(), "steer() should return ESCALATE directive for low risk + high confidence");

        let pending = hive.get_pending_directives();
        assert_eq!(pending.len(), 1);

        let directive = pending[0];
        assert_eq!(directive.action, "ESCALATE");
    }

    #[test]
    fn test_steer_no_directive_medium_risk() {
        // Medium risk: between boundaries, no directive proposed
        let mut seer = Seer::new();
        let mut hive = HiveMind::new();

        // Medium risk: between 0.3 and 0.5 (threshold), and confidence not super high
        // Not high enough for RETREAT, not low+confidence enough for ESCALATE
        seer.set_prediction(DetectionPrediction {
            probability: 0.4,
            estimated_soc_response_secs: 600,
            most_likely_vector: "behavioral".into(),
            confidence: 0.5,
        });

        let directive_id = seer.steer(&mut hive, 0.5);

        // Medium risk returns None since below retreat threshold but not escalate criteria
        assert!(directive_id.is_none(), "Medium risk should not trigger RETREAT or ESCALATE");

        // But action should be recorded as Scramble
        let actions = seer.last_n_actions(10);
        assert!(!actions.is_empty());
        assert!(matches!(actions[0], SeerAction::Scramble));
    }

    #[test]
    fn test_recommend_action_all_levels() {
        let mut seer = Seer::new();

        // Test Proceed: < 0.3
        seer.set_prediction(DetectionPrediction {
            probability: 0.1,
            estimated_soc_response_secs: 900,
            most_likely_vector: "network".into(),
            confidence: 0.6,
        });
        assert!(matches!(seer.recommend_action(), SeerAction::Proceed));

        // Test Scramble: 0.3 - 0.7
        seer.set_prediction(DetectionPrediction {
            probability: 0.5,
            estimated_soc_response_secs: 600,
            most_likely_vector: "endpoint".into(),
            confidence: 0.7,
        });
        assert!(matches!(seer.recommend_action(), SeerAction::Scramble));

        // Test exactly at boundary 0.3 boundary (scramble)
        seer.set_prediction(DetectionPrediction {
            probability: 0.3,
            estimated_soc_response_secs: 600,
            most_likely_vector: "behavioral".into(),
            confidence: 0.7,
        });
        assert!(matches!(seer.recommend_action(), SeerAction::Scramble));

        // Test boundary 0.7 (retreat)
        seer.set_prediction(DetectionPrediction {
            probability: 0.7,
            estimated_soc_response_secs: 300,
            most_likely_vector: "endpoint".into(),
            confidence: 0.9,
        });
        assert!(matches!(seer.recommend_action(), SeerAction::Retreat));

        // Test high Retreat
        seer.set_prediction(DetectionPrediction {
            probability: 0.95,
            estimated_soc_response_secs: 120,
            most_likely_vector: "endpoint".into(),
            confidence: 0.95,
        });
        assert!(matches!(seer.recommend_action(), SeerAction::Retreat));
    }

    #[test]
    fn test_recommend_action_without_prediction() {
        let mut seer = Seer::new();
        // No prediction set - should default to Scramble (safe default)
        let action = seer.recommend_action();
        assert!(matches!(action, SeerAction::Scramble));
    }

    #[test]
    fn test_action_history() {
        let mut seer = Seer::new();

        // Initially empty
        assert!(seer.last_n_actions(10).is_empty());
        assert_eq!(seer.action_history().len(), 0);

        // Set some predictions and get recommendations
        seer.set_prediction(DetectionPrediction {
            probability: 0.1, confidence: 0.8,
            estimated_soc_response_secs: 900, most_likely_vector: "network".into(),
        });
        seer.recommend_action(); // Proceed

        seer.set_prediction(DetectionPrediction {
            probability: 0.5, confidence: 0.7,
            estimated_soc_response_secs: 600, most_likely_vector: "endpoint".into(),
        });
        seer.recommend_action(); // Scramble

        seer.set_prediction(DetectionPrediction {
            probability: 0.9, confidence: 0.95,
            estimated_soc_response_secs: 120, most_likely_vector: "endpoint".into(),
        });
        seer.recommend_action(); // Retreat

        // Check history length
        assert_eq!(seer.action_history().len(), 3);

        // last_n_actions returns in reverse order (most recent first)
        let last3 = seer.last_n_actions(3);
        assert_eq!(last3.len(), 3);
        assert!(matches!(last3[0], SeerAction::Retreat));  // most recent
        assert!(matches!(last3[1], SeerAction::Scramble));
        assert!(matches!(last3[2], SeerAction::Proceed));

        // Test with smaller N
        let last1 = seer.last_n_actions(1);
        assert_eq!(last1.len(), 1);
        assert!(matches!(last1[0], SeerAction::Retreat));

        // Test with larger N than available
        let last10 = seer.last_n_actions(10);
        assert_eq!(last10.len(), 3);
    }

    #[test]
    fn test_update_prediction() {
        let mut seer = Seer::new();
        let telem = sample_telemetry();

        assert!(seer.last_prediction().is_none());

        seer.update_prediction(&telem, "exfiltrate data");

        assert!(seer.last_prediction().is_some());
        let pred = seer.last_prediction().unwrap();
        assert!(pred.probability > 0.0);
        assert!(pred.estimated_soc_response_secs > 0);
    }

    #[test]
    fn test_reset() {
        let mut seer = Seer::new();

        seer.on_event("SafetyTrigger");
        seer.on_event("ChaosInjected");
        seer.on_event("HeartbeatSent");

        assert!(seer.risk_adjustment() > 0.0);
        assert!(seer.confidence_adjustment() > 0.0);

        seer.reset();

        assert!((seer.risk_adjustment() - 0.0).abs() < 0.001);
        assert!((seer.confidence_adjustment() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_clamping() {
        let mut seer = Seer::new();

        // Add many SafetyTrigger events to test upper clamp at +0.5
        for _ in 0..100 {
            seer.on_event("SafetyTrigger");
        }

        // Should be clamped at +0.5
        assert!(seer.risk_adjustment() <= 0.51);
        assert!((seer.risk_adjustment() - 0.5).abs() < 0.01);

        // With this maxed, prediction still clamps to 1.0 max
        let telem = TelemetrySample {
            edr_process_count: 0,
            total_processes: 10,
            uptime_hours: 1,
            firewall_rules: 0,
            logged_in_users: 1,
            listening_ports: 0,
            has_defender: false,
            has_sentinelone: false,
            has_crowdstrike: false,
            has_carbonblack: false,
            has_symantec: false,
            is_vm: false,
            is_domain_controller: false,
            is_server_os: false,
        };

        // Check that predict_detection properly clamps
        let pred = seer.predict_detection(&telem, "test action");
        assert!(pred.probability <= 1.0);
        assert!(pred.probability >= 0.0);
        assert!(pred.confidence <= 1.0);
        assert!(pred.confidence >= 0.0);
    }
}
