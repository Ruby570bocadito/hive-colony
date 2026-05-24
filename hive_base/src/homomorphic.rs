// Homomorphic: experimental homomorphic encryption for consensus.
// Research module — allows the colony to vote on proposals without
// decrypting individual votes. Uses a simplified additive homomorphic
// scheme (Paillier-like) to aggregate votes while keeping them secret.
//
// In production, replace with tfhe-rs or concrete for full FHE.
// This implementation demonstrates the concept with additive scheme.

use rand::Rng;

/// Simplified additive homomorphic encryption (demonstration).
/// Enc(v1) + Enc(v2) = Enc(v1 + v2).
/// This allows the colony to tally votes without revealing who voted what.
///
/// Paillier-style simplified keypair.
pub struct HomoKeypair {
    pub n: u64,       // modulus (product of two primes, simplified)
    pub g: u64,       // generator
    pub lambda: u64,   // private key (Carmichael's function)
}

impl HomoKeypair {
    /// Generate a simplified keypair for demonstration.
    pub fn generate() -> Self {
        // Small primes for demonstration (real FHE needs 2048-bit primes)
        let p: u64 = 499;  // prime
        let q: u64 = 503;  // prime
        let n = p * q;
        let lambda = (p - 1) * (q - 1);
        let g = n + 1;  // Simplified Paillier: g = n + 1

        Self { n, g, lambda }
    }

    /// Encrypt: c = (1 + m*n) * r^n mod n^2
    pub fn encrypt(&self, value: u64) -> u64 {
        let mut rng = rand::thread_rng();
        let r: u64 = rng.gen_range(2..self.n);
        let n_sq = (self.n as u128) * (self.n as u128);

        // g^m = (n+1)^m = 1 + m*n (mod n^2) for small m
        let gm = (1u128 + (value as u128) * (self.n as u128)) % n_sq;
        // r^n mod n^2
        let rn = modular_pow(r as u128, self.n as u128, n_sq);

        ((gm * rn) % n_sq) as u64
    }

    /// Decrypt: L(c^lambda mod n^2) * lambda^-1 mod n
    pub fn decrypt(&self, ciphertext: u64) -> u64 {
        let n_sq = self.n * self.n;
        let c_lambda = modular_pow(ciphertext as u128, self.lambda as u128, n_sq as u128) as u64;
        // L(x) = (x - 1) / n
        if c_lambda < 1 { return 0; }
        let l = (c_lambda - 1) / self.n;
        let mu = mod_inverse(self.lambda, self.n);
        (l as u128 * mu as u128 % self.n as u128) as u64
    }

    /// Homomorphic addition: c1 * c2 mod n^2
    pub fn add_encrypted(&self, c1: u64, c2: u64) -> u64 {
        let n_sq = self.n * self.n;
        ((c1 as u128 * c2 as u128) % n_sq as u128) as u64
    }

    /// Tally multiple encrypted votes.
    pub fn tally_votes(&self, votes: &[u64]) -> u64 {
        let mut total = 1; // Enc(0) simplified: (1 + 0*n)*r^n = r^n which is just an encryption
        for vote in votes {
            total = self.add_encrypted(total, *vote);
        }
        total
    }
}

/// Modular exponentiation: base^exp mod modulus (u128 version).
fn modular_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0; }
    let mut result: u128 = 1;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}

/// Modular inverse using extended Euclidean algorithm.
fn mod_inverse(a: u64, m: u64) -> u64 {
    let (mut t, mut new_t): (i64, i64) = (0, 1);
    let (mut r, mut new_r): (i64, i64) = (m as i64, a as i64);
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    if r > 1 { return 0; }
    if t < 0 { t += m as i64; }
    t as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let kp = HomoKeypair::generate();
        let plain = 42u64;
        let ct = kp.encrypt(plain);
        let dec = kp.decrypt(ct);
        assert_eq!(plain, dec);
    }

    #[test]
    fn test_homomorphic_addition() {
        let kp = HomoKeypair::generate();
        let a = 10u64;
        let b = 25u64;
        let ca = kp.encrypt(a);
        let cb = kp.encrypt(b);
        let sum_ct = kp.add_encrypted(ca, cb);
        let sum_pt = kp.decrypt(sum_ct);
        assert_eq!(sum_pt, a + b);
    }

    #[test]
    fn test_tally_votes() {
        static SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _guard = SERIAL.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();
        let kp = HomoKeypair::generate();
        let votes: Vec<u64> = vec![1, 1, 0, 1, 1]; // 4 support, 1 reject
        let encrypted_votes: Vec<u64> = votes.iter().map(|v| kp.encrypt(*v)).collect();
        let tally_ct = kp.tally_votes(&encrypted_votes);
        let tally_pt = kp.decrypt(tally_ct);
        assert_eq!(tally_pt, 4); // 4 support votes
    }

    #[test]
    fn test_encrypted_zero_doesnt_change_tally() {
        static SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _guard = SERIAL.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();
        let kp = HomoKeypair::generate();
        let votes: Vec<u64> = vec![1, 0, 1, 0, 1];
        let encrypted: Vec<u64> = votes.iter().map(|v| kp.encrypt(*v)).collect();
        let tally_ct = encrypted.iter().fold(kp.encrypt(0), |acc, v| kp.add_encrypted(acc, *v));
        let tally_pt = kp.decrypt(tally_ct);
        assert_eq!(tally_pt, 3); // 3 support votes, zeros don't affect
    }
}
