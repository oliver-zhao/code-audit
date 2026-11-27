// Weak hashes, ciphers, nonces and random numbers.
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha1::{Digest, Sha1};

static SIGNING_SECRET: &str = "Fixture0nlyRustSigningValue0000";

pub fn file_fingerprint(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}

pub fn store_password(password: &str) -> Vec<u8> {
    Sha1::digest(password.as_bytes()).to_vec()
}

pub fn legacy_encrypt(key: &[u8], block: &mut [u8]) {
    let cipher = des::Des::new_from_slice(key).unwrap();
    let _ = (cipher, block);
}

pub fn openssl_ecb() -> openssl::symm::Cipher {
    openssl::symm::Cipher::aes_128_ecb()
}

pub fn seal(cipher: &Aes256Gcm, plaintext: &[u8]) -> Vec<u8> {
    let nonce = Nonce::from_slice(b"fixed nonce!");
    cipher.encrypt(nonce, plaintext).unwrap()
}

pub fn new_session_token() -> String {
    let token: u64 = StdRng::seed_from_u64(42).gen();
    format!("{:016x}", token)
}
