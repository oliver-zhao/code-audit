// SHA-256, argon2, AEAD with random nonces and OS randomness.
use aes_gcm::{aead::{Aead, AeadCore, OsRng}, Aes256Gcm};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::{Digest, Sha256};

static SIGNING_SECRET_ENV: &str = "APP_SIGNING_SECRET";

pub fn file_fingerprint(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub fn store_password(password: &str) -> String {
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    argon2::PasswordHasher::hash_password(&argon2::Argon2::default(), password.as_bytes(), &salt).unwrap().to_string()
}

pub fn seal(cipher: &Aes256Gcm, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    (nonce.to_vec(), cipher.encrypt(&nonce, plaintext).unwrap())
}

pub fn new_session_token() -> String {
    let token: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    token
}

pub fn signing_secret() -> String {
    std::env::var(SIGNING_SECRET_ENV).expect("signing secret")
}
