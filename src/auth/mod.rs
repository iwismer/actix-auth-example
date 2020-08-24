/// Module that contains all the functions related to authentication.
use hex::encode;
use sha2::{Digest, Sha256};
pub mod credentials;
pub mod csrf;
pub mod email;
pub mod middleware;
pub mod session;
pub mod totp;

pub fn generate_token() -> Result<String, String> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(|e| format!("Error generating token: {}", e))?;
    Ok(hex::encode(token.to_vec()))
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    encode(hasher.finalize())
}
