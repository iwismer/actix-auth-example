/// Module that contains all the functions related to authentication.
use crate::err_server;
use crate::models::ServerError;

use hex::encode;
use sha2::{Digest, Sha256};

pub mod credentials;
pub mod csrf;
pub mod email;
pub mod middleware;
pub mod session;
pub mod totp;

/// Generate a generic 32 byte token, and convert it to a hex string.
pub fn generate_token() -> Result<String, ServerError> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(|e| err_server!("Error generating token: {}", e))?;
    Ok(hex::encode(token.to_vec()))
}

/// Hash a token with SHA256.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    encode(hasher.finalize())
}
