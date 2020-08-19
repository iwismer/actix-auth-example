/// Module that contains all the functions related to credentials.
use crate::db::auth::get_user_hash;
use argon2::{hash_encoded, verify_encoded, Config};
use hex::encode;

/// Generate a password hash from the supplied password, using a random salt
pub fn generate_password_hash(password: &str) -> Result<String, String> {
    let config = Config::default();
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|e| format!("Error generating salt: {}", e))?;
    hash_encoded(password.as_bytes(), &salt, &config)
        .map_err(|e| format!("Error generating hash: {}", e))
}

/// Generate a random user ID
/// TODO make this check for duplicates, and maybe use a better ID generation scheme
pub fn generate_user_id() -> Result<String, String> {
    let mut id = [0u8; 64];
    getrandom::getrandom(&mut id).map_err(|e| format!("Error generating salt: {}", e))?;
    Ok(encode(id.to_vec()))
}

/// Check if the username + password pair are valid
/// TODO allow either email or username
pub async fn credential_validator(username: &str, password: &str) -> Result<bool, String> {
    // TODO return full user
    let hash = get_user_hash(username)
        .await?
        .ok_or(format!("User doesn't exist: {}", username))?;
    verify_encoded(&hash, password.as_bytes()).map_err(|e| format!("Error verifying hash: {}", e))
}
