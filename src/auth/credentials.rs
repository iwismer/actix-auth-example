/// Module that contains all the functions related to credentials.
use crate::db::auth::get_user_by_username;
use crate::models::User;
use argon2::{hash_encoded, verify_encoded, Config};
use hex::encode;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// Generate a password hash from the supplied password, using a random salt
pub fn generate_password_hash(password: &str) -> Result<String, String> {
    let config = Config::default();
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|e| format!("Error generating salt: {}", e))?;
    hash_encoded(
        password.nfkc().collect::<String>().as_bytes(),
        &salt,
        &config,
    )
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
pub fn credential_validator(user: &User, password: &str) -> Result<bool, String> {
    // TODO return full user
    Ok(verify_encoded(
        &user.pass_hash,
        password.nfkc().collect::<String>().as_bytes(),
    )
    .map_err(|e| format!("Error verifying hash: {}", e))?)
}

/// Check if the username + password pair are valid
/// TODO allow either email or username
pub async fn credential_validator_username(
    username: &str,
    password: &str,
) -> Result<Option<User>, String> {
    // TODO return full user
    let user = get_user_by_username(username)
        .await?
        .ok_or(format!("User doesn't exist: {}", username))?;
    match credential_validator(&user, &password)? {
        true => Ok(Some(user)),
        false => Ok(None),
    }
}

pub fn validate_password_rules(password: &str, password_confirm: &str) -> Result<(), String> {
    if password.len() < 10 {
        return Err("Password must be at least 10 characters.".to_string());
    }
    if password.bytes().len() > 8192 {
        return Err("Password too long (> 8192 bytes).".to_string());
    }
    if password != password_confirm {
        return Err("Passwords don't match.".to_string());
    }
    Ok(())
}

pub fn validate_username_rules(username: &str) -> Result<(), String> {
    if username.len() == 0 {
        return Err("Username cannot be empty.".to_string());
    }
    if username.bytes().len() > 8192 {
        return Err("Username too long (> 8192 bytes).".to_string());
    }
    Ok(())
}

pub fn validate_email_rules(email: &str) -> Result<(), String> {
    // TODO check for a better regex
    let re = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();
    if !re.is_match(email) {
        return Err("Invalid email.".to_string());
    }
    Ok(())
}
