/// Module that contains all the functions related to credentials.
use crate::db::user::get_user_by_username;
use crate::models::ServerError;
use crate::models::User;
use crate::{err_input, err_server};

use argon2::{hash_encoded, verify_encoded, Config};
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// Generate a password hash from the supplied password, using a random salt
pub fn generate_password_hash(password: &str) -> Result<String, ServerError> {
    let config = Config::default();
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|e| err_server!("Error generating salt: {}", e))?;
    hash_encoded(
        password.nfkc().collect::<String>().as_bytes(),
        &salt,
        &config,
    )
    .map_err(|e| err_server!("Error generating hash: {}", e))
}

/// Generate a random user ID
pub fn generate_user_id() -> Result<String, ServerError> {
    super::generate_token()
}

/// Check if the username + password pair are valid
pub fn credential_validator(user: &User, password: &str) -> Result<bool, ServerError> {
    Ok(verify_encoded(
        &user.pass_hash,
        password.nfkc().collect::<String>().as_bytes(),
    )
    .map_err(|e| err_server!("Error verifying hash: {}", e))?)
}

/// Check if the username + password pair are valid
pub async fn credential_validator_username(
    username: &str,
    password: &str,
) -> Result<Option<User>, ServerError> {
    let user = match get_user_by_username(username).await? {
        Some(u) => u,
        None => {
            log::warn!("User doesn't exist: {}", username);
            return Ok(None);
        }
    };
    match credential_validator(&user, &password)? {
        true => Ok(Some(user)),
        false => Ok(None),
    }
}

/// Check that a password meets password requirements
pub fn validate_password_rules(password: &str, password_confirm: &str) -> Result<(), ServerError> {
    if password.len() < 10 {
        return Err(err_input!("Password must be at least 10 characters."));
    }
    if password.bytes().len() > 8192 {
        return Err(err_input!("Password too long (> 8192 bytes)."));
    }
    if password != password_confirm {
        return Err(err_input!("Passwords don't match."));
    }
    Ok(())
}

/// Check that an username meets username requirements
pub fn validate_username_rules(username: &str) -> Result<(), ServerError> {
    if username.len() == 0 {
        return Err(err_input!("Username cannot be empty."));
    }
    if username.bytes().len() > 8192 {
        return Err(err_input!("Username too long (> 8192 bytes)."));
    }
    Ok(())
}

/// Check that an email meets email requirements
pub fn validate_email_rules(email: &str) -> Result<(), ServerError> {
    let re = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();
    if !re.is_match(email) {
        return Err(err_input!("Invalid email."));
    }
    Ok(())
}
