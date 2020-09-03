use crate::config;
use crate::db::totp::add_totp_token;
use crate::db::user::modify_user;
use crate::models::ServerError;
use crate::models::User;
use crate::{err_input, err_server};

use actix_http::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use totp_rs::{Algorithm, TOTP};

/// Create a totp token for a specific user
pub async fn generate_totp_token(
    user_id: &str,
    persistant: bool,
) -> Result<Cookie<'_>, ServerError> {
    // Try a few times to create a token, in case of a token that is not unique (Unlikely!)
    // Only repeat 10 times to prevent an infinite loop
    for i in 0..10 {
        let token = super::generate_token()?;
        match add_totp_token(
            user_id,
            &token,
            persistant,
            Utc::now() + Duration::minutes(5),
        )
        .await
        {
            Ok(_) => {
                return Ok(Cookie::build("totp", token.to_string())
                    .domain(config::COOKIE_DOMAIN.as_str())
                    .path("/")
                    .secure(*config::PRODUCTION)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .max_age(Duration::minutes(5).num_seconds())
                    .finish());
            }
            Err(e) => log::warn!(
                "Problem creating totp token for user {} (attempt {}/10): {}",
                user_id,
                i + 1,
                e
            ),
        }
    }
    Err(err_server!("Unable to generate session token."))
}

/// Check that a TOTP value is valid for a user.
/// If it is not valid, it will also try it as a backup code.
pub async fn validate_totp_token(user: &User, otp: &str) -> Result<bool, ServerError> {
    if otp.len() != 6 {
        return Err(err_input!("Invalid token length."));
    }
    let now = Utc::now().timestamp() as u64;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        user.totp_token
            .as_ref()
            .ok_or(err_input!("User doesn't use 2FA"))?,
    );
    let token = totp.generate(now);
    Ok(token == otp)
}

/// Validate a TOTP backup code, and if it is valid, remove it as it's been used.
pub async fn validate_totp_backup(user: &mut User, backup_code: &str) -> Result<bool, ServerError> {
    if backup_code.len() != 32 {
        return Err(err_input!("Invalid token length."));
    }
    match user
        .totp_backups
        .as_ref()
        .ok_or(err_input!("User doesn't have 2FA backup codes"))?
        .iter()
        .position(|code| code.to_string() == backup_code)
    {
        Some(pos) => {
            let backups = user
                .totp_backups
                .as_mut()
                .ok_or(err_input!("User doesn't have 2FA backup codes"))?;
            // Get rid of the code and update the user.
            backups.remove(pos);
            modify_user(user).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

pub async fn validate_totp(user: &mut User, token: &str) -> Result<(), ServerError> {
    if !user.totp_active {
        return Err(err_input!("User doesn't use 2FA"));
    }
    if !validate_totp_token(user, token).await? && !validate_totp_backup(user, token).await? {
        return Err(err_input!("Backup code doesn't match."));
    }
    Ok(())
}

/// Generate 10 TOTP backup codes.
pub fn generate_totp_backup_codes() -> Result<Vec<String>, ServerError> {
    let mut backup_codes: Vec<String> = vec![];
    for _ in 0..10 {
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token)
            .map_err(|e| err_server!("Error generating token: {}", e))?;
        backup_codes.push(hex::encode(token.to_vec()));
    }
    Ok(backup_codes)
}
