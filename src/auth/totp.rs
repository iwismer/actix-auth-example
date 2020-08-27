use crate::config;
use crate::db::totp::add_totp_token;
use crate::db::user::{get_user_by_userid, modify_user};

use actix_http::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use totp_rs::{Algorithm, TOTP};

/// Create a totp token for a specific user
pub async fn generate_totp_token(user_id: &str, persistant: bool) -> Result<Cookie<'_>, String> {
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
    Err("Unable to generate session token.".to_string())
}

/// Check that a TOTP value is valid for a user.
/// If it is not valid, it will also try it as a backup code.
pub async fn validate_totp(user_id: &str, otp: &str) -> Result<(), String> {
    // TODO replace user_id with user
    // TODO do a simple length check
    let now = Utc::now().timestamp() as u64;
    let user = get_user_by_userid(&user_id)
        .await?
        .ok_or(format!("User not found: {}", user_id))?;
    if !user.totp_active {
        return Err("User doesn't use 2FA".to_string());
    }
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        user.totp_token.ok_or("User doesn't use 2FA".to_string())?,
    );
    let token = totp.generate(now);
    // If it's not a totp match, then check if it's a backup code.
    if token != otp && validate_totp_backup(&user_id, otp).await.is_err() {
        return Err("Token doesn't match".to_string());
    }
    Ok(())
}

/// Validate a TOTP backup code, and if it is valid, remove it as it's been used.
pub async fn validate_totp_backup(user_id: &str, backup_code: &str) -> Result<(), String> {
    // TODO maybe just get the user as a param?
    let mut user = get_user_by_userid(&user_id)
        .await?
        .ok_or(format!("User not found: {}", user_id))?;
    if !user.totp_active {
        return Err("User doesn't use 2FA".to_string());
    }
    match user
        .totp_backups
        .as_ref()
        .ok_or("User doesn't have 2FA backup codes".to_string())?
        .iter()
        .position(|code| code.to_string() == backup_code)
    {
        Some(pos) => {
            let mut backups = user
                .totp_backups
                .ok_or("User doesn't have 2FA backup codes".to_string())?;
            // Get rid of the code and update the user.
            backups.remove(pos);
            user.totp_backups = Some(backups);
            modify_user(user).await?;
            Ok(())
        }
        None => Err("Backup code doesn't match.".to_string()),
    }
}

/// Generate 10 TOTP backup codes.
pub fn generate_totp_backup_codes() -> Result<Vec<String>, String> {
    let mut backup_codes: Vec<String> = vec![];
    for _ in 0..10 {
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token).map_err(|e| format!("Error generating token: {}", e))?;
        backup_codes.push(hex::encode(token.to_vec()));
    }
    Ok(backup_codes)
}
