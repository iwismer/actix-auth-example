/// Module containing the email sending related functions.
use crate::config;
use crate::db::email::{add_email_token, add_password_reset_token};

use chrono::{Duration, Utc};
use lazy_static::lazy_static;
use lettre::{smtp::authentication::Credentials, SmtpClient, SmtpTransport, Transport};
use lettre_email::EmailBuilder;
use std::sync::Mutex;

lazy_static! {
    static ref MAILER: Mutex<SmtpTransport> = Mutex::new(
        SmtpClient::new_simple(config::EMAIL_SERVER.as_str())
            .unwrap()
            .credentials(Credentials::new(
                config::EMAIL_USER.to_string(),
                config::EMAIL_PASS.to_string(),
            ))
            .transport()
    );
}

/// Send a verification email to the supplied email.
pub fn send_verification_email(email: &str, token: &str) -> Result<(), String> {
    let email = EmailBuilder::new()
        .to(email)
        .from(config::EMAIL_FROM.as_str())
        .subject("Rust Authentication Example: Email Verification.")
        .text(format!("This email was used to register for the Rust Authentication Example. To verify your email follow this link: {}email?token={}\nThis link will expire in 24 hours.", config::DOMAIN.as_str(), token))
        .build()
        .unwrap();

    let result = MAILER
        .lock()
        .map_err(|e| format!("Error unlocking mailer: {}", e))?
        .send(email.into());

    if result.is_ok() {
        log::debug!("Email sent");
    } else {
        log::warn!("Could not send email: {:?}", result);
    }
    Ok(())
}

/// Send a password reset email.
pub async fn send_password_reset_email(user_id: &str, email: &str) -> Result<(), String> {
    let mut password_reset_token = "".to_string();
    let mut error: Option<String> = None;
    for i in 0..10 {
        password_reset_token = super::generate_token()?;
        match add_password_reset_token(
            user_id,
            &password_reset_token,
            Utc::now() + Duration::days(1),
        )
        .await
        {
            Ok(_) => {
                error = None;
                break;
            }
            Err(e) => {
                log::warn!(
                    "Problem creating password reset token for user {} (attempt {}/10): {}",
                    user_id,
                    i + 1,
                    e
                );
                error = Some(e);
            }
        }
    }
    if let Some(e) = error {
        return Err(format!("Error generating password reset token: {}", e));
    }
    let email = EmailBuilder::new()
        .to(email)
        .from(config::EMAIL_FROM.as_str())
        .subject("Rust Authentication Example: Password Reset")
        .text(format!("The account associated with this email has had a password reset request. Click this link to reset the password: {}password-reset?token={}\nThis link will expire in 24 hours.", config::DOMAIN.as_str(), password_reset_token))
        .build()
        .unwrap();

    let result = MAILER
        .lock()
        .map_err(|e| format!("Error unlocking mailer: {}", e))?
        .send(email.into());

    if result.is_ok() {
        log::debug!("Email sent");
    } else {
        log::warn!("Could not send email: {:?}", result);
    }
    Ok(())
}

/// Generate an email token and then send a verification email.
pub async fn validate_email(user_id: &str, email: &str) -> Result<(), String> {
    // TODO retry in case of duplicate
    let email_token = super::generate_token()?;
    add_email_token(user_id, email, &email_token, Utc::now() + Duration::days(1)).await?;
    send_verification_email(email, &email_token)?;
    Ok(())
}
