use crate::config;
use crate::db::email::add_email_token;
use chrono::{Duration, Utc};
use lazy_static::lazy_static;
use lettre::Transport;
use lettre::{smtp::authentication::Credentials, SmtpClient, SmtpTransport};
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

pub fn send_verification_email(email: &str, token: &str) -> Result<(), String> {
    let email = EmailBuilder::new()
        .to(email)
        .from(config::EMAIL_FROM.as_str())
        .subject("Rust Authentication Example: Email Verification.")
        .text(format!("This email was used to register for the Rust Authentication Example. To verify your email follow this link: {}email?token={}", config::DOMAIN.as_str(), token))
        .build()
        .unwrap();

    let result = MAILER.lock().unwrap().send(email.into());

    if result.is_ok() {
        log::debug!("Email sent");
    } else {
        log::warn!("Could not send email: {:?}", result);
    }
    Ok(())
}

pub async fn validate_email(user_id: &str, email: &str) -> Result<(), String> {
    let email_token = super::generate_token()?;
    add_email_token(user_id, email, &email_token, Utc::now() + Duration::days(1)).await?;
    send_verification_email(email, &email_token)?;
    Ok(())
}
