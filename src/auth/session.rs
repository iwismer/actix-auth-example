/// Module that contains all the functions related to sessions.
use crate::db::session::add_session;
use crate::models::ServerError;
use crate::{config, err_server};

use actix_http::cookie::{Cookie, SameSite};
use actix_web::HttpMessage;
use chrono::{Duration, Utc};
use log::warn;

/// Create a session token for a specific user
pub async fn generate_session_token(
    user: &str,
    persistant: bool,
) -> Result<Cookie<'_>, ServerError> {
    let expiry = match persistant {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(30),
    };
    // Try a few times to create a token, in case of a token that is not unique (Unlikely!)
    // Only repeat 10 times to prevent an infinite loop
    for i in 0..10 {
        let token = super::generate_token()?;
        match add_session(user, &token, expiry).await {
            Ok(_) => {
                let mut cookie = Cookie::build("session", token.to_string())
                    .domain(config::COOKIE_DOMAIN.as_str())
                    .path("/")
                    .secure(*config::PRODUCTION)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish();
                if persistant {
                    cookie.set_max_age(Duration::days(30));
                }
                return Ok(cookie);
            }
            Err(e) => warn!(
                "Problem creating session token for user {} (attempt {}/10): {}",
                user,
                i + 1,
                e
            ),
        }
    }
    Err(err_server!("Unable to generate session token."))
}

/// Extract the session token from the request cookies
pub fn get_session_token<T: HttpMessage>(req: &T) -> Option<String> {
    req.cookie("session").map(|c| c.value().to_string())
}
