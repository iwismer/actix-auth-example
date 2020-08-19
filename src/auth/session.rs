/// Module that contains all the functions related to sessions.
use crate::db::auth::{add_session, get_session_user_id, get_user_by_userid};
use crate::models::User;
use actix_web::HttpMessage;
use chrono::{Duration, Utc};
use log::warn;

/// Create a session token for a specific user
pub async fn generate_session_token(user: &str) -> Result<String, String> {
    let expiry = Utc::now() + Duration::days(1);
    // Try a few times to create a token, in case of a token that is not unique (Unlikely!)
    // Only repeat 10 times to prevent an infinite loop
    for i in 0..10 {
        let mut session_token = [0u8; 64];
        getrandom::getrandom(&mut session_token)
            .map_err(|e| format!("Error generating session token: {}", e))?;
        let token = hex::encode(session_token.to_vec());
        match add_session(user, &token, expiry).await {
            Ok(_) => return Ok(token),
            Err(e) => warn!(
                "Problem creating session token for user {} (attempt {}/10): {}",
                user,
                i + 1,
                e
            ),
        }
    }
    Err("Unable to generate session token.".to_string())
}

/// Extract the session token from the request cookies
pub fn get_session_token<T: HttpMessage>(req: &T) -> Option<String> {
    req.cookies()
        .ok()?
        .iter()
        .find(|c| c.name() == "session")
        .map(|c| c.value().to_string())
}

// TODO replace with extractor when I figure out how to do async in an extractor
/// Get the username that sent the request based on the session
pub async fn get_req_user<T: HttpMessage>(req: &T) -> Result<Option<User>, String> {
    let user_id = match get_session_token(req) {
        Some(token) => match get_session_user_id(&token).await? {
            Some(u) => u,
            None => return Ok(None),
        },
        None => return Ok(None),
    };
    log::debug!("userid: {}", user_id);
    get_user_by_userid(&user_id).await
}
