/// Module that contains all the DB functions related to authentication.
use super::{get_bson_bool, get_bson_string, totp_token_collection};

use crate::auth::hash_token;

use bson::doc;
use chrono::{DateTime, Utc};

/// Add a email token to the DB
pub async fn add_totp_token(
    user_id: &str,
    token: &str,
    persist: bool,
    expiry: DateTime<Utc>,
) -> Result<(), String> {
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    totp_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "token": hashed_token, "persist": persist, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| format!("Problem adding totp token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete an totp token
pub async fn verify_totp_token(token: &str) -> Result<(String, bool), String> {
    let hashed_token = hash_token(token);
    let token_doc = totp_token_collection()?
        .find_one(doc! { "token": hashed_token.to_string() }, None)
        .await
        .map_err(|e| format!("Problem finding totp token {}: {}", token, e))?
        .ok_or("Token not found.".to_string())?;

    if totp_token_collection()?
        .delete_one(doc! { "token": hashed_token }, None)
        .await
        .map_err(|e| format!("Problem deleting totp token {}: {}", token, e))?
        .deleted_count
        != 1
    {
        return Err("Incorrect number of tokens deleted.".to_string());
    }
    Ok((
        get_bson_string("user_id", &token_doc)?,
        get_bson_bool("persist", &token_doc)?,
    ))
}

pub async fn check_totp_token_exists(token: &str) -> Result<(), String> {
    let hashed_token = hash_token(token);
    totp_token_collection()?
        .find_one(doc! { "token": hashed_token.to_string() }, None)
        .await
        .map_err(|e| format!("Problem finding totp token {}: {}", token, e))?
        .ok_or("Token not found.".to_string())?;

    Ok(())
}
