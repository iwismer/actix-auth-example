/// Module that contains all the DB functions related to authentication.
use super::get_bson_string;
use super::session_collection;
use bson::doc;
use chrono::{DateTime, Utc};
/// Get username from session token
pub async fn validate_session(token: &str) -> Result<bool, String> {
    match session_collection()?
        .find_one(Some(doc! {"token": token}), None)
        .await
        .map_err(|e| format!("Problem querying database for token {}: {}", token, e))?
    {
        Some(item) => Ok(item
            .get_datetime("expiry")
            .map_err(|e| format!("Unable to get expiry from BSON: {}", e))?
            > &Utc::now()),
        None => Ok(false),
    }
}

/// Add a user session to the DB
/// The DB will return an error if the token already exists in the DB
pub async fn add_session(user_id: &str, token: &str, expiry: DateTime<Utc>) -> Result<(), String> {
    // Uniqueness is taken care of by an index in the DB
    session_collection()?
        .insert_one(
            doc! { "user_id": user_id, "token": token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| format!("Problem adding user session {}:{}", user_id, e))?;
    Ok(())
}

/// Delete a user session from the DB
pub async fn delete_session(token: &str) -> Result<(), String> {
    session_collection()?
        .delete_one(doc! { "token": token }, None)
        .await
        .map_err(|e| format!("Problem deleting session {}: {}", token, e))?;
    Ok(())
}

/// Get user_id from session token
pub async fn get_session_user_id(token: &str) -> Result<Option<String>, String> {
    Ok(
        match session_collection()?
            .find_one(Some(doc! {"token": token}), None)
            .await
            .map_err(|e| format!("Problem querying database for token {}: {}", token, e))?
        {
            Some(item) => Some(get_bson_string("user_id", &item)?),
            None => None,
        },
    )
}
