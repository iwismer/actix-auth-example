/// Module that contains all the DB functions related to authentication.
use super::get_bson_string;
use super::{session_collection, users_collection};
use crate::models::User;
use bson::doc;
use chrono::{DateTime, Utc};
use mongodb::options::UpdateModifications;
use std::convert::TryFrom;

/// Get a single user from the DB
pub async fn get_user_by_username(username: &str) -> Result<Option<User>, String> {
    Ok(
        match users_collection()?
            .find_one(Some(doc! {"username": username}), None)
            .await
            .map_err(|e| format!("Problem querying database for user {}: {}", username, e))?
        {
            Some(d) => Some(
                User::try_from(d)
                    .map_err(|e| format!("Problem parsing user from BSON {}: {}", username, e))?,
            ),
            None => None,
        },
    )
}

/// Get user_id from session token
pub async fn get_user_by_userid(user_id: &str) -> Result<Option<User>, String> {
    Ok(
        match users_collection()?
            .find_one(Some(doc! {"user_id": user_id}), None)
            .await
            .map_err(|e| format!("Problem querying database for user_id {}: {}", user_id, e))?
        {
            Some(item) => Some(
                User::try_from(item)
                    .map_err(|e| format!("Problem parsing user from BSON {}: {}", user_id, e))?,
            ),
            None => None,
        },
    )
}

/// Get a user's has from the database
// pub async fn get_user_hash(user: &str) -> Result<Option<String>, String> {
//     Ok(get_user_username(user).await?.map(|u| u.pass_hash))
// }

/// Add a user to the DB
pub async fn add_user(user: User) -> Result<(), String> {
    users_collection()?
        .insert_one(user.into(), None)
        .await
        .map_err(|e| format!("Problem adding user:{}", e))?;
    Ok(())
}

/// Add a user to the DB
pub async fn modify_user(user: User) -> Result<(), String> {
    users_collection()?
        .update_one(
            doc! { "user_id": &user.user_id },
            UpdateModifications::Document(user.into()),
            None,
        )
        .await
        .map_err(|e| format!("Problem modifying user:{}", e))?;
    Ok(())
}

/// Delete a user from the DB
pub async fn delete_user(user_id: &str) -> Result<(), String> {
    // Delete existing sessions
    session_collection()?
        .delete_many(doc! { "user_id": user_id }, None)
        .await
        .map_err(|e| format!("Problem deleting user sessions {}: {}", user_id, e))?;
    // Delete user
    users_collection()?
        .delete_one(doc! { "user_id": user_id }, None)
        .await
        .map_err(|e| format!("Problem deleting user {}: {}", user_id, e))?;
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
