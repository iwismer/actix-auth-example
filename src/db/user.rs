/// Module that contains all the DB functions related to users.
use super::{session_collection, users_collection};

use crate::err_server;
use crate::models::{ServerError, User};

use bson::doc;
use mongodb::options::UpdateModifications;
use std::convert::TryFrom;

/// Get a single user from the DB, searching by username
pub async fn get_user_by_username(username: &str) -> Result<Option<User>, ServerError> {
    Ok(
        match users_collection()?
            .find_one(Some(doc! {"username": username}), None)
            .await
            .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e))?
        {
            Some(d) => Some(User::try_from(d).map_err(|mut e| {
                e.message = format!("Problem parsing user from BSON {}: {}", username, e);
                e
            })?),
            None => None,
        },
    )
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_email(email: &str) -> Result<Option<User>, ServerError> {
    Ok(
        match users_collection()?
            .find_one(Some(doc! {"email": email}), None)
            .await
            .map_err(|e| err_server!("Problem querying database for email {}: {}", email, e))?
        {
            Some(d) => Some(User::try_from(d).map_err(|mut e| {
                e.message = format!("Problem parsing user from BSON {}: {}", email, e);
                e
            })?),
            None => None,
        },
    )
}

/// Get a single user from the DB searching by user ID
pub async fn get_user_by_userid(user_id: &str) -> Result<Option<User>, ServerError> {
    Ok(
        match users_collection()?
            .find_one(Some(doc! {"user_id": user_id}), None)
            .await
            .map_err(|e| err_server!("Problem querying database for user_id {}: {}", user_id, e))?
        {
            Some(item) => Some(User::try_from(item).map_err(|mut e| {
                e.message = format!("Problem parsing user from BSON {}: {}", user_id, e);
                e
            })?),
            None => None,
        },
    )
}

/// Add a user to the DB
pub async fn add_user(user: &User) -> Result<(), ServerError> {
    users_collection()?
        .insert_one(user.into(), None)
        .await
        .map_err(|e| err_server!("Problem adding user: {}", e))?;
    Ok(())
}

/// Modify an existing user in the DB
pub async fn modify_user(user: &User) -> Result<(), ServerError> {
    users_collection()?
        .update_one(
            doc! { "user_id": &user.user_id },
            UpdateModifications::Document(user.into()),
            None,
        )
        .await
        .map_err(|e| err_server!("Problem modifying user: {}", e))?;
    Ok(())
}

/// Delete a user from the DB
pub async fn delete_user(user_id: &str) -> Result<(), ServerError> {
    // TODO delete all other tokens too!
    // Delete existing sessions
    session_collection()?
        .delete_many(doc! { "user_id": user_id }, None)
        .await
        .map_err(|e| err_server!("Problem deleting user sessions {}: {}", user_id, e))?;
    // Delete user
    users_collection()?
        .delete_one(doc! { "user_id": user_id }, None)
        .await
        .map_err(|e| err_server!("Problem deleting user {}: {}", user_id, e))?;
    Ok(())
}
