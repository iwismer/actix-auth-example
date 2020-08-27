/// Module that contains all the DB functions related to emails (and password reset, because that's email related).
use super::get_bson_string;
use super::user::{get_user_by_userid, modify_user};
use super::{email_token_collection, password_reset_token_collection};

use crate::auth::hash_token;
use crate::models::User;

use bson::doc;
use chrono::{DateTime, Utc};

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), String> {
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    email_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "email": email, "token": hashed_token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| format!("Problem adding email token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete an email token
pub async fn verify_email_token(token: &str) -> Result<(), String> {
    let hashed_token = hash_token(token);
    let token_doc = email_token_collection()?
        .find_one(doc! { "token": hashed_token }, None)
        .await
        .map_err(|e| format!("Problem finding email token {}: {}", token, e))?
        .ok_or("Token not found.".to_string())?;
    let user_id = get_bson_string("user_id", &token_doc)?;
    let email = get_bson_string("email", &token_doc)?;

    let mut user = get_user_by_userid(&user_id)
        .await?
        .ok_or("User doesn't exist.".to_string())?;
    if email != user.email {
        return Err("Invalid Token. Email doesn't match".to_string());
    }
    user.email_validated = true;
    modify_user(user).await?;
    if email_token_collection()?
        .delete_one(doc! { "token": hash_token(token) }, None)
        .await
        .map_err(|e| format!("Problem deleting email token {}: {}", token, e))?
        .deleted_count
        != 1
    {
        return Err("Incorrect number of tokens deleted. Something weird went wrong.".to_string());
    }
    Ok(())
}

/// Add a password reset token to the DB
pub async fn add_password_reset_token(
    user_id: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), String> {
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    password_reset_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "token": hashed_token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| format!("Problem adding password reset token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete a password reset token
pub async fn verify_password_reset_token(token: &str, delete_token: bool) -> Result<User, String> {
    let hashed_token = hash_token(token);
    let token_doc = password_reset_token_collection()?
        .find_one(doc! { "token": hashed_token }, None)
        .await
        .map_err(|e| format!("Problem finding password reset token {}: {}", token, e))?
        .ok_or("Token not found.".to_string())?;
    let user_id = get_bson_string("user_id", &token_doc)?;

    let user = get_user_by_userid(&user_id)
        .await?
        .ok_or("User doesn't exist.".to_string())?;
    if delete_token {
        if password_reset_token_collection()?
            .delete_one(doc! { "token": hash_token(token) }, None)
            .await
            .map_err(|e| format!("Problem deleting password reset token {}: {}", token, e))?
            .deleted_count
            != 1
        {
            return Err(
                "Incorrect number of tokens deleted. Something weird went wrong.".to_string(),
            );
        }
    }
    Ok(user)
}
