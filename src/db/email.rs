/// Module that contains all the DB functions related to emails (and password reset, because that's email related).
use super::get_bson_string;
use super::user::{get_user_by_userid, modify_user};
use super::{email_token_collection, password_reset_token_collection};

use crate::auth::hash_token;
use crate::models::ServerError;
use crate::models::User;
use crate::{err_input, err_server};

use bson::doc;
use chrono::{DateTime, Utc};

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), ServerError> {
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    email_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "email": email, "token": hashed_token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete an email token
pub async fn verify_email_token(token: &str) -> Result<(), ServerError> {
    let hashed_token = hash_token(token);
    let token_doc = email_token_collection()?
        .find_one(doc! { "token": hashed_token }, None)
        .await
        .map_err(|e| err_server!("Problem finding email token {}: {}", token, e))?
        .ok_or(err_input!("Token not found."))?;
    let user_id = get_bson_string("user_id", &token_doc)?;
    let email = get_bson_string("email", &token_doc)?;

    let mut user = get_user_by_userid(&user_id)
        .await?
        .ok_or(err_input!("User doesn't exist."))?;
    if email != user.email {
        return Err(err_input!("Invalid Token. Email doesn't match"));
    }
    user.email_validated = true;
    modify_user(&user).await?;
    if email_token_collection()?
        .delete_one(doc! { "token": hash_token(token) }, None)
        .await
        .map_err(|e| err_server!("Problem deleting email token {}: {}", token, e))?
        .deleted_count
        != 1
    {
        return Err(err_server!(
            "Incorrect number of tokens deleted. Something weird went wrong."
        ));
    }
    Ok(())
}

/// Add a password reset token to the DB
pub async fn add_password_reset_token(
    user_id: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), ServerError> {
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    password_reset_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "token": hashed_token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| err_server!("Problem adding password reset token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete a password reset token
pub async fn verify_password_reset_token(
    token: &str,
    delete_token: bool,
) -> Result<User, ServerError> {
    let hashed_token = hash_token(token);
    let token_doc = password_reset_token_collection()?
        .find_one(doc! { "token": hashed_token }, None)
        .await
        .map_err(|e| err_server!("Problem finding password reset token {}: {}", token, e))?
        .ok_or(err_input!("Token not found."))?;
    let user_id = get_bson_string("user_id", &token_doc)?;

    let user = get_user_by_userid(&user_id)
        .await?
        .ok_or(err_input!("User doesn't exist."))?;
    if delete_token {
        if password_reset_token_collection()?
            .delete_one(doc! { "token": hash_token(token) }, None)
            .await
            .map_err(|e| err_server!("Problem deleting password reset token {}: {}", token, e))?
            .deleted_count
            != 1
        {
            return Err(err_server!(
                "Incorrect number of tokens deleted. Something weird went wrong."
            ));
        }
    }
    Ok(user)
}
