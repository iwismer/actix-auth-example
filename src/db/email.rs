use super::email_token_collection;
/// Module that contains all the DB functions related to authentication.
use super::user::{get_user_by_userid, modify_user};
use bson::doc;
use chrono::{DateTime, Utc};
/// Add a email token to the DB
pub async fn add_email_token(
    user_id: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), String> {
    // Uniqueness is taken care of by an index in the DB
    email_token_collection()?
        .insert_one(
            doc! { "user_id": user_id, "token": token, "expiry": expiry },
            None,
        )
        .await
        .map_err(|e| format!("Problem adding email token {}:{}", user_id, e))?;
    Ok(())
}

/// Verify and delete an email token
pub async fn verify_email_token(token: &str) -> Result<(), String> {
    let user_id = email_token_collection()?
        .find_one(doc! { "token": token }, None)
        .await
        .map_err(|e| format!("Problem finding email token {}: {}", token, e))?
        .ok_or("Token not found.".to_string())?
        .get_str("user_id")
        .map_err(|e| format!("Error getting userID: {}", e))?
        .to_string();

    let mut user = get_user_by_userid(&user_id)
        .await?
        .ok_or("User doesn't exist.".to_string())?;
    user.email_validated = true;
    modify_user(user).await?;
    if email_token_collection()?
        .delete_one(doc! { "token": token }, None)
        .await
        .map_err(|e| format!("Problem deleting email token {}: {}", token, e))?
        .deleted_count
        != 1
    {
        return Err("Invalid Token.".to_string());
    }
    Ok(())
}
