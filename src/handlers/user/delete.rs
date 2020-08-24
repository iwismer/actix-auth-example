/// Module for endpoints related to deleting users
use crate::auth::{credentials::credential_validator, csrf::check_csrf};
use crate::db::user::{delete_user, get_user_by_userid};
use crate::models::ServiceError;
use actix_web::{http::header, web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// Struct for the delete user form fields
#[derive(Serialize, Deserialize)]
pub struct DeleteUserParams {
    user_id: String,
    current_password: String,
    confirm: String,
    csrf: String,
}

/// Accepts the post request to create a new user
/// TODO make it so you can only delete your own user (get the user from the session?)
pub async fn delete_user_post(
    req: HttpRequest,
    params: Form<DeleteUserParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if params.confirm != "DELETE ACCOUNT" {
        return Err(ServiceError::bad_request(&req, "Confirm string incorrect"));
    }
    let user = match get_user_by_userid(&params.user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(u) => u,
        None => {
            return Err(ServiceError::bad_request(
                &req,
                format!("User doesn't exist: {}", params.user_id),
            ))
        }
    };
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    // delete user from the DB
    delete_user(&params.user_id)
        .await
        .map_err(|e| ServiceError::bad_request(&req, e))?;
    // Redirect back to the users page
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/")
        .finish())
}
