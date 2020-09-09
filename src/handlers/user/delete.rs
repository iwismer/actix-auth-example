/// Module for endpoints related to deleting users
use crate::auth::{credentials::credential_validator, csrf::check_csrf};
use crate::db::user::delete_user;
use crate::models::{ServiceError, User};
use crate::templating::render_message;

use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// Struct for the delete user form fields
#[derive(Serialize, Deserialize)]
pub struct DeleteUserParams {
    current_password: String,
    confirm: String,
    csrf: String,
}

/// Accepts the post request to delete a user
pub async fn delete_user_post(
    req: HttpRequest,
    params: Form<DeleteUserParams>,
    user: User,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if params.confirm != "DELETE ACCOUNT" {
        return Err(ServiceError::bad_request(
            &req,
            "Confirm deletion string incorrect",
            true,
        ));
    }
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // delete user from the DB
    delete_user(&user.user_id)
        .await
        .map_err(|e| e.general(&req))?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Account Deleted",
            "Account Deleted Successfully.",
            "Your account was deleted successfully. We're sorry to see you go.",
            req.uri().path().to_string(),
            None,
        )?))
}
