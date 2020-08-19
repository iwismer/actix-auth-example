/// Module for endpoints related to adding new users
use super::super::CSRFContext;
use crate::auth::credentials::generate_user_id;
use crate::auth::credentials::{
    credential_validator, generate_password_hash, validate_password_rules,
};
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::session::get_req_user;
use crate::db::auth::{get_user_by_userid, modify_user};
use crate::models::{ServiceError, User};
use crate::templating::render;
use actix_web::http::header;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// serves the new user page
pub async fn change_password_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let csrf_token = generate_csrf_token().map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok()
        .cookie(csrf_cookie(&csrf_token))
        .content_type("text/html")
        .body(render(
            "user/password.html",
            req.uri().path().to_string(),
            Some(CSRFContext { csrf: csrf_token }),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting requeset user: {}", e))
            })?,
        )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordParams {
    user_id: String,
    current_password: String,
    new_password: String,
    new_password_confirm: String,
    csrf: String,
}

/// Accepts the post request to create a new user
pub async fn change_password_post(
    req: HttpRequest,
    params: Form<ChangePasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
    // check user doesn't already exist
    let mut user = match get_user_by_userid(&params.user_id)
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
    // TODO validate current password
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    // create password hash
    let hash =
        generate_password_hash(&params.new_password).map_err(|s| ServiceError::general(&req, s))?;
    // insert user
    user.pass_hash = hash;
    modify_user(user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/user")
        .finish())
}
