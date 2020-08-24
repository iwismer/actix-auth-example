/// Module for endpoints related to adding new users
use super::super::CSRFContext;
use crate::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
    validate_username_rules,
};
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::email::{generate_email_token, send_verification_email};
use crate::auth::session::get_req_user;
use crate::db::email::add_email_token;
use crate::db::user::{get_user_by_userid, get_user_by_username, modify_user};
use crate::models::ServiceError;
use crate::templating::render;
use actix_web::http::header;
use actix_web::{web::Form, Error, HttpRequest, HttpResponse, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

pub async fn get_page(req: HttpRequest) -> Result<HttpResponse, Error> {
    let csrf_token = generate_csrf_token().map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(csrf_cookie(&csrf_token))
        .body(render(
            &format!(
                "user/{}.html",
                req.match_info().get("page").ok_or(ServiceError::general(
                    &req,
                    "Page match info no available. Something is very wrong."
                ))?
            ),
            req.uri().path().to_string(),
            Some(CSRFContext { csrf: csrf_token }),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e))
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

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangeUsernameParams {
    user_id: String,
    current_password: String,
    new_username: String,
    csrf: String,
}

/// Accepts the post request to create a new user
pub async fn change_username_post(
    req: HttpRequest,
    params: Form<ChangeUsernameParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if let Err(e) = validate_username_rules(&params.new_username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
    if let Some(_) = get_user_by_username(&params.new_username)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: Username already in use"),
        ));
    }
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
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    // insert user
    user.username = params.new_username.to_string();
    modify_user(user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/user")
        .finish())
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangeEmailParams {
    user_id: String,
    current_password: String,
    new_email: String,
    csrf: String,
}

/// Accepts the post request to create a new user
pub async fn change_email_post(
    req: HttpRequest,
    params: Form<ChangeEmailParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if let Err(e) = validate_email_rules(&params.new_email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
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
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    let email_token = generate_email_token().map_err(|s| ServiceError::general(&req, s))?;
    add_email_token(
        &user.user_id,
        &params.new_email,
        &email_token,
        Utc::now() + Duration::days(1),
    )
    .await
    .map_err(|s| ServiceError::general(&req, s))?;
    send_verification_email(&params.new_email, &email_token)
        .map_err(|s| ServiceError::general(&req, s))?;
    // insert user
    user.email = params.new_email.to_string();
    user.email_validated = false;
    modify_user(user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/user")
        .finish())
}
