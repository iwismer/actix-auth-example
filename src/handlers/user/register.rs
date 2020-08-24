/// Module for endpoints related to adding new users
use crate::auth::credentials::generate_user_id;
use crate::auth::credentials::{
    generate_password_hash, validate_email_rules, validate_password_rules, validate_username_rules,
};
use crate::auth::email::{generate_email_token, send_verification_email};
use crate::auth::session::{generate_session_token, get_req_user};
use crate::config;
use crate::db::email::{add_email_token, verify_email_token};
use crate::db::user::{add_user, get_user_by_username};
use crate::models::{ServiceError, User};
use crate::templating::render;
use actix_http::cookie::{Cookie, SameSite};
use actix_web::{web::Form, web::Query, HttpRequest, HttpResponse, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// serves the new user page
pub async fn register_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "register.html",
        req.uri().path().to_string(),
        None::<i32>,
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e))
        })?,
    )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct NewUserParams {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegSuccessContext {
    email: String,
}

/// Accepts the post request to create a new user
pub async fn register_post(
    req: HttpRequest,
    params: Form<NewUserParams>,
) -> Result<HttpResponse, ServiceError> {
    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
        ));
    }
    // check user doesn't already exist
    if get_user_by_username(&params.username)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            &format!("Creating user: user already exists: {}", params.username),
        ));
    }
    // create password hash
    let hash =
        generate_password_hash(&params.password).map_err(|s| ServiceError::general(&req, s))?;
    // insert user
    let user_id = generate_user_id().map_err(|s| ServiceError::general(&req, s))?;
    let user = User {
        // TODO Maybe just use the monfodb _id??
        user_id: user_id.to_string(),
        username: params.username.to_string(),
        email: params.email.to_string(),
        email_validated: false,
        pass_hash: hash,
        otp_token: None,
        otp_backups: None,
    };
    add_user(user.clone())
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    let email_token = generate_email_token().map_err(|s| ServiceError::general(&req, s))?;
    add_email_token(
        &user_id,
        &params.email,
        &email_token,
        Utc::now() + Duration::days(1),
    )
    .await
    .map_err(|s| ServiceError::general(&req, s))?;
    send_verification_email(&params.email, &email_token)
        .map_err(|s| ServiceError::general(&req, s))?;
    let session_token = generate_session_token(&user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(
            Cookie::build("session", session_token)
                .domain(config::COOKIE_DOMAIN.as_str())
                .path("/")
                .secure(*config::PRODUCTION)
                .max_age(Duration::days(1).num_seconds())
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .body(render(
            "reg_success.html",
            req.uri().path().to_string(),
            Some(RegSuccessContext {
                email: params.email.to_string(),
            }),
            Some(user),
        )?))
}

/// serves the new user page
pub async fn verify_email(
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse, ServiceError> {
    let token = query
        .get("token")
        .ok_or(ServiceError::bad_request(&req, "Missing token in request."))?;
    verify_email_token(&token)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "email_verify_success.html",
        req.uri().path().to_string(),
        None::<i32>,
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e))
        })?,
    )?))
}
