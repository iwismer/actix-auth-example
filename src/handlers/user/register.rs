/// Module for endpoints related to adding new users
use crate::auth::credentials::generate_user_id;
use crate::auth::credentials::{
    generate_password_hash, validate_email_rules, validate_password_rules, validate_username_rules,
};
use crate::auth::session::{generate_session_token, get_req_user};
use crate::config;
use crate::db::auth::{add_user, get_user_by_username};
use crate::models::{ServiceError, User};
use crate::templating::render;
use actix_http::cookie::{Cookie, SameSite};
use actix_web::http::header;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use chrono::Duration;
use serde::{Deserialize, Serialize};
/// serves the new user page
pub async fn register_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "register.html",
        req.uri().path().to_string(),
        None::<i32>,
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting requeset user: {}", e))
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
    add_user(user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    let session_token = generate_session_token(&user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/zone")
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
        .finish())
}
