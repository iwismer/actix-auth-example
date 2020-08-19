/// Module for endpoints related to adding new users
use crate::auth::credentials::generate_user_id;
use crate::auth::credentials::{
    generate_password_hash, validate_password_rules, validate_username_rules,
};
use crate::auth::session::get_req_user;
use crate::db::auth::{add_user, get_user_by_username};
use crate::models::{ServiceError, User};
use crate::templating::render;
use actix_web::http::header;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use regex::Regex;
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
    // TODO check for a better regex
    let re = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();
    if !re.is_match(&params.email) {
        return Err(ServiceError::bad_request(
            &req,
            "Creating user: invalid email.",
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
    add_user(User {
        // TODO Maybe just use the monfodb _id??
        user_id: generate_user_id().map_err(|s| ServiceError::general(&req, s))?,
        username: params.username.to_string(),
        email: params.email.to_string(),
        email_validated: false,
        pass_hash: hash,
        otp_token: None,
        otp_backups: None,
    })
    .await
    .map_err(|s| ServiceError::bad_request(&req, s))?;
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/")
        .finish())
}
