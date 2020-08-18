/// Module for endpoints related to adding new users
use super::super::CSRFContext;
use crate::auth::credentials::generate_password_hash;
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::db::auth::{add_user, get_user};
use crate::models::ServiceError;
use crate::templating::render;
use actix_web::http::header;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// serves the new user page
pub async fn register_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let csrf_token = generate_csrf_token().map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok()
        .cookie(csrf_cookie(&csrf_token))
        .content_type("text/html")
        .body(render(
            "users/new.html",
            req.uri().path().to_string(),
            Some(CSRFContext { csrf: csrf_token }),
        )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct NewUserParams {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
    csrf: String,
}

/// Accepts the post request to create a new user
pub async fn register_post(
    req: HttpRequest,
    params: Form<NewUserParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if params.username.len() == 0 || params.password.len() == 0 {
        return Err(ServiceError::bad_request(
            &req,
            "Creating user: Empty username/password.",
        ));
    }
    if params.password.len() < 10 {
        return Err(ServiceError::bad_request(
            &req,
            "Password must be at least 10 characters.",
        ));
    }
    if params.username.bytes().len() > 8192 || params.password.bytes().len() > 8192 {
        return Err(ServiceError::bad_request(
            &req,
            "Username/Password too long (> 8192 bytes).",
        ));
    }
    // check passwords match
    if params.password != params.password_confirm {
        return Err(ServiceError::bad_request(
            &req,
            "Creating user: passwords don't match.",
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
    if get_user(&params.username)
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
    add_user(&params.username, &hash)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/edit/users")
        .finish())
}
