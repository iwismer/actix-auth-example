/// Module for endpoints related to adding new users
use crate::auth::credentials::{
    generate_password_hash, generate_user_id, validate_email_rules, validate_password_rules,
    validate_username_rules,
};
use crate::auth::email::validate_email;
use crate::auth::session::generate_session_token;
use crate::db::user::{add_user, get_user_by_email, get_user_by_username};
use crate::models::{ServerError, ServiceError, User};
use crate::templating::{render, render_message};

use actix_web::web::Form;
use actix_web::{HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// serves the registration page
pub async fn register_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "register.html",
        req.uri().path().to_string(),
        None,
        None,
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
            true,
        ));
    }
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    // check user doesn't already exist
    if get_user_by_username(&params.username)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            &format!(
                "Cannot create user: {} as that username is taken",
                params.username
            ),
            true,
        ));
    }
    if get_user_by_email(&params.email)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            &format!("Cannot create user for email: {} as that email is already associated with an account.", params.email),
            true,
        ));
    }
    // create password hash
    let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;
    // insert user
    let mut user = User {
        user_id: "".to_string(),
        username: params.username.to_string(),
        email: params.email.to_string(),
        email_validated: false,
        pass_hash: hash,
        totp_active: false,
        totp_token: None,
        totp_backups: None,
        profile_pic: None,
    };
    let mut user_error: Option<ServerError> = None;
    let mut user_id = "".to_string();
    for i in 0..10 {
        user_id = generate_user_id().map_err(|s| s.general(&req))?;
        user.user_id = user_id.to_string();
        match add_user(&user).await {
            Ok(_) => {
                user_error = None;
                break;
            }
            Err(e) => {
                log::warn!(
                    "Problem creating user ID for new user {} (attempt {}/10): {}",
                    user_id,
                    i + 1,
                    e
                );
                user_error = Some(e);
            }
        }
    }
    if let Some(e) = user_error {
        return Err(ServiceError::general(
            &req,
            format!("Error generating user ID: {}", e),
            false,
        ));
    }
    // Send a validation email
    validate_email(&user_id, &params.email)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(generate_session_token(&user_id, false)
        .await
        .map_err(|s| ServiceError::general(&req, s.message, false))?)
        .body(render_message(
            "Registration Success",
            "Welcome! You've successfully registered.",
            &format!("A verification email has been sent to: {}. Follow the link in the message to verify your email. The link will only be valid for 24 hours.", params.email),
            req.uri().path().to_string(),
            Some(user),
        )?))
}
