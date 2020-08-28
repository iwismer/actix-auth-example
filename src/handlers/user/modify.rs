/// Module for endpoints related to modifying an existing user.
use crate::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
    validate_username_rules,
};
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::email::validate_email;
use crate::auth::session::get_req_user;
use crate::context;
use crate::db::user::{get_user_by_username, modify_user};
use crate::models::ServiceError;
use crate::templating::{render, render_message};

use actix_web::{web::Form, Error, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// Generic get page for the modification pages.
pub async fn get_page(req: HttpRequest) -> Result<HttpResponse, Error> {
    let csrf_token = generate_csrf_token().map_err(|s| ServiceError::general(&req, s, false))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(csrf_cookie(&csrf_token))
        .body(render(
            &format!(
                "user/{}.html",
                req.match_info().get("page").ok_or(ServiceError::general(
                    &req,
                    "Page match info no available. Something is very wrong.",
                    false
                ))?
            ),
            req.uri().path().to_string(),
            Some(context! { "csrf" => &csrf_token }),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e), false)
            })?,
        )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordParams {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
    csrf: String,
}

/// Accepts the post request to change a user's password
pub async fn change_password_post(
    req: HttpRequest,
    params: Form<ChangePasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e), false)
        })?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e, false))?
    {
        return Err(ServiceError::bad_request(
            &req,
            "Invalid current password",
            true,
        ));
    }
    // create password hash
    let hash = generate_password_hash(&params.new_password)
        .map_err(|s| ServiceError::general(&req, s, false))?;
    // insert user
    user.pass_hash = hash;
    modify_user(&user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s, false))?;
    log::debug!("Modified user password");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Password Changed",
            "Password Changed Successfully.",
            "The password for your account was updated successfully. Make sure you update the new password in your password manager.",
            req.uri().path().to_string(),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e), false)
            })?,
        )?))
}

/// Form parameters for changing a username.
#[derive(Serialize, Deserialize)]
pub struct ChangeUsernameParams {
    current_password: String,
    new_username: String,
    csrf: String,
}

/// Accepts the post request to change a user's username
pub async fn change_username_post(
    req: HttpRequest,
    params: Form<ChangeUsernameParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if let Err(e) = validate_username_rules(&params.new_username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    // Check that the username is not in use. This is also checked by the DB.
    if get_user_by_username(&params.new_username)
        .await
        .map_err(|s| ServiceError::general(&req, s, false))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: Username already in use"),
            true,
        ));
    }
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e), false)
        })?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e, false))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // update user
    user.username = params.new_username.to_string();
    modify_user(&user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s, false))?;
    log::debug!("Modified user username");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Username Changed",
            "Username Changed Successfully.",
            "The username for your account was updated successfully. Make sure you update to the new username in your password manager.",
            req.uri().path().to_string(),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e), false)
            })?,
        )?))
}

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize)]
pub struct ChangeEmailParams {
    current_password: String,
    new_email: String,
    csrf: String,
}

/// Accepts the post request to change a user's email.
pub async fn change_email_post(
    req: HttpRequest,
    params: Form<ChangeEmailParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Check the email is valid
    if let Err(e) = validate_email_rules(&params.new_email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e), false)
        })?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e, false))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // Send a validation email
    validate_email(&user.user_id, &params.new_email)
        .await
        .map_err(|s| ServiceError::general(&req, s, false))?;
    // update user
    user.email = params.new_email.to_string();
    user.email_validated = false;
    modify_user(&user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s, false))?;
    log::debug!("Modified user email");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Email Changed",
            "Email Changed Successfully.",
            "The email for your account was updated successfully. A verification email has been sent to the new email.",
            req.uri().path().to_string(),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e), false)
            })?,
        )?))
}
