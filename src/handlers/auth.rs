/// Module that handles all the authentication related enpoints in the website
use crate::auth::credentials::{
    credential_validator_username, generate_password_hash, validate_email_rules,
    validate_password_rules, validate_username_rules,
};
use crate::auth::email::send_password_reset_email;
use crate::auth::session::get_req_user;
use crate::auth::session::{generate_session_token, get_session_token};
use crate::auth::totp::{generate_totp_token, validate_totp};
use crate::db::email::verify_password_reset_token;
use crate::db::session::delete_session;
use crate::db::totp::{check_totp_token_exists, verify_totp_token};
use crate::db::user::{get_user_by_userid, get_user_by_username, modify_user};
use crate::models::ServiceError;
use crate::templating::{render, render_message};

use actix_http::cookie::Cookie;
use actix_web::http::header;
use actix_web::web::{Form, Query};
use actix_web::{Error, HttpMessage, HttpRequest, HttpResponse, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serves the login page
pub async fn login(req: HttpRequest) -> Result<HttpResponse, Error> {
    let show_totp = match req
        .cookies()
        .map_err(|_| ServiceError::bad_request(&req, "Can't find request cookies."))?
        .iter()
        .find(|c| c.name() == "totp")
    {
        Some(c) => {
            let totp_token = c.value().to_string();
            match check_totp_token_exists(&totp_token).await {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        None => false,
    };
    if show_totp {
        Ok(HttpResponse::Ok().content_type("text/html").body(render(
            "2fa.html",
            req.uri().path().to_string(),
            None::<i32>,
            None,
        )?))
    } else {
        Ok(HttpResponse::Ok().content_type("text/html").body(render(
            "login.html",
            req.uri().path().to_string(),
            None::<i32>,
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e))
            })?,
        )?))
    }
}

#[derive(Serialize, Deserialize)]
pub struct LoginParams {
    username: String,
    password: String,
    persist: Option<bool>,
}

/// Handler for the login post request
pub async fn login_post(
    req: HttpRequest,
    params: Form<LoginParams>,
) -> Result<HttpResponse, ServiceError> {
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(ServiceError::bad_request(&req, e));
    }
    if let Err(e) = validate_password_rules(&params.password, &params.password) {
        return Err(ServiceError::bad_request(&req, e));
    }
    match credential_validator_username(&params.username, &params.password)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(user) => match user.totp_token {
            Some(_) => {
                let totp_cookie =
                    generate_totp_token(&user.user_id, params.persist.unwrap_or(false))
                        .await
                        .map_err(|s| {
                            ServiceError::general(&req, format!("Error adding TOTP Token: {}", s))
                        })?;
                Ok(HttpResponse::SeeOther()
                    .header(header::LOCATION, "/login")
                    .cookie(totp_cookie)
                    .finish())
            }
            None => {
                let cookie = generate_session_token(&user.user_id, params.persist.unwrap_or(false))
                    .await
                    .map_err(|s| ServiceError::general(&req, s))?;

                info!("Successfully logged in user: {}", params.username);
                Ok(HttpResponse::SeeOther()
                    .header(header::LOCATION, "/zone")
                    .cookie(cookie)
                    .finish())
            }
        },
        None => {
            info!("Invalid user: {}", &params.username);
            Err(ServiceError::unauthorized(&req, "Invalid credentials."))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TotpParams {
    code: String,
}

/// Handler for the login post request
pub async fn totp_post(
    req: HttpRequest,
    params: Form<TotpParams>,
) -> Result<HttpResponse, ServiceError> {
    let totp_token = req
        .cookies()
        .map_err(|_| ServiceError::bad_request(&req, "Can't find request cookies."))?
        .iter()
        .find(|c| c.name() == "totp")
        .ok_or(ServiceError::bad_request(&req, "Missing TOTP Cookie."))?
        .value()
        .to_string();
    // Check that it is a valid TOTP token, and get the user_ID and persist value
    let (user_id, persist) = verify_totp_token(&totp_token)
        .await
        .map_err(|s| ServiceError::bad_request(&req, format!("Invalid TOTP Token: {}", s)))?;
    // Check the code is correct
    match validate_totp(&user_id, &params.code).await {
        Ok(_) => {
            let user = get_user_by_userid(&user_id)
                .await
                .map_err(|s| ServiceError::general(&req, format!("Error getting user: {}", s)))?
                .ok_or(ServiceError::general(
                    &req,
                    format!("User not found: {}", &user_id),
                ))?;
            let cookie = generate_session_token(&user.user_id, persist)
                .await
                .map_err(|s| ServiceError::general(&req, s))?;
            info!("Successfully logged in user: {}", user.username);
            Ok(HttpResponse::SeeOther()
                .header(header::LOCATION, "/zone")
                .cookie(cookie)
                .del_cookie(&Cookie::named("totp"))
                .finish())
        }
        Err(e) => {
            info!("Invalid TOTP for user {}: {}", user_id, e);
            Err(ServiceError::unauthorized(&req, "Invalid TOTP."))
        }
    }
}

/// Serves the login page
pub async fn forgot_password_get(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "forgot_password.html",
        req.uri().path().to_string(),
        None::<i32>,
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e))
        })?,
    )?))
}

#[derive(Serialize, Deserialize)]
pub struct ForgotPasswordParams {
    username: String,
    email: String,
}

/// Handler for the login post request
pub async fn forgot_password_post(
    req: HttpRequest,
    params: Form<ForgotPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(ServiceError::bad_request(&req, e));
    }
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(ServiceError::bad_request(&req, e));
    }
    match get_user_by_username(&params.username)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(user) => {
            if user.email_validated && user.email == params.email {
                send_password_reset_email(&user.user_id, &user.email)
                    .await
                    .map_err(|s| ServiceError::general(&req, s))?;
            }
        }
        None => {}
    };
    // Always send back a success message, unless there was a server error.
    // This way an attacker doesn't know if the username and email are valid/matching.
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Password Reset Sent",
            "A password reset request has been sent.",
            "A password reset request has been sent to the account. Please check your email for a message and click the link to reset your password.",
            req.uri().path().to_string(),
            None,
        )?))
}

#[derive(Serialize, Deserialize)]
pub struct ResetPasswordContext {
    username: String,
    user_id: String,
    token: String,
}

/// serves the new user page
pub async fn password_reset_get(
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse, ServiceError> {
    let token = query
        .get("token")
        .ok_or(ServiceError::bad_request(&req, "Missing token in request."))?;
    let user = verify_password_reset_token(&token, false)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "reset_password.html",
        req.uri().path().to_string(),
        Some(ResetPasswordContext {
            username: user.username.to_string(),
            user_id: user.user_id.to_string(),
            token: token.to_string(),
        }),
        None,
    )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ResetPasswordParams {
    user_id: String,
    token: String,
    password: String,
    password_confirm: String,
}

/// Accepts the post request to create a new user
pub async fn password_reset_post(
    req: HttpRequest,
    params: Form<ResetPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error resetting password: {}", e),
        ));
    }
    let mut user = verify_password_reset_token(&params.token, true)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    // check user doesn't already exist
    if user.user_id != params.user_id {
        return Err(ServiceError::bad_request(&req, "User/token mismatch."));
    }
    // create password hash
    let hash =
        generate_password_hash(&params.password).map_err(|s| ServiceError::general(&req, s))?;
    user.pass_hash = hash;
    modify_user(user.clone())
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Password Reset",
            "Password successfully reset.",
            "Go to the login page to login with your new password.",
            req.uri().path().to_string(),
            None,
        )?))
}

/// Logout get request handler
pub async fn logout(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let token = get_session_token(&req);
    match token {
        Some(t) => {
            delete_session(&t)
                .await
                .map_err(|s| ServiceError::general(&req, s))?;
            info!("Successfully logged out user");
        }
        None => {
            warn!("Token not found in request to log out");
        }
    }
    Ok(HttpResponse::SeeOther()
        .header(header::LOCATION, "/")
        .del_cookie(&Cookie::named("session"))
        .del_cookie(&Cookie::named("csrf"))
        .finish())
}
