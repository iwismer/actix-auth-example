/// Module that handles all the authentication related endpoints in the website
use crate::auth::credentials::{
    credential_validator_username_email, generate_password_hash, validate_email_rules,
    validate_password_rules, validate_username_rules,
};
use crate::auth::email::send_password_reset_email;
use crate::auth::session::{generate_session_token, get_session_token_http_request};
use crate::auth::totp::{generate_totp_token, validate_totp};
use crate::db::email::verify_password_reset_token;
use crate::db::session::delete_session;
use crate::db::totp::{check_totp_token_exists, verify_totp_token};
use crate::db::user::{get_user_by_userid, get_user_by_username, modify_user};
use crate::models::ServiceError;
use crate::templating::{render, render_message};
use crate::{config, context};

use actix_web::cookie::Cookie;
use actix_web::http::header;
use actix_web::web::{Form, Query};
use actix_web::{Error, HttpRequest, HttpResponse, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serves the login/2fa page
pub async fn login(req: HttpRequest) -> Result<HttpResponse, Error> {
    let show_totp = match req
        .cookies()
        .map_err(|_| ServiceError::bad_request(&req, "Can't find request cookies.", false))?
        .iter()
        .find(|c| c.name() == "totp")
    {
        Some(c) => check_totp_token_exists(c.value()).await.is_ok(),
        None => false,
    };
    if show_totp {
        Ok(HttpResponse::Ok().content_type("text/html").body(render(
            "2fa.html",
            req.uri().path().to_string(),
            None,
            None,
        )?))
    } else {
        Ok(HttpResponse::Ok().content_type("text/html").body(render(
            "login.html",
            req.uri().path().to_string(),
            None,
            None,
        )?))
    }
}

/// Form parameters for the login form.
#[derive(Serialize, Deserialize)]
pub struct LoginParams {
    identifier: String,
    password: String,
    persist: Option<bool>,
}

/// Handler for the login post request
pub async fn login_post(
    req: HttpRequest,
    params: Form<LoginParams>,
) -> Result<HttpResponse, ServiceError> {
    // Check the username is valid
    if validate_username_rules(&params.identifier).is_err()
        && validate_email_rules(&params.identifier).is_err()
    {
        return Err(ServiceError::bad_request(
            &req,
            "Invalid Username/Email",
            true,
        ));
    }
    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password) {
        return Err(e.bad_request(&req));
    }
    match credential_validator_username_email(&params.identifier, &params.password)
        .await
        .map_err(|s| s.general(&req))?
    {
        Some(user) => match user.totp_active {
            true => {
                // Generate the token that identifies what login flow the TOTP belongs to
                let totp_cookie =
                    generate_totp_token(&user.user_id, params.persist.unwrap_or(false))
                        .await
                        .map_err(|s| s.general(&req))?;
                Ok(HttpResponse::SeeOther()
                    .append_header((header::LOCATION, "/login"))
                    .cookie(totp_cookie)
                    .finish())
            }
            false => {
                let cookie = generate_session_token(&user.user_id, params.persist.unwrap_or(false))
                    .await
                    .map_err(|s| ServiceError::general(&req, s.message, false))?;

                info!("Successfully logged in user: {}", params.identifier);
                Ok(HttpResponse::SeeOther()
                    .append_header((header::LOCATION, "/zone"))
                    .cookie(cookie)
                    .finish())
            }
        },
        None => {
            info!("Invalid credentials: {}", &params.identifier);
            Err(ServiceError::unauthorized(
                &req,
                "Invalid credentials.",
                true,
            ))
        }
    }
}

/// Form parameters for TOTP post requests
#[derive(Serialize, Deserialize)]
pub struct TotpParams {
    code: String,
}

/// Handler for the TOTP post request
pub async fn totp_post(
    req: HttpRequest,
    params: Form<TotpParams>,
) -> Result<HttpResponse, ServiceError> {
    let totp_token = req
        .cookies()
        .map_err(|_| ServiceError::bad_request(&req, "Can't find request cookies.", false))?
        .iter()
        .find(|c| c.name() == "totp")
        .ok_or(ServiceError::bad_request(
            &req,
            "Missing TOTP Cookie.",
            true,
        ))?
        .value()
        .to_string();
    // Check that it is a valid TOTP token, and get the user_ID and persist value
    let (user_id, persist) = verify_totp_token(&totp_token)
        .await
        .map_err(|s| ServiceError::bad_request(&req, format!("Invalid TOTP Token: {}", s), true))?;

    let mut user = get_user_by_userid(&user_id)
        .await
        .map_err(|s| ServiceError::general(&req, format!("Error getting user: {}", s), false))?
        .ok_or(ServiceError::general(
            &req,
            format!("User not found: {}", &user_id),
            false,
        ))?;

    // Check the code is correct, return an error if not
    validate_totp(&mut user, &params.code).await.map_err(|e| {
        info!("Invalid TOTP for user {}: {}", user_id, e);
        ServiceError::unauthorized(&req, "Invalid TOTP.", true)
    })?;

    let cookie = generate_session_token(&user.user_id, persist)
        .await
        .map_err(|s| ServiceError::general(&req, s.message, false))?;
    info!("Successfully logged in user: {}", user.username);
    let mut totp_cookie = Cookie::build("totp", "")
        .domain(config::COOKIE_DOMAIN.as_str())
        .path("/")
        .finish();
    totp_cookie.make_removal();
    Ok(HttpResponse::SeeOther()
        .append_header((header::LOCATION, "/zone"))
        .cookie(cookie)
        .cookie(totp_cookie)
        .finish())
}

/// Serves the forgot password form
pub async fn forgot_password_get(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "forgot_password.html",
        req.uri().path().to_string(),
        None,
        None,
    )?))
}

/// Form params for the forgot password form
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
    // Check the username is valid
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(e.bad_request(&req));
    }
    // Check the password is valid
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(e.bad_request(&req));
    }
    match get_user_by_username(&params.username)
        .await
        .map_err(|s| s.general(&req))?
    {
        Some(user) => {
            if user.email_validated && user.email == params.email {
                send_password_reset_email(&user.user_id, &user.email)
                    .await
                    .map_err(|s| ServiceError::general(&req, s.message, false))?;
            }
        }
        None => {}
    };
    // Always send back a success message unless there was a server error.
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

/// serves the password reset page
pub async fn password_reset_get(
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse, ServiceError> {
    let token = query.get("token").ok_or(ServiceError::bad_request(
        &req,
        "Missing token in request.",
        true,
    ))?;
    // TODO give a better error message
    let user = verify_password_reset_token(&token, false)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "reset_password.html",
        req.uri().path().to_string(),
        Some(context! {
            "username" => &user.username,
            "user_id" => &user.user_id,
            "token" => &token
        }),
        None,
    )?))
}

/// Parameters for the reset password form
#[derive(Serialize, Deserialize)]
pub struct ResetPasswordParams {
    user_id: String,
    token: String,
    password: String,
    password_confirm: String,
}

/// Accepts the post request for resetting a password
pub async fn password_reset_post(
    req: HttpRequest,
    params: Form<ResetPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    let mut user = verify_password_reset_token(&params.token, true)
        .await
        .map_err(|s| s.general(&req))?;
    // Check the new password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(e.bad_request(&req));
    }
    // check user matches the one from the token
    if user.user_id != params.user_id {
        return Err(ServiceError::bad_request(
            &req,
            "User/token mismatch.",
            true,
        ));
    }
    // create password hash
    let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;
    // Update the user
    user.pass_hash = hash;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
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

/// Logout request handler
pub async fn logout(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let token = get_session_token_http_request(&req);
    match token {
        Some(t) => {
            delete_session(&t).await.map_err(|s| s.general(&req))?;
            info!("Successfully logged out user");
        }
        None => {
            warn!("Token not found in request to log out");
        }
    }
    let mut session_cookie = Cookie::build("session", "")
        .domain(config::COOKIE_DOMAIN.as_str())
        .path("/")
        .finish();
    session_cookie.make_removal();
    let mut csrf_cookie = Cookie::build("csrf", "")
        .domain(config::COOKIE_DOMAIN.as_str())
        .path("/")
        .finish();
    csrf_cookie.make_removal();
    Ok(HttpResponse::SeeOther()
        .append_header((header::LOCATION, "/"))
        .cookie(session_cookie)
        .cookie(csrf_cookie)
        .finish())
}
