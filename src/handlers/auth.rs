use crate::auth::session::get_req_user;
use crate::auth::totp::{generate_totp_token, validate_totp};
/// Module that handles all the authentication related enpoints in the website
use crate::auth::{
    credentials::credential_validator_username, session::generate_session_token,
    session::get_session_token,
};
use crate::db::session::delete_session;
use crate::db::totp::{check_totp_token_exists, verify_totp_token};
use crate::db::user::get_user_by_userid;
use crate::models::ServiceError;
use crate::templating::render;
use actix_http::cookie::Cookie;
use actix_web::{http::header, web::Form, Error};
use actix_web::{HttpMessage, HttpRequest, HttpResponse};
use log::{info, warn};
use serde::{Deserialize, Serialize};

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
    if params.username.bytes().len() > 8192 || params.password.bytes().len() > 8192 {
        return Err(ServiceError::bad_request(
            &req,
            "Username/Password too long (> 8192 bytes)",
        ));
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
