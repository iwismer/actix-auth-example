use crate::auth::session::get_req_user;
/// Module that handles all the authentication related enpoints in the website
use crate::auth::{
    credentials::credential_validator, session::generate_session_token, session::get_session_token,
};
use crate::config;
use crate::db::auth::delete_session;
use crate::db::auth::get_user_username;
use crate::models::ServiceError;
use crate::templating::render;
use actix_http::cookie::{Cookie, SameSite};
use actix_web::{http::header, web, Error};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Duration;
use log::{info, warn};
use serde::{Deserialize, Serialize};

/// Serves the login page
pub async fn login(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "login.html",
        req.uri().path().to_string(),
        None::<i32>,
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting requeset user: {}", e))
        })?,
    )?))
}

#[derive(Serialize, Deserialize)]
pub struct LoginParams {
    username: String,
    password: String,
}

/// Handler for the login post request
pub async fn login_post(
    req: HttpRequest,
    params: web::Form<LoginParams>,
) -> Result<HttpResponse, ServiceError> {
    if params.username.bytes().len() > 8192 || params.password.bytes().len() > 8192 {
        return Err(ServiceError::bad_request(
            &req,
            "Username/Password too long (> 8192 bytes)",
        ));
    }
    if credential_validator(&params.username, &params.password)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        let user = get_user_username(&params.username)
            .await
            .map_err(|s| ServiceError::general(&req, s))?
            .ok_or(ServiceError::unauthorized(
                &req,
                "Invalid username/password.",
            ))?;
        let session_token = generate_session_token(&user.user_id)
            .await
            .map_err(|s| ServiceError::general(&req, s))?;
        info!("Successfully logged in user: {}", params.username);
        Ok(HttpResponse::SeeOther()
            .header(header::LOCATION, "/")
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
    } else {
        info!("Invalid password for user: {}", &params.username);
        Err(ServiceError::unauthorized(
            &req,
            "Invalid username/password.",
        ))
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
        }
        None => {
            warn!("Token not found in request to log out");
        }
    }
    info!("Successfully logged out user");
    Ok(HttpResponse::SeeOther()
        .header(header::LOCATION, "/")
        .del_cookie(&Cookie::named("session"))
        .del_cookie(&Cookie::named("csrf"))
        .finish())
}
