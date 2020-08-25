/// Module for endpoints related to adding new users
use crate::auth::email::validate_email;
use crate::auth::session::get_req_user;
use crate::db::email::verify_email_token;
use crate::models::ServiceError;
use crate::templating::render_message;

use actix_web::web::Query;
use actix_web::{HttpRequest, HttpResponse, Result};
use std::collections::HashMap;

/// Accepts the post request to create a new user
pub async fn verify_email_get(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let user = get_req_user(&req)
        .await
        .map_err(|e| ServiceError::general(&req, format!("Error getting request user: {}", e)))?
        .ok_or(ServiceError::bad_request(
            &req,
            "No user found associated with request.",
        ))?;
    if user.email_validated {
        return Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Email Validation",
            "Email already validated.",
            "The email for your account has already been validated, so another validation has not been sent.",
            req.uri().path().to_string(),
            Some(user),
        )?));
    }
    validate_email(&user.user_id, &user.email)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    log::debug!("Sent validation email");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Email Validation",
            "Email Validation Sent Successfully.",
            "The email associated with your account has had a validation email sent to it.",
            req.uri().path().to_string(),
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
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Email Verified",
            "Email Verified Successfully.",
            "You can now close this tab.",
            req.uri().path().to_string(),
            get_req_user(&req).await.map_err(|e| {
                ServiceError::general(&req, format!("Error getting request user: {}", e))
            })?,
        )?))
}
