/// Module for endpoints related to adding new users
use crate::auth::email::validate_email;
use crate::auth::session::get_req_user;
use crate::models::ServiceError;
use crate::templating::render_message;

use actix_web::{HttpRequest, HttpResponse, Result};

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
