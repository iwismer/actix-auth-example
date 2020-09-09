/// Module that contains all the functions related to CSRF.
use crate::config;
use crate::models::{ServerError, ServiceError};

use actix_http::cookie::{Cookie, SameSite};
use actix_web::{HttpMessage, HttpRequest};

/// Generate a new random csrf token
pub fn generate_csrf_token() -> Result<String, ServerError> {
    super::generate_token()
}

/// Checks that the CSRF token contained in the submitted form and the CSRF token in the request cookie match.
pub async fn check_csrf<T: Into<String>>(
    form_csrf: Option<T>,
    req: &HttpRequest,
) -> Result<(), ServiceError> {
    // Get the csrf token from the form
    let form_csrf_unwrapped = form_csrf
        .ok_or(ServiceError::bad_request(
            &req,
            "No CSRF token found in form.",
            true,
        ))?
        .into();
    // Get the CSRF cookie from the request
    match req
        .cookies()
        .map_err(|e| {
            ServiceError::general(
                &req,
                &format!("Error getting cookies from request: {}", e),
                false,
            )
        })?
        .iter()
        .find(|c| c.name() == "csrf")
        .map(|c| c.value().to_string())
    {
        Some(cookie) => match cookie == form_csrf_unwrapped {
            true => Ok(()),
            false => Err(ServiceError::unauthorized(
                &req,
                "CSRF tokens don't match.",
                true,
            )),
        },
        None => Err(ServiceError::unauthorized(
            &req,
            "No CSRF cookies found.",
            true,
        )),
    }
}

/// Generate a csrf cookie from the supplied token
pub fn csrf_cookie(csrf_token: &str) -> Cookie {
    Cookie::build("csrf", csrf_token.to_string())
        .domain(config::COOKIE_DOMAIN.as_str())
        .path("/")
        .secure(*config::PRODUCTION)
        .http_only(true)
        .same_site(SameSite::Strict)
        .finish()
}
