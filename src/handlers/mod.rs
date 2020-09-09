/// Module that contains all the handler functions for the web endpoints in the website.
use crate::models::{ServiceError, User};
use crate::templating::render;

use actix_web::{Error, HttpRequest, HttpResponse, Result};

pub mod auth;
pub mod user;

/// 404 handler
pub async fn p404(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Err(ServiceError::not_found(&req, "Page not found.", true))
}

/// Top level page
pub async fn page(req: HttpRequest, user: Option<User>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        &format!(
            "{}.html",
            req.match_info().get("page").ok_or(ServiceError::general(
                &req,
                "Page match info no available. Something is very wrong.",
                false
            ))?
        ),
        req.uri().path().to_string(),
        None,
        user,
    )?))
}

/// Home Page when not logged in
pub async fn home(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "home.html",
        req.uri().path().to_string(),
        None,
        None,
    )?))
}

/// Home Page when logged in
pub async fn zone(req: HttpRequest, user: User) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "zone.html",
        req.uri().path().to_string(),
        None,
        Some(user),
    )?))
}
