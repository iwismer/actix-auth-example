/// Module that contains all the handler functions for the web endpoints in the website.
use crate::models::ServiceError;
use crate::templating::render;
use actix_web::{Error, HttpRequest, HttpResponse, Result};
use serde::Serialize;

pub mod auth;
pub mod user;

#[derive(Serialize)]
struct CSRFContext {
    csrf: String,
}

/// 404 handler
pub async fn p404(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    Err(ServiceError::not_found(&req, "Page not found."))
}

/// Top level page
pub async fn page(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        &format!(
            "{}.html",
            req.match_info().get("page").ok_or(ServiceError::general(
                &req,
                "Page match info no available. Something is very wrong."
            ))?
        ),
        req.uri().path().to_string(),
        None::<i32>,
    )?))
}

/// Home Page
pub async fn home(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "home.html",
        req.uri().path().to_string(),
        None::<i32>,
    )?))
}
