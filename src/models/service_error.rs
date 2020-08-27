/// Module for the ServiceError struct.
use crate::config;
use crate::context;
use crate::templating::render;

use actix_web::http::{header, StatusCode};
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use log::error;
use std::fmt;

/// A generic error for the web server.
// TODO pass the request to the error? That way we can get the user
#[derive(Debug)]
pub struct ServiceError {
    pub code: StatusCode,
    pub path: String,
    pub message: String,
}

impl ServiceError {
    pub fn unauthorized<T: Into<String>>(req: &HttpRequest, message: T) -> Self {
        ServiceError {
            code: StatusCode::UNAUTHORIZED,
            path: req.uri().path().to_string(),
            message: message.into(),
        }
    }

    pub fn general<T: Into<String>>(req: &HttpRequest, message: T) -> Self {
        ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: req.uri().path().to_string(),
            message: message.into(),
        }
    }

    pub fn bad_request<T: Into<String>>(req: &HttpRequest, message: T) -> Self {
        ServiceError {
            code: StatusCode::BAD_REQUEST,
            path: req.uri().path().to_string(),
            message: message.into(),
        }
    }

    pub fn not_found<T: Into<String>>(req: &HttpRequest, message: T) -> Self {
        ServiceError {
            code: StatusCode::NOT_FOUND,
            path: req.uri().path().to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        error!("Path: {} | Message: {}", self.path, self.message);
        let mut status_code = self.code;
        // try to add the domain to the start of the path
        let url = match config::DOMAIN.join(&self.path) {
            Ok(u) => u.to_string(),
            Err(_) => self.path.to_string(),
        };
        let body = match render(
            "error.html",
            self.path.to_string(),
            Some(context! {
                "page" => &url,
                "code" => &self.code.to_string(),
                "message" => &match self.path.starts_with("/edit") {
                    true => Some(self.message.to_string()),
                    false => None,
                }
            }),
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Error when rendering error template: {}", e);
                status_code = StatusCode::INTERNAL_SERVER_ERROR;
                format!("500 Internal Server Error.")
            }
        };
        HttpResponse::build(status_code)
            .content_type("text/html")
            .if_true(status_code == StatusCode::UNAUTHORIZED, |b| {
                b.header(header::WWW_AUTHENTICATE, "Cookie");
            })
            .body(body)
    }
}
