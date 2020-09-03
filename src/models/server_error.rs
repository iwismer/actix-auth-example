/// A module containing an error for a backend error.
/// This error will be either transformed or dropped before being shown to the user.
use crate::models::ServiceError;

use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use std::fmt;

#[derive(Debug, Clone)]
pub enum ErrorCode {
    ServerError,
    InputError,
}

/// A generic error for the web server.
#[derive(Debug, Clone)]
pub struct ServerError {
    pub code: ErrorCode,
    pub message: String,
    pub show_message: bool,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} {}", self.code, self.message)
    }
}

#[macro_export]
macro_rules! err_server {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        log::error!("{}", msg);
        ServerError {
            code: crate::models::ErrorCode::ServerError,
            message: msg,
            show_message: false,
        }
    }};
}

#[macro_export]
macro_rules! err_server_show {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        log::error!("{}", msg);
        ServerError {
            code: crate::models::ErrorCode::ServerError,
            message: msg,
            show_message: true,
        }
    }};
}

#[macro_export]
macro_rules! err_input {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        log::error!("{}", msg);
        ServerError {
            code: crate::models::ErrorCode::InputError,
            message: msg,
            show_message: true,
        }
    }};
}

impl ServerError {
    pub fn not_found(&self, req: &HttpRequest) -> ServiceError {
        ServiceError {
            code: StatusCode::NOT_FOUND,
            path: req.uri().path().to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }

    pub fn unauthorized(&self, req: &HttpRequest) -> ServiceError {
        ServiceError {
            code: StatusCode::UNAUTHORIZED,
            path: req.uri().path().to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }

    /// Shortcut for creating a 500 General Server Error
    pub fn general(&self, req: &HttpRequest) -> ServiceError {
        ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: req.uri().path().to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }

    /// Shortcut for creating a 400 Bad Request Error
    pub fn bad_request(&self, req: &HttpRequest) -> ServiceError {
        ServiceError {
            code: StatusCode::BAD_REQUEST,
            path: req.uri().path().to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }
}
