/// Module that contains all the template rendering functions.
use crate::models::{ServiceError, User};

use actix_web::{http::StatusCode, Result};
use lazy_static::lazy_static;
use log::debug;
use tera::{Context, Tera};

lazy_static! {
    pub static ref TERA: Tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"))
        .expect("Unable to create tera instance");
}

#[macro_export]
macro_rules! context {
    () => {{ $tera::Context::new() }};
    ($( $key:expr => $value:expr ),*) => {{
        let mut ctx = tera::Context::new();
        $(ctx.insert($key, $value);)*
        ctx
    }};
}

/// Render an HTML template.
pub fn render(
    template: &str,
    path: String,
    context: Option<Context>,
    user: Option<User>,
) -> Result<String, ServiceError> {
    let mut ctx = context.unwrap_or(Context::new());
    ctx.insert("user", &user);
    debug!("Rendering Template: {} {:#?}", template, ctx);
    TERA.render(template, &ctx).map_err(|e| match e.kind {
        tera::ErrorKind::TemplateNotFound(es) => ServiceError {
            code: StatusCode::NOT_FOUND,
            path: path,
            message: format!("Template not found: {}", es),
        },
        ek => ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: path,
            message: format!("Error rendering template: {:?}", ek),
        },
    })
}

/// Render an HTML template.
pub fn render_message(
    title: &str,
    header: &str,
    message: &str,
    path: String,
    user: Option<User>,
) -> Result<String, ServiceError> {
    let context = context! {
        "title" => title,
        "header" => header,
        "message" => message,
        "user" => &user
    };
    TERA.render("message.html", &context)
        .map_err(|e| match e.kind {
            tera::ErrorKind::TemplateNotFound(es) => ServiceError {
                code: StatusCode::NOT_FOUND,
                path: path,
                message: format!("Template not found: {}", es),
            },
            ek => ServiceError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: path,
                message: format!("Error rendering template: {:?}", ek),
            },
        })
}
