/// Module that contains all the template rendering functions.
use crate::models::ServiceError;
use actix_web::{http::StatusCode, Result};
use lazy_static::lazy_static;
use log::debug;
use serde::Serialize;
use tera::{Context, Tera};

lazy_static! {
    pub static ref TERA: Tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"))
        .expect("Unable to create tera instance");
}

/// Render an HTML template.
pub fn render(
    template: &str,
    path: String,
    context: Option<impl Serialize>,
) -> Result<String, ServiceError> {
    let ctx = context.map_or(Context::new(), |c| {
        Context::from_serialize(c).unwrap_or(Context::new())
    });
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
