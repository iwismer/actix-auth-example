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

/// Macro for easily creating a tera context struct.
/// The items must be passed as references, and must be implement Serialize.
#[macro_export]
macro_rules! context {
    () => {{ $tera::Context::new() }};
    ($( $key:expr => $value:expr ),*) => {{
        let mut ctx = tera::Context::new();
        $(ctx.insert($key, $value);)*
        ctx
    }};
}

/// Render an HTML template using tera and the provided context.
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
            show_message: false,
        },
        ek => ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: path,
            message: format!("Error rendering template: {:?}", ek),
            show_message: false,
        },
    })
}

/// Render the basic message template using tera.
/// This is simply a shortcut function for the regular render function.
///
/// # Arguments
///
/// * `title` - The title of the webpage (shows up in the tab)
/// * `header` - The leading text of the webpage (shows up in big letters)
/// * `message` - The main text of the webpage
/// * `path` - The path of the page where the message is coming from
/// * `user` - The user associated with the request, if there is one.
///
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
    render("message.html", path, Some(context), user)
}
