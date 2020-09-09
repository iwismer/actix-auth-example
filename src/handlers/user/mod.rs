/// Module that handles all the user related endpoints of the website
use crate::models::User;
use crate::templating::render;

use actix_web::{Error, HttpRequest, HttpResponse, Result};

pub mod delete;
pub mod email;
pub mod modify;
pub mod register;
pub mod totp;

/// Page to view the user's details
pub async fn view_user(req: HttpRequest, user: User) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user/user.html",
        req.uri().path().to_string(),
        None,
        Some(user),
    )?))
}
