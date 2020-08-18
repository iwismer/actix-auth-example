/// Module that handles all the user related endpoints of the website
use crate::templating::render;
use actix_web::{Error, HttpRequest, HttpResponse, Result};

pub mod delete;
pub mod register;

/// Page to view the user's details
/// TODO
pub async fn view_user(req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user.html",
        req.uri().path().to_string(),
        None::<i32>,
    )?))
}
