use crate::auth::session::get_req_user;
use crate::models::ServiceError;
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
        get_req_user(&req).await.map_err(|e| {
            ServiceError::general(&req, format!("Error getting requeset user: {}", e))
        })?,
    )?))
}
