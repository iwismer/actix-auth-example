/// Module for endpoints related to deleting users
use crate::auth::{csrf::check_csrf, session::get_req_user};
use crate::db::auth::delete_user;
use crate::models::ServiceError;
use actix_web::{http::header, web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};

/// Struct for the delete user form fields
#[derive(Serialize, Deserialize)]
pub struct DeleteUserParams {
    username: String,
    csrf: String,
}

/// Accepts the post request to create a new user
/// TODO make it so you can only delete your own user (get the user from the session?)
pub async fn delete_user_post(
    req: HttpRequest,
    params: Form<DeleteUserParams>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Check that the user is not trying to delete themselves
    if get_req_user(&req)
        .await
        .map_err(|s| {
            ServiceError::bad_request(&req, format!("Cannot get current user from request: {}", s))
        })?
        .ok_or(ServiceError::unauthorized(&req, "Current user not found."))?
        == params.username
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Cannot delete your own user: {}", params.username),
        ));
    }
    // delete user from the DB
    delete_user(&params.username)
        .await
        .map_err(|e| ServiceError::bad_request(&req, e))?;
    // Redirect back to the users page
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/edit/users")
        .finish())
}
