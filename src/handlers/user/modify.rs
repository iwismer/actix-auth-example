/// Module for endpoints related to modifying an existing user.
use crate::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
    validate_username_rules,
};
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::email::validate_email;
use crate::db::user::{get_user_by_username, modify_user};
use crate::models::{ServiceError, User};
use crate::templating::{render, render_message};
use crate::{config, context};

use actix_web::{web::Form, Error, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Generic get page for the modification pages.
pub async fn get_page(req: HttpRequest, user: User) -> Result<HttpResponse, Error> {
    let csrf_token =
        generate_csrf_token().map_err(|s| ServiceError::general(&req, s.message, false))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(csrf_cookie(&csrf_token))
        .body(render(
            &format!(
                "user/{}.html",
                req.match_info().get("page").ok_or(ServiceError::general(
                    &req,
                    "Page match info no available. Something is very wrong.",
                    false
                ))?
            ),
            req.uri().path().to_string(),
            Some(context! { "csrf" => &csrf_token }),
            Some(user),
        )?))
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordParams {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
    csrf: String,
}

/// Accepts the post request to change a user's password
pub async fn change_password_post(
    req: HttpRequest,
    params: Form<ChangePasswordParams>,
    mut user: User,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            "Invalid current password",
            true,
        ));
    }
    // create password hash
    let hash = generate_password_hash(&params.new_password).map_err(|s| s.general(&req))?;
    // insert user
    user.pass_hash = hash;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user password");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Password Changed",
            "Password Changed Successfully.",
            "The password for your account was updated successfully. Make sure you update the new password in your password manager.",
            req.uri().path().to_string(),
            Some(user),
        )?))
}

/// Form parameters for changing a username.
#[derive(Serialize, Deserialize)]
pub struct ChangeUsernameParams {
    current_password: String,
    new_username: String,
    csrf: String,
}

/// Accepts the post request to change a user's username
pub async fn change_username_post(
    req: HttpRequest,
    params: Form<ChangeUsernameParams>,
    mut user: User,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    if let Err(e) = validate_username_rules(&params.new_username) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    // Check that the username is not in use. This is also checked by the DB.
    if get_user_by_username(&params.new_username)
        .await
        .map_err(|s| s.general(&req))?
        .is_some()
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: Username already in use"),
            true,
        ));
    }
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // update user
    user.username = params.new_username.to_string();
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user username");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Username Changed",
            "Username Changed Successfully.",
            "The username for your account was updated successfully. Make sure you update to the new username in your password manager.",
            req.uri().path().to_string(),
            Some(user),
        )?))
}

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize)]
pub struct ChangeEmailParams {
    current_password: String,
    new_email: String,
    csrf: String,
}

/// Accepts the post request to change a user's email.
pub async fn change_email_post(
    req: HttpRequest,
    params: Form<ChangeEmailParams>,
    mut user: User,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Check the email is valid
    if let Err(e) = validate_email_rules(&params.new_email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("Error creating user: {}", e),
            true,
        ));
    }
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // Send a validation email
    validate_email(&user.user_id, &params.new_email)
        .await
        .map_err(|s| s.general(&req))?;
    // update user
    user.email = params.new_email.to_string();
    user.email_validated = false;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user email");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Email Changed",
            "Email Changed Successfully.",
            "The email for your account was updated successfully. A verification email has been sent to the new email.",
            req.uri().path().to_string(),
            Some(user),
        )?))
}

pub async fn profile_pic_post(
    req: HttpRequest,
    mut parts: awmp::Parts,
    mut user: User,
) -> Result<HttpResponse, ServiceError> {
    let text_fields = parts.texts.as_hash_map();
    check_csrf(text_fields.get("csrf").map(|s| s.to_string()), &req).await?;

    let file = parts
        .files
        .take("profile_pic")
        .pop()
        .ok_or(ServiceError::bad_request(
            &req,
            "Picture missing from request",
            true,
        ))?;
    log::debug!("Got file from request.");
    // Use the first 2 chars of the userID first, so there isn't a huge folder with all userIDs
    // This improves performance
    let save_path = config::STORAGE_DIR
        .join(user.user_id[..2].to_string())
        .join(&user.user_id);
    let new_path = PathBuf::from("/s/")
        .join(user.user_id[..2].to_string())
        .join(&user.user_id)
        .join(file.sanitized_file_name())
        .as_os_str()
        .to_string_lossy()
        .to_string();
    // TODO change the file name to the userID and don't have a userID folder
    fs::create_dir_all(save_path.as_path()).map_err(|e| {
        ServiceError::general(&req, format!("Unable to create folder: {}", e), false)
    })?;
    // Save the new picture
    file.persist(save_path.as_path())
        .map_err(|e| ServiceError::general(&req, format!("{}", e), false))?;
    // remove old profile picture
    if let Some(url) = user.profile_pic {
        let old_path = config::STORAGE_DIR.join(url[3..].to_string());
        fs::remove_file(old_path.as_path()).map_err(|e| {
            ServiceError::general(&req, format!("Unable to delete picture: {}", e), false)
        })?;
    }
    // Don't change the user until everything has completed successfully
    user.profile_pic = Some(new_path);
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user profile picture");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Profile Picture Changed",
            "Profile Picture Changed Successfully.",
            "The profile picture for your account was updated successfully.",
            req.uri().path().to_string(),
            Some(user),
        )?))
}

/// Form parameters for changing a username.
#[derive(Serialize, Deserialize)]
pub struct DeletePictureParams {
    csrf: String,
}

pub async fn profile_pic_delete_post(
    req: HttpRequest,
    params: Form<DeletePictureParams>,
    mut user: User,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;

    let url = match user.profile_pic {
        Some(u) => u,
        None => {
            return Err(ServiceError::bad_request(
                &req,
                "Profile picture already removed.",
                true,
            ))
        }
    };

    let path = config::STORAGE_DIR.join(url[3..].to_string());
    fs::remove_file(path.as_path()).map_err(|e| {
        ServiceError::general(&req, format!("Unable to delete picture: {}", e), false)
    })?;
    user.profile_pic = None;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Removed user profile picture");

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(render_message(
            "Profile Picture Changed",
            "Profile Picture Changed Successfully.",
            "The profile picture for your account was updated successfully.",
            req.uri().path().to_string(),
            Some(user),
        )?))
}
