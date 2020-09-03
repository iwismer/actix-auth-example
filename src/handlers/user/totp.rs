/// Module for endpoints related to TOTP
use crate::auth::credentials::credential_validator;
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::generate_token;
use crate::auth::session::get_req_user;
use crate::auth::totp::{generate_totp_backup_codes, validate_totp_token};
use crate::config;
use crate::context;
use crate::db::user::modify_user;
use crate::models::ServiceError;
use crate::templating::render;

use actix_web::http::header;
use actix_web::Error;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};

/// Handler for the page to modify TOTP
pub async fn get_totp_page(req: HttpRequest) -> Result<HttpResponse, Error> {
    let csrf_token = generate_csrf_token().map_err(|s| s.general(&req))?;
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| e.general(&req))?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    // The context depends on whether TOTP is active or not.
    let ctx = match user.totp_active {
        true => context! {
            // "qr_code" => "",
            // "totp_token" => "",
            "csrf" => &csrf_token
        },
        false => {
            let token =
                generate_token().map_err(|s| ServiceError::general(&req, s.message, false))?;
            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, &token);
            let qr_code = totp
                .get_qr(&user.username, config::DOMAIN.as_str())
                .map_err(|e| {
                    ServiceError::general(&req, format!("Problem generating QR code: {}", e), false)
                })?;
            user.totp_token = Some(token.to_string());
            modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
            context! {
                "qr_code" => &qr_code,
                "totp_token" => &token,
                "csrf" => &csrf_token
            }
        }
    };
    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .cookie(csrf_cookie(&csrf_token))
        .body(render(
            "user/2fa.html",
            req.uri().path().to_string(),
            Some(ctx),
            Some(user),
        )?))
}

/// Struct for the adding TOTP form
#[derive(Serialize, Deserialize)]
pub struct AddTotpForm {
    current_password: String,
    code: String,
    csrf: String,
}

/// Accepts the post request to activate TOTP for a user
pub async fn add_totp_post(
    req: HttpRequest,
    params: Form<AddTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    // Get the user from the form
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| e.general(&req))?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    // Check the password entered was correct
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", &user.user_id),
            true,
        ));
    }
    // Set this before validating since it needs to be true for validation to succeed.
    user.totp_active = true;
    // Check the TOTP code was correct
    if !validate_totp_token(&mut user, &params.code)
        .await
        .map_err(|s| s.general(&req))?
    {
        return Err(ServiceError::bad_request(&req, "Invalid token.", true));
    }
    // update user
    let backup_codes = generate_totp_backup_codes().map_err(|s| {
        ServiceError::general(
            &req,
            format!("Problem generating backup codes: {}", s),
            true,
        )
    })?;
    user.totp_backups = Some(backup_codes.clone());
    user.totp_active = true;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user -> Enable TOTP");
    // Show the backup codes
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user/2fa_backup.html",
        req.uri().path().to_string(),
        Some(context! {
            "totp_backups" => &backup_codes
        }),
        Some(user),
    )?))
}

/// Form parameters for changing TOTP
#[derive(Serialize, Deserialize)]
pub struct ChangeTotpForm {
    current_password: String,
    csrf: String,
}

/// Accepts the post request to disable TOTP
pub async fn remove_totp_post(
    req: HttpRequest,
    params: Form<ChangeTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e), false)
        })?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", user.user_id),
            true,
        ));
    }
    // update user
    user.totp_active = false;
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user -> disable TOTP");
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/user")
        .finish())
}

/// Accepts the post request to change the TOTP backup codes
pub async fn reset_backup_totp_post(
    req: HttpRequest,
    params: Form<ChangeTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| {
            ServiceError::general(&req, format!("Error getting request user: {}", e), false)
        })?
        .ok_or(ServiceError::general(
            &req,
            "No user found in request.",
            false,
        ))?;
    if !user.totp_active {
        return Err(ServiceError::bad_request(
            &req,
            "TOTP is not enabled for the current user.",
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
    // update user with new backup codes
    let backup_codes = generate_totp_backup_codes().map_err(|s| {
        ServiceError::general(
            &req,
            format!("Problem generating backup codes: {}", s),
            false,
        )
    })?;
    user.totp_backups = Some(backup_codes.clone());
    modify_user(&user).await.map_err(|s| s.bad_request(&req))?;
    log::debug!("Modified user");
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user/2fa_backup.html",
        req.uri().path().to_string(),
        Some(context! {
            "totp_backups" => &backup_codes
        }),
        Some(user),
    )?))
}
