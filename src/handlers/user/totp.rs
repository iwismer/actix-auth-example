/// Module for endpoints related to adding new users
use crate::auth::credentials::credential_validator;
use crate::auth::csrf::{check_csrf, csrf_cookie, generate_csrf_token};
use crate::auth::generate_token;
use crate::auth::session::get_req_user;
use crate::auth::totp::{generate_totp_backup_codes, validate_totp};
use crate::config;
use crate::db::user::{get_user_by_userid, modify_user};
use crate::models::ServiceError;
use crate::templating::render;

use actix_web::http::header;
use actix_web::Error;
use actix_web::{web::Form, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};

#[derive(Serialize)]
pub struct TotpContext {
    qr_code: String,
    totp_token: String,
    csrf: String,
}

pub async fn get_totp_page(req: HttpRequest) -> Result<HttpResponse, Error> {
    let csrf_token = generate_csrf_token().map_err(|s| ServiceError::general(&req, s))?;
    let mut user = get_req_user(&req)
        .await
        .map_err(|e| ServiceError::general(&req, format!("Error getting request user: {}", e)))?
        .ok_or(ServiceError::general(&req, "No user found in request."))?;
    let ctx = match user.totp_active {
        true => TotpContext {
            qr_code: "".to_string(),
            totp_token: "".to_string(),
            csrf: csrf_token.to_string(),
        },
        false => {
            let token = generate_token().map_err(|s| ServiceError::general(&req, s))?;
            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, &token);
            let qr_code = totp
                .get_qr(&user.username, config::DOMAIN.as_str())
                .map_err(|e| {
                    ServiceError::general(&req, format!("Problem generating QR code: {}", e))
                })?;
            user.totp_token = Some(token.to_string());
            modify_user(user.clone())
                .await
                .map_err(|s| ServiceError::bad_request(&req, s))?;
            TotpContext {
                qr_code: qr_code,
                totp_token: token,
                csrf: csrf_token.to_string(),
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

#[derive(Serialize, Deserialize)]
pub struct AddTotpForm {
    current_password: String,
    user_id: String,
    code: String,
    csrf: String,
}

#[derive(Serialize)]
pub struct TotpBackupContext {
    totp_backups: Vec<String>,
}

/// Accepts the post request to create a new user
pub async fn add_totp_post(
    req: HttpRequest,
    params: Form<AddTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    let mut user = match get_user_by_userid(&params.user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(u) => u,
        None => {
            return Err(ServiceError::bad_request(
                &req,
                format!("User doesn't exist: {}", params.user_id),
            ))
        }
    };
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    validate_totp(&user.user_id, &params.code)
        .await
        .map_err(|s| ServiceError::general(&req, s))?;
    // insert user
    let backup_codes = generate_totp_backup_codes().map_err(|s| {
        ServiceError::general(&req, format!("Problem generating backup codes: {}", s))
    })?;
    user.totp_backups = Some(backup_codes.clone());
    user.totp_active = true;
    modify_user(user.clone())
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user/2fa_backup.html",
        req.uri().path().to_string(),
        Some(TotpBackupContext {
            totp_backups: backup_codes,
        }),
        Some(user),
    )?))
}

#[derive(Serialize, Deserialize)]
pub struct ChangeTotpForm {
    current_password: String,
    user_id: String,
    csrf: String,
}

/// Accepts the post request to create a new user
pub async fn remove_totp_post(
    req: HttpRequest,
    params: Form<ChangeTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    let mut user = match get_user_by_userid(&params.user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(u) => u,
        None => {
            return Err(ServiceError::bad_request(
                &req,
                format!("User doesn't exist: {}", params.user_id),
            ))
        }
    };
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    // insert user
    user.totp_active = false;
    modify_user(user)
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::SeeOther()
        .content_type("text/html")
        .header(header::LOCATION, "/user")
        .finish())
}

/// Accepts the post request to create a new user
pub async fn reset_backup_totp_post(
    req: HttpRequest,
    params: Form<ChangeTotpForm>,
) -> Result<HttpResponse, ServiceError> {
    check_csrf(Some(&params.csrf), &req).await?;
    let mut user = match get_user_by_userid(&params.user_id)
        .await
        .map_err(|s| ServiceError::general(&req, s))?
    {
        Some(u) => u,
        None => {
            return Err(ServiceError::bad_request(
                &req,
                format!("User doesn't exist: {}", params.user_id),
            ))
        }
    };
    if !credential_validator(&user, &params.current_password)
        .map_err(|e| ServiceError::general(&req, e))?
    {
        return Err(ServiceError::bad_request(
            &req,
            format!("Invalid current password: {}", params.user_id),
        ));
    }
    // insert user
    let backup_codes = generate_totp_backup_codes().map_err(|s| {
        ServiceError::general(&req, format!("Problem generating backup codes: {}", s))
    })?;
    user.totp_backups = Some(backup_codes.clone());
    modify_user(user.clone())
        .await
        .map_err(|s| ServiceError::bad_request(&req, s))?;
    log::debug!("Modified user");
    Ok(HttpResponse::Ok().content_type("text/html").body(render(
        "user/2fa_backup.html",
        req.uri().path().to_string(),
        Some(TotpBackupContext {
            totp_backups: backup_codes,
        }),
        Some(user),
    )?))
}
