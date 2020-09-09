/// Module for the struct that represents a single user.
use crate::db::session::get_session_user_id;
use crate::db::user::get_user_by_userid;
use crate::db::{get_bson_bool, get_bson_string};
use crate::models::{ServerError, ServiceError};

use actix_web::{dev, http::StatusCode, FromRequest, HttpMessage, HttpRequest};
use bson::{doc, document::Document, Bson};
use futures::Future;
use serde::Serialize;
use std::convert::TryFrom;
use std::pin::Pin;

/// Holds a single user's information.
#[derive(Serialize, Debug, Clone)]
pub struct User {
    /// Random user ID that is unique.
    /// Used to identify the user so that email and username can be changed without issue
    pub user_id: String,
    /// User email
    pub email: String,
    /// User selected username
    pub username: String,
    /// The hash of the password for the user (using Argon2)
    pub pass_hash: String,
    /// Whether or not the user's email is validated.
    pub email_validated: bool,
    /// Whether or not the user is using 2fa on their account
    pub totp_active: bool,
    /// Their TOTP token
    pub totp_token: Option<String>,
    /// The TOTP backup codes (hashed with SHA256)
    pub totp_backups: Option<Vec<String>>,
    /// The path to the saved profile
    pub profile_pic: Option<String>,
}

impl TryFrom<Document> for User {
    type Error = ServerError;

    fn try_from(item: Document) -> Result<Self, Self::Error> {
        Ok(User {
            user_id: get_bson_string("user_id", &item)?,
            email: get_bson_string("email", &item)?,
            username: get_bson_string("username", &item)?,
            pass_hash: get_bson_string("pass_hash", &item)?,
            email_validated: get_bson_bool("email_validated", &item).unwrap_or(false),
            totp_active: get_bson_bool("totp_active", &item).unwrap_or(false),
            totp_token: get_bson_string("totp_token", &item).ok(),
            totp_backups: match item.get_array("totp_backups") {
                Ok(arr) => Some(
                    arr.iter()
                        .filter_map(|b| match b {
                            Bson::String(s) => Some(s.to_string()),
                            _ => None,
                        })
                        .collect(),
                ),
                Err(e) => {
                    log::warn!("totp_backups: {}", e);
                    None
                }
            },
            profile_pic: get_bson_string("profile_pic", &item).ok(),
        })
    }
}

impl From<&User> for Document {
    fn from(item: &User) -> Self {
        let totp_token = match item.totp_token.as_ref() {
            Some(s) => Bson::String(s.to_string()),
            None => Bson::Null,
        };
        let profile_pic = match item.profile_pic.as_ref() {
            Some(s) => Bson::String(s.to_string()),
            None => Bson::Null,
        };
        let totp_backups = match item.totp_backups.as_ref() {
            Some(arr) => Bson::Array(arr.iter().map(|s| Bson::String(s.to_string())).collect()),
            None => Bson::Null,
        };
        doc! {
            "user_id": item.user_id.to_string(),
            "email": item.email.to_string(),
            "username": item.username.to_string(),
            "pass_hash": item.pass_hash.to_string(),
            "email_validated": item.email_validated,
            "totp_active": item.totp_active,
            "totp_token": totp_token,
            "totp_backups": totp_backups,
            "profile_pic": profile_pic,
        }
    }
}

/// Async extractor for users from requests.
/// It is made async by using a pinned box. See <https://stackoverflow.com/a/63343022>
impl FromRequest for User {
    type Error = ServiceError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    type Config = ();
    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let path = req.uri().path().to_string();
        let error = ServiceError {
            code: StatusCode::BAD_REQUEST,
            path: path,
            message: "User not logged in.".to_string(),
            show_message: true,
        };
        let cookie = req.cookie("session").map(|c| c.value().to_string());

        Box::pin(async move {
            let token = match cookie {
                Some(c) => c,
                None => return Err(error),
            };
            let user_id = match get_session_user_id(&token).await {
                Ok(s) => match s {
                    Some(u) => u,
                    None => return Err(error),
                },
                Err(_) => return Err(error),
            };
            get_user_by_userid(&user_id)
                .await
                .unwrap_or(None)
                .ok_or(error)
        })
    }
}
