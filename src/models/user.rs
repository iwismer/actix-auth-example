/// Module for the struct that represents a single user.
use crate::db::{get_bson_bool, get_bson_string};

use bson::{doc, document::Document, Bson};
use serde::Serialize;
use std::convert::TryFrom;

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
}

impl TryFrom<Document> for User {
    type Error = String;

    fn try_from(item: Document) -> Result<Self, Self::Error> {
        Ok(User {
            user_id: get_bson_string("user_id", &item)?,
            email: get_bson_string("email", &item)?,
            username: get_bson_string("username", &item)?,
            pass_hash: get_bson_string("pass_hash", &item)?,
            email_validated: get_bson_bool("email_validated", &item)?,
            totp_active: get_bson_bool("totp_active", &item)?,
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
                    log::warn!("{}", e);
                    None
                }
            },
        })
    }
}

#[allow(unused_variables)]
impl From<User> for Document {
    fn from(item: User) -> Self {
        let totp_token = match item.totp_token {
            Some(s) => Bson::String(s),
            None => Bson::Null,
        };
        let totp_backups = match item.totp_backups {
            Some(arr) => Bson::Array(arr.iter().map(|s| Bson::String(s.to_string())).collect()),
            None => Bson::Null,
        };
        doc! {
            "user_id": item.user_id,
            "email": item.email,
            "username": item.username,
            "pass_hash": item.pass_hash,
            "email_validated": item.email_validated,
            "totp_active": item.totp_active,
            "totp_token": totp_token,
            "totp_backups": totp_backups,
        }
    }
}
