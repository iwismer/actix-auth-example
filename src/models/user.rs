/// Module for the struct that represents a single user.
use crate::db::{get_bson_bool, get_bson_string};
use bson::doc;
use bson::document::Document;
use serde::Serialize;
use std::convert::TryFrom;

/// Holds a single user's information.
#[derive(Serialize, Debug)]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub pass_hash: String,
    pub email_validated: bool,
    pub otp_token: Option<String>,
    pub otp_backups: Option<Vec<String>>,
    // TODO user privileges
    // TODO profile picture?
    // TODO OAuth tokens
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
            otp_token: get_bson_string("otp_token", &item).ok(),
            // TODO
            otp_backups: None,
        })
    }
}

#[allow(unused_variables)]
impl From<User> for Document {
    fn from(item: User) -> Self {
        doc! {
            "user_id": item.user_id,
            "email": item.email,
            "username": item.username,
            "pass_hash": item.pass_hash,
            "email_validated": item.email_validated,
            // TODO
            // "otp_token": item.otp_token,
        }
    }
}
