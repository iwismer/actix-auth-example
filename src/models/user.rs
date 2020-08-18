/// Module for the struct that represents a single user.
use crate::db::get_bson_string;
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
    pub otp_token: String,
    // TODO user privileges
}

impl TryFrom<Document> for User {
    type Error = String;

    fn try_from(item: Document) -> Result<Self, Self::Error> {
        Ok(User {
            user_id: get_bson_string("user_id", &item)?,
            email: get_bson_string("email", &item)?,
            username: get_bson_string("user", &item)?,
            pass_hash: get_bson_string("hash", &item)?,
            // TODO
            email_validated: false,
            otp_token: get_bson_string("otp_token", &item)?,
        })
    }
}
