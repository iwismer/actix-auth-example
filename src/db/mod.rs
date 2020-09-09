/// Module that contains all the DB functions.
use crate::models::ServerError;
use crate::{config, err_server};

use bson::{doc, document::Document};
use lazy_static::lazy_static;
use mongodb::options::{ClientOptions, StreamAddress};
use mongodb::{Client, Collection, Database};

pub mod email;
pub mod session;
pub mod totp;
pub mod user;

lazy_static! {
    static ref DB_CONN: Result<Database, ServerError> = connect_to_db();
}

/// Get the collection containing all the users.
fn users_collection() -> Result<Collection, ServerError> {
    Ok((*DB_CONN)
        .as_ref()
        .map_err(|e| e.clone())?
        .collection(&config::AUTH_COLLECTION))
}

/// Get the collection containing all the session tokens.
fn session_collection() -> Result<Collection, ServerError> {
    Ok((*DB_CONN)
        .as_ref()
        .map_err(|e| e.clone())?
        .collection(&config::SESSION_COLLECTION))
}

/// Get the collection containing all the email tokens.
fn email_token_collection() -> Result<Collection, ServerError> {
    Ok((*DB_CONN)
        .as_ref()
        .map_err(|e| e.clone())?
        .collection(&config::EMAIL_TOKEN_COLLECTION))
}

/// Get the collection containing all the TOTP tokens.
fn totp_token_collection() -> Result<Collection, ServerError> {
    Ok((*DB_CONN)
        .as_ref()
        .map_err(|e| e.clone())?
        .collection(&config::TOTP_TOKEN_COLLECTION))
}

/// Get the collection containing all the password reset tokens.
fn password_reset_token_collection() -> Result<Collection, ServerError> {
    Ok((*DB_CONN)
        .as_ref()
        .map_err(|e| e.clone())?
        .collection(&config::PASSWORD_RESET_TOKEN_COLLECTION))
}

/// Connect to the DB and return the connection struct.
/// This should only be called once at the start up of the server.
fn connect_to_db() -> Result<Database, ServerError> {
    let mut client_options = ClientOptions::builder()
        .hosts(vec![StreamAddress {
            hostname: config::DB_ADDR.to_string(),
            port: Some(*config::DB_PORT),
        }])
        .max_pool_size(Some(*config::DB_POOL_SIZE))
        .build();
    if config::DB_PASS.is_some() || config::DB_USER.is_some() {
        client_options.credential = Some(
            mongodb::options::Credential::builder()
                .username(config::DB_USER.to_owned())
                .password(config::DB_PASS.to_owned())
                .build(),
        );
    }
    let client = Client::with_options(client_options).map_err(|e| {
        err_server!(
            "Failed to connect to MongoDB at `mongodb://{}:{}`: {}",
            config::DB_ADDR.to_string(),
            *config::DB_PORT,
            e
        )
    })?;
    let db = client.database(&config::DB_NAME);
    Ok(db)
}

/// Get a string from a BSON document.
/// This is a convenience function to reduce code repetition.
pub fn get_bson_string(key: &str, item: &Document) -> Result<String, ServerError> {
    Ok(item
        .get_str(key)
        .map_err(|e| err_server!("Unable to get {} from BSON: {}", key, e))?
        .to_string())
}

/// Get a bool from a BSON document.
/// This is a convenience function to reduce code repetition.
pub fn get_bson_bool(key: &str, item: &Document) -> Result<bool, ServerError> {
    Ok(item
        .get_bool(key)
        .map_err(|e| err_server!("Unable to get {} from BSON: {}", key, e))?)
}
