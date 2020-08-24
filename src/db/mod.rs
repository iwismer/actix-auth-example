/// Module that contains all the DB functions.
use crate::config::{
    AUTH_COLLECTION, DB_ADDR, DB_NAME, DB_PASS, DB_POOL_SIZE, DB_PORT, DB_USER,
    EMAIL_TOKEN_COLLECTION, SESSION_COLLECTION,
};
use bson::doc;
use bson::document::Document;
use lazy_static::lazy_static;
use mongodb::options::ClientOptions;
use mongodb::{options::StreamAddress, Client, Collection, Database};

pub mod email;
pub mod session;
pub mod user;

lazy_static! {
    static ref DB_CONN: Result<Database, String> = connect_to_db();
}

/// Get the collection containing all the users.
fn users_collection() -> Result<Collection, String> {
    Ok((*DB_CONN).as_ref()?.collection(&AUTH_COLLECTION))
}

/// Get the collection containing all the session tokens.
fn session_collection() -> Result<Collection, String> {
    Ok((*DB_CONN).as_ref()?.collection(&SESSION_COLLECTION))
}

/// Get the collection containing all the session tokens.
fn email_token_collection() -> Result<Collection, String> {
    Ok((*DB_CONN).as_ref()?.collection(&EMAIL_TOKEN_COLLECTION))
}

/// Connect to the DB and return the connection struct.
/// This should only be called once at the start up of the server.
fn connect_to_db() -> Result<Database, String> {
    let mut client_options = ClientOptions::builder()
        .hosts(vec![StreamAddress {
            hostname: DB_ADDR.to_string(),
            port: Some(*DB_PORT),
        }])
        .max_pool_size(Some(*DB_POOL_SIZE))
        .build();
    if DB_PASS.is_some() || DB_USER.is_some() {
        client_options.credential = Some(
            mongodb::options::Credential::builder()
                .username(DB_USER.to_owned())
                .password(DB_PASS.to_owned())
                .build(),
        );
    }
    let client = Client::with_options(client_options).map_err(|e| {
        format!(
            "Failed to connect to MongoDB at `mongodb://{}:{}`: {}",
            DB_ADDR.to_string(),
            *DB_PORT,
            e
        )
    })?;
    let db = client.database(&DB_NAME);
    Ok(db)
}

/// Get a string from a BSON document.
/// This is a convenience function to reduce code repetition.
pub fn get_bson_string(key: &str, item: &Document) -> Result<String, String> {
    Ok(item
        .get_str(key)
        .map_err(|e| format!("Unable to get {} from BSON: {}", key, e))?
        .to_string())
}

/// Get a bool from a BSON document.
/// This is a convenience function to reduce code repetition.
pub fn get_bson_bool(key: &str, item: &Document) -> Result<bool, String> {
    Ok(item
        .get_bool(key)
        .map_err(|e| format!("Unable to get {} from BSON: {}", key, e))?)
}
