/// Module that contains all the configuration from environment variables.
use lazy_static::lazy_static;
use std::env;
use url::Url;

lazy_static! {
    /// The public domain for the website, with trailing slash
    pub static ref DOMAIN: Url = Url::parse(&env::var("DOMAIN").unwrap_or("http://127.0.0.1:8080/".to_string())).expect("Unable to parse DOMAIN variable to a URL.");
    /// The domain to use in the cookie, consists of just the host portion of the domain.
    pub static ref COOKIE_DOMAIN: String = DOMAIN.host_str().unwrap_or("127.0.0.1").to_string();

    /// The address to bind the server to
    pub static ref SERVER_ADDR: String = env::var("SERVER_ADDR").unwrap_or("0.0.0.0".to_string());
    /// The port to bind the server to
    pub static ref SERVER_PORT: String = env::var("SERVER_PORT").unwrap_or("8080".to_string());

    /// Whether or not this is a production environment
    pub static ref PRODUCTION: bool = env::var("PRODUCTION").unwrap_or("false".to_string()).parse().expect("Unable to parse PRODUCTION variable. Must be `true` or `false`.");

    // Database options
    /// The address of the database
    pub static ref DB_ADDR: String = env::var("DB_ADDR").unwrap_or("localhost".to_string());
    /// The port of the database
    pub static ref DB_PORT: u16 = env::var("DB_PORT").unwrap_or("27017".to_string()).parse().expect("Unable to parse DB_PORT variable. Must be an u16.");
    /// The username for the database
    pub static ref DB_USER: Option<String> = env::var("DB_USER").ok();
    /// The password for the database
    pub static ref DB_PASS: Option<String> = env::var("DB_PASS").ok();
    /// The name of the database
    pub static ref DB_NAME: String = env::var("DB_NAME").unwrap_or("auth-example".to_string());
    /// The size of the connection pool for the database
    pub static ref DB_POOL_SIZE: u32 = env::var("DB_POOL_SIZE").unwrap_or("10".to_string()).parse().expect("Unable to parse DB_POOL_SIZE variable. Must be an unsigned int.");
    /// The name of the authentication collection in the DB
    pub static ref AUTH_COLLECTION: String = env::var("AUTH_COLLECTION").unwrap_or("users".to_string());
    /// The name of the session collection in the DB
    pub static ref SESSION_COLLECTION: String = env::var("SESSION_COLLECTION").unwrap_or("sessions".to_string());
    /// The name of the email token collection in the DB
    pub static ref EMAIL_TOKEN_COLLECTION: String = env::var("EMAIL_TOKEN_COLLECTION").unwrap_or("emails".to_string());
    /// The name of the TOTP token collection in the DB
    pub static ref TOTP_TOKEN_COLLECTION: String = env::var("TOTP_TOKEN_COLLECTION").unwrap_or("totp".to_string());
    /// The name of the password reset token collection in the DB
    pub static ref PASSWORD_RESET_TOKEN_COLLECTION: String = env::var("PASSWORD_RESET_TOKEN_COLLECTION").unwrap_or("password_reset".to_string());

    // Email Options
    /// The from email to use when sending emails
    pub static ref EMAIL_FROM: String = env::var("EMAIL_FROM").unwrap();
    /// The server to connect to for STMP
    pub static ref EMAIL_SERVER: String = env::var("EMAIL_SERVER").unwrap_or("".to_string());
    /// The username to use when authentication with the email server
    pub static ref EMAIL_USER: String = env::var("EMAIL_USER").unwrap_or("".to_string());
    /// The password to use for authentication with the email server
    pub static ref EMAIL_PASS: String = env::var("EMAIL_PASS").unwrap_or("".to_string());

}
