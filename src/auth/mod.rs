/// Module that contains all the functions related to authentication.
pub mod credentials;
pub mod csrf;
pub mod email;
pub mod middleware;
pub mod session;

pub fn generate_token() -> Result<String, String> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(|e| format!("Error generating token: {}", e))?;
    Ok(hex::encode(token.to_vec()))
}
