mod server_error;
/// Module for data structures used in various parts of the server.
mod service_error;
mod user;

pub use server_error::ErrorCode;
pub use server_error::ServerError;
pub use service_error::ServiceError;
pub use user::User;
