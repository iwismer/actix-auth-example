/// Module that contains all the functions related to sessions.
use crate::db::auth::{add_session, get_session_user, validate_session};
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{Error, HttpMessage, HttpResponse};
use chrono::{Duration, Utc};
use futures::future::{ok, Ready};
use futures::Future;
use log::error;
use log::warn;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
/// Wrapper for checking that the user is logged in
/// Checks that there is a valid session cookie sent along with the request
#[derive(Clone)]
pub struct AuthService;

impl<S, B> Transform<S> for AuthService
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct AuthMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service for AuthMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut srv = self.service.clone();
        Box::pin(async move {
            let is_logged_in = match get_session_token(&req) {
                Some(t) => match validate_session(&t).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Error validating token: {}", e);
                        false
                    }
                },
                None => false,
            };
            if is_logged_in {
                srv.call(req).await
            } else {
                Ok(req.into_response(
                    HttpResponse::Found()
                        .header(header::LOCATION, "/login")
                        .finish()
                        .into_body(),
                ))
            }
        })
    }
}

/// Create a session token for a specific user
pub async fn generate_session_token(user: &str) -> Result<String, String> {
    let expiry = Utc::now() + Duration::days(1);
    // Try a few times to create a token, in case of a token that is not unique (Unlikely!)
    // Only repeat 10 times to prevent an infinite loop
    for i in 0..10 {
        let mut session_token = [0u8; 64];
        getrandom::getrandom(&mut session_token)
            .map_err(|e| format!("Error generating session token: {}", e))?;
        let token = hex::encode(session_token.to_vec());
        match add_session(user, &token, expiry).await {
            Ok(_) => return Ok(token),
            Err(e) => warn!(
                "Problem creating session token for user {} (attempt {}/10): {}",
                user,
                i + 1,
                e
            ),
        }
    }
    Err("Unable to generate session token.".to_string())
}

/// Extract the session token from the request cookies
pub fn get_session_token<T: HttpMessage>(req: &T) -> Option<String> {
    req.cookies()
        .ok()?
        .iter()
        .find(|c| c.name() == "session")
        .map(|c| c.value().to_string())
}

// TODO replace with extractor when I figure out how to do async in an extractor
/// Get the username that sent the request based on the session
pub async fn get_req_user<T: HttpMessage>(req: &T) -> Result<Option<String>, String> {
    match get_session_token(req) {
        Some(token) => Ok(get_session_user(&token).await?),
        None => Ok(None),
    }
}
