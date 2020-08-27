/// Module that contains all the auth middleware.
use super::session::get_session_token;

use crate::db::session::validate_session;

use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{Error, HttpResponse};
use futures::future::{ok, Ready};
use futures::Future;
use log::error;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

/// What to do based on whether or not the user is logged in.
#[derive(Clone)]
enum AuthRedirectStrategy {
    /// Require authentication for the page. Returns a 401 error if they are not authenticated.
    RequireAuth,
    /// Don't allow authenticated users to see this page. Redirect them to the path in the string.
    DisallowAuth(String),
}
/// Wrapper for checking that the user is logged in
/// Checks that there is a valid session cookie sent along with the request.
/// It then does an action based on the strategy
#[derive(Clone)]
pub struct AuthCheckService {
    strategy: AuthRedirectStrategy,
}

impl AuthCheckService {
    pub fn require_auth() -> Self {
        AuthCheckService {
            strategy: AuthRedirectStrategy::RequireAuth,
        }
    }

    pub fn disallow_auth<T: Into<String>>(redirect_path: T) -> Self {
        AuthCheckService {
            strategy: AuthRedirectStrategy::DisallowAuth(redirect_path.into()),
        }
    }
}

impl<S, B> Transform<S> for AuthCheckService
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthCheckMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthCheckMiddleware {
            service: Rc::new(RefCell::new(service)),
            strategy: self.strategy.clone(),
        })
    }
}

pub struct AuthCheckMiddleware<S> {
    service: Rc<RefCell<S>>,
    strategy: AuthRedirectStrategy,
}

impl<S, B> Service for AuthCheckMiddleware<S>
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
        let strategy = self.strategy.clone();
        // Run this async so we can use async functions.
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
            match strategy {
                AuthRedirectStrategy::RequireAuth => match is_logged_in {
                    true => {
                        log::debug!("Authentication succeeded, continuing request.");
                        srv.call(req).await
                    }
                    false => {
                        log::debug!("Authentication failed, redirecting.");
                        Ok(req.into_response(
                            HttpResponse::Found()
                                .header(header::LOCATION, "/login")
                                .finish()
                                .into_body(),
                        ))
                    }
                },
                AuthRedirectStrategy::DisallowAuth(s) => match is_logged_in {
                    false => srv.call(req).await,
                    true => Ok(req.into_response(
                        HttpResponse::Found()
                            .header(header::LOCATION, s.as_str())
                            .finish()
                            .into_body(),
                    )),
                },
            }
        })
    }
}
