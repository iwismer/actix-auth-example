/// This is an example for using different auths with actix
mod auth;
mod config;
mod db;
mod handlers;
mod models;
mod templating;

use actix_files::Files;
use actix_http::http::{PathAndQuery, Uri};
use actix_service::Service;
use actix_web::{http::header, middleware, web, App, HttpResponse, HttpServer};
use log::info;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    std::env::set_var("RUST_LOG", "actix_web=info,auth-example=info");

    info!(
        "Starting http server: {}:{}",
        config::SERVER_ADDR.as_str(),
        config::SERVER_PORT.as_str()
    );
    // start http server
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .wrap(
                middleware::DefaultHeaders::new().header(header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            )
            // Removes trailing slash
            .wrap_fn(|mut req, srv| {
                let head = req.head();
                let mut new_path = head.uri.path().to_string();
                // If the URL ends in a /
                if new_path.pop() == Some('/') {
                    let mut parts = head.uri.clone().into_parts();
                    let pq = parts.path_and_query.as_ref().unwrap();

                    // Attach the query params back onto the path
                    let path = match pq.query() {
                        Some(q) => format!("{}?{}", new_path, q),
                        None => new_path,
                    }
                    .as_bytes()
                    .to_vec();
                    parts.path_and_query = Some(PathAndQuery::from_maybe_shared(path).unwrap());

                    // Set the URI of the request
                    let uri = Uri::from_parts(parts).unwrap();
                    req.match_info_mut().get_mut().update(&uri);
                    req.head_mut().uri = uri;
                }
                srv.call(req)
            })
            // Remove duplicate slashes
            .wrap(middleware::NormalizePath::default())
            // enable logger
            .wrap(middleware::Logger::default())
            // Home page
            .service(
                web::resource("")
                    .wrap(auth::middleware::AuthCheckService::disallow_auth("/zone"))
                    .route(web::get().to(handlers::home)),
            )
            .service(
                web::scope("/zone")
                    .wrap(auth::middleware::AuthCheckService::require_auth())
                    .service(web::resource("").route(web::get().to(handlers::zone))),
                // TODO have some other various pages here
            )
            .service(
                web::scope("/user")
                    .wrap(auth::middleware::AuthCheckService::require_auth())
                    .service(web::resource("").route(web::get().to(handlers::user::view_user)))
                    .service(
                        web::resource("/2fa")
                            .route(web::get().to(handlers::user::totp::get_totp_page)),
                    )
                    .service(
                        web::resource("/{page}")
                            .guard(actix_web::guard::Get())
                            .route(web::get().to(handlers::user::modify::get_page)),
                    )
                    .service(
                        web::resource("/delete")
                            // TODO change to delete using client side JS
                            .route(web::post().to(handlers::user::delete::delete_user_post)),
                    )
                    .service(
                        web::resource("/email")
                            .route(web::post().to(handlers::user::modify::change_email_post)),
                    )
                    .service(
                        web::resource("/username")
                            .route(web::post().to(handlers::user::modify::change_username_post)),
                    )
                    .service(
                        web::resource("/password")
                            .route(web::post().to(handlers::user::modify::change_password_post)),
                    )
                    .service(
                        web::resource("/2fa-add")
                            .route(web::post().to(handlers::user::totp::add_totp_post)),
                    )
                    .service(
                        web::resource("/2fa-remove")
                            .route(web::post().to(handlers::user::totp::remove_totp_post)),
                    ),
            )
            .service(
                web::resource("/login")
                    .wrap(auth::middleware::AuthCheckService::disallow_auth("/zone"))
                    .route(web::get().to(handlers::auth::login))
                    .route(web::post().to(handlers::auth::login_post)),
            )
            .service(
                web::resource("/login-2fa")
                    .wrap(auth::middleware::AuthCheckService::disallow_auth("/zone"))
                    .route(web::post().to(handlers::auth::totp_post)),
            )
            .service(
                web::resource("/register")
                    .wrap(auth::middleware::AuthCheckService::disallow_auth("/zone"))
                    .route(web::get().to(handlers::user::register::register_get))
                    .route(web::post().to(handlers::user::register::register_post)),
            )
            .service(web::resource("/logout").route(web::get().to(handlers::auth::logout)))
            .service(
                web::resource("/email")
                    .route(web::get().to(handlers::user::register::verify_email)),
            )
            // Favicon handler so that it doesn't try to render it.
            .service(web::resource("/favicon.ico").to(|| HttpResponse::NotFound()))
            // Any top level pages, the URL matches the template name
            .service(web::resource("/{page}").route(web::get().to(handlers::page)))
            // Static resources
            .service(Files::new("/static", "static/"))
            .service(Files::new("/.well-known", ".well-known/"))
            // 404 handler
            .default_service(web::route().to(handlers::p404))
    })
    .bind(format!(
        "{}:{}",
        config::SERVER_ADDR.as_str(),
        config::SERVER_PORT.as_str()
    ))?
    .run()
    .await
}
