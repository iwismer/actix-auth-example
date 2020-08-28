# Authentication Example Website

## Why?

I made this project to learn a bit more about modern authentication on the web, and to practise my skills with Rust.
I also hope that other people might find it a useful reference when implementing authentication (once this is complete).

## Todo

- [x] Add a user ID to the user DB
- [x] Add OTP and backup codes
- [x] Show backup codes after OTP, allow regenerating backup codes
- [x] password unicode normalization
- [x] Allow changing password, username, email
- [x] Validate email
- [ ] OAuth
- [ ] Add script to automatically setup up mongo
- [ ] User profile picture
  - Resize on upload
  - Put them in the DB
  - display on the profile page
- [x] Logout button in menu if logged in
- [x] redirect away from login page if logged in
- [x] Keep me signed in checkbox (also set session key on each request)
- [x] Forgotten password
- [x] Auto retry on insertion of unique fields
- [x] Generic message page
- [ ] Time delay lockout to prevent brute force (credentials and TOTP)
- [ ] Split login tokens from session tokens?
- [ ] Differentiate between input and server errors on backend functions
- [ ] Structured logging/add more info to logs
  - User ID
- [ ] User extractor (Async trait)
- [ ] Add error creating macros
- [ ] Simplify error handling on result(option()) functions

### Maybes

- [ ] Add captcha on registration?
- [ ] Use client side redirects
- [ ] User privileges


`docker run -it --rm --network=host iwismer/auth-example`

## Setting up MongoDB

```
db.createCollection("users", {})
db.createCollection("sessions", {})
db.createCollection("emails", {})
db.createCollection("totp", {})
db.createCollection("password-reset", {})

db.sessions.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.email.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.totp.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.password-reset.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )

db.sessions.createIndex( { "token": 1 }, { unique: true } )
db.emails.createIndex( { "token": 1 }, { unique: true } )
db.totp.createIndex( { "token": 1 }, { unique: true } )
db.password-reset.createIndex( { "token": 1 }, { unique: true } )
db.users.createIndex( { "user_id": 1 }, { unique: true } )
db.users.createIndex( { "username": 1 }, { unique: true } )
```

## Building

```
sudo systemctl start docker
docker pull clux/muslrust:stable
docker build -t iwismer/auth-example .
docker push iwismer/auth-example:latest
```

## On Server

```
use admin
db.auth("", "")
use authentication
```

## Docs:

<https://stackoverflow.com/questions/549/the-definitive-guide-to-form-based-website-authentication#477579>

## Tokens

Tokens are hashed with SHA256 before being stored in the database. This is to ensure that someone with access to the database can't
simply impersonate users by using their session tokens, or log in with their TOTP backup codes. Since the codes are sufficiently long
and random, they don't need to be salted or use a password specific hashing algorithm.

## CSRF

To prevent request forgery this example uses the [Double Submit Cookie](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Double_Submit_Cookie) method of CSRF prevention. This method was chosen since it requires no client side JS.

All forms that require user authentication use CSRF.
