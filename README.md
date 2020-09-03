# Actix Authentication Example

## Why?

I made this project to learn a bit more about modern authentication on the web, and to practise my skills with Rust.
I also hope that other people might find it a useful reference when implementing authentication (once this is complete).

## What is here

- Username/password authentication
  - Unicode normalization of password
  - Argon2 for hashing
- user modification
  - Email
  - Username
  - Password
  - Profile picture (in progress)
- TOTP
- Email validation
- Email based password reset
- Session management with cookies
- JS free CSRF

## Contributing

I'm not a good designer, so the front end is pretty sparse and boring. If you're into that sort of thing, I love for it to look nice.

If you find any issues related to the security of this example, please let me know. I'm far from perfect and may have made some mistakes.
By helping fix them you're also ensuring that others don't make the same mistake.

I'm open to any sort of improvements that can be made to this code. That being said, this is not intended to be the fastest implementation.
I'm going a bit more for ease of use/understanding than performance. That being said, I'm always willing to consider performance improvements.

The documentation is also important. If you have any improvements just for the README or for inline comments, open a PR!

## Todo

- [x] Add a user ID to the user DB
- [x] Add OTP and backup codes
- [x] Show backup codes after OTP, allow regenerating backup codes
- [x] password unicode normalization
- [x] Allow changing password, username, email
- [x] Validate email
- [ ] OAuth
- [X] Add script to automatically setup up mongo
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
- [ ] Improve logging and error handling
  - [ ] Different log and user facing messages
  - [x] Choose whether or not to show error message
  - [ ] Add more details to logs, like user ID
  - [ ] look into structured logging
  - [x] Add error creation macros
  - [x] Log error before passing up the chain
  - [ ] Simplify error handling on result(option()) functions
- [ ] User extractor (Async trait)

### Maybes

- [ ] Add captcha on registration?
- [ ] Use client side redirects
- [ ] User privileges
- [ ] Split login tokens from session tokens?
- [ ] Unicode normalization for all input strings

# Building and Running

## Requirements

- Rust stable
- MongoDB
- Docker (optional, but recommended)

## Simple setup with docker compose

`docker compose up -d`

## Building manually with docker

```
sudo systemctl start docker
docker pull clux/muslrust:stable
docker build -t auth-example .
```

## Building with Cargo

`cargo build`

## Setting up the MongoDB instance

Run the commands in `init/db-init.js`. These will be automatically run if you're using Docker Compose.

# Documentation

## Tokens

Tokens are hashed with SHA256 before being stored in the database. This is to ensure that someone with access to the database can't
simply impersonate users by using their session tokens, or log in with their TOTP backup codes. Since the codes are sufficiently long
and random, they don't need to be salted or use a password specific hashing algorithm.

## CSRF

To prevent request forgery this example uses the [Double Submit Cookie](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Double_Submit_Cookie) method of CSRF prevention. This method was chosen since it requires no client side JS.

All forms that require user authentication use CSRF.

## .well-known/security.txt

See <https://securitytxt.org/>

## Useful Links

<https://stackoverflow.com/questions/549/the-definitive-guide-to-form-based-website-authentication#477579>

# License

See LICENSE.txt
