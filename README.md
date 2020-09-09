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
  - [ ] Google
  - [ ] Microsoft
  - [ ] Github
  - [ ] Gitlab
  - [ ] ...
- [X] Add script to automatically setup up mongo
- [x] User profile picture
  - [x] Display on the profile page
  - [ ] Manipulate on upload
- [x] Logout button in menu if logged in
- [x] redirect away from login page if logged in
- [x] Keep me signed in checkbox (also set session key on each request)
- [x] Forgotten password
- [x] Auto retry on insertion of unique fields
- [x] Generic message page
- [ ] Time delay lockout to prevent brute force (credentials, TOTP, email validation)
- [ ] Improve logging and error handling
  - [ ] Different log and user facing messages
  - [x] Choose whether or not to show error message
  - [ ] Add more details to logs, like user ID
  - [ ] look into structured logging
  - [x] Add error creation macros
  - [x] Log error before passing up the chain
  - [ ] Simplify error handling on result(option()) functions
- [x] User extractor (Async trait)

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

## Token Generation

I chose to use 32 byte randomly generated tokens. This gives me virtual certainty of no collisions. I use the secure RNG
from the `getrandom` crate.

You can also use a UUIDv4 if you want, as long as you also use a secure random number generator.

Whenever I update a field in the DB that has a uniqueness index on it, I retry a few times in case of a collision.
This isn't strictly required as the chances of collision are near zero, but I added it anyways.

## CSRF

To prevent request forgery this example uses the [Double Submit Cookie](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Double_Submit_Cookie) method of CSRF prevention. This method was chosen since it requires no client side JS.

All forms that require user authentication use CSRF.

## .well-known/security.txt

See <https://securitytxt.org/>

## Login Credentials

I currently allow logging in via either email or username. This adds the restriction of not allowing email addresses as usernames,
and forcing emails to be unique to an account. This means that during registration it is possible to determine if an email
is associated with an account.

Additionally, this can lead to some undesirable security consequences. See <https://security.stackexchange.com/a/139350>.

## Email Validation

The email validation flow I have chosen does not require entering the account password in order to validate the email from the link.
This was an intentional decision as I don't like conditioning users to clicking links in emails, then having them ask for
and account password. Instead, it just uses the token from the email, and hoping the user typed in the correct email, and
that if they didn't, they'll realize and fix it in their account.

I chose not to force email validation for the account to be valid (some websites will delete an account after a specified
amount of time if the email has not been validated). But, if an account doesn't have a validated email, the password cannot
be reset from the password reset form.

Requesting a validation email should be rate limited to prevent spam.

## Useful Links

<https://stackoverflow.com/questions/549/the-definitive-guide-to-form-based-website-authentication#477579>

## Mobile friendliness

I didn't really try to make this mobile friendly. TO be honest, I didn't really spend much time at all with the style/front end
(if you couldn't tell). There is still some CSS laying around that is copied from some other projects I've worked on in the past
that was mobile friendly.

# License

See LICENSE.txt
