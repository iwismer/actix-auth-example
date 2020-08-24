# Authentication Example Website

## Why?

I made this project to learn a bit more about modern authentication on the web, and to practise my skills with Rust.
I also hope that other people might find it a useful reference when implementing authentication (once this is complete).

## Todo

- [x] Add a user ID to the user DB
- [ ] Add OTP and backup codes (https://github.com/constantoine/totp-rs)
- [x] password unicode normalization
- [x] Allow changing password, username, email
- [x] Validate email
- [ ] User privileges?
- [ ] OAuth
- [ ] Add script to automatically setup up mongo
- [ ] User profile picture
  - Resize on upload
  - Put them in the DB
  - display on the profile page
- [x] Logout button in menu if logged in
- [x] redirect away from login page if logged in
- [ ] Keep me signed in checkbox (also set session key on each request)
- [ ] Use client side redirects
- [ ] Add captcha on registration
- [ ] Forgotten password
- [ ] Auto retry on insertion of unique fields
- [ ] Generic message page

`docker run -it --rm --network=host iwismer/auth-example`

## Setting up MongoDB

```
db.createCollection("users", {})
db.createCollection("sessions", {})
db.sessions.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.sessions.createIndex( { "token": 1 }, { unique: true } )
db.emails.createIndex( { "token": 1 }, { unique: true } )
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
